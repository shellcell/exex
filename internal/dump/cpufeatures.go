package dump

import (
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/rabarbra/exex/internal/arch"
	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/cpufeat"
	"github.com/rabarbra/exex/internal/disasm"
)

// cpuClassifier returns the per-architecture instruction→feature classifier, or
// nil when feature detection isn't supported for the architecture.
func cpuClassifier(a arch.Arch) func(string) string {
	switch a {
	case arch.ArchX86, arch.ArchAMD64:
		return cpufeat.X86
	case arch.ArchARM64:
		return cpufeat.ARM64
	}
	return nil
}

// CPUFeatureSet is the result of a feature scan.
type CPUFeatureSet struct {
	Counts   map[string]int    // feature → number of instructions using it
	FirstUse map[string]uint64 // feature → address of the first instruction using it
	Total    int               // instructions scanned
	Baseline string            // implied x86-64 microarch level (x86 only), or ""
}

// chunkFeatures is one worker's partial result.
type chunkFeatures struct {
	counts map[string]int
	first  map[string]uint64
	total  int
}

// ScanCPUFeatures decodes the executable sections — in parallel chunks across all
// cores, the same way the syscall scan does — and classifies every instruction
// into the CPU-feature families it requires. Each chunk decodes a small lead of
// preceding bytes to re-synchronise the (variable-length x86) decoder, then only
// counts instructions at or past the chunk's real start so the overlap isn't
// double-counted.
func ScanCPUFeatures(f *binfile.File) (CPUFeatureSet, error) {
	classify := cpuClassifier(f.Arch())
	if classify == nil {
		return CPUFeatureSet{}, fmt.Errorf("CPU-feature detection is not supported for %s", f.Arch())
	}
	dis, err := disasm.For(f.Arch())
	if err != nil || dis == nil {
		return CPUFeatureSet{}, fmt.Errorf("no disassembler for this architecture")
	}
	raw := f.Raw()

	var tasks []chunkTask
	for _, s := range f.Sections {
		if !s.Exec || s.FileSize == 0 {
			continue
		}
		secOff := int(s.Offset)
		secEnd := min(secOff+int(s.FileSize), len(raw))
		for p := secOff; p < secEnd; p += dumpScanChunk {
			hi := min(p+dumpScanChunk, secEnd)
			lo := max(secOff, p-dumpScanLead)
			tasks = append(tasks, chunkTask{
				lo: lo, hi: hi,
				baseVA: s.Addr + uint64(lo-secOff),
				emitVA: s.Addr + uint64(p-secOff),
			})
		}
	}

	parts := make([]chunkFeatures, len(tasks))
	workers := max(min(runtime.GOMAXPROCS(0), len(tasks)), 1)
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i, tk := range tasks {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, tk chunkTask) {
			defer wg.Done()
			defer func() { <-sem }()
			cf := chunkFeatures{counts: map[string]int{}, first: map[string]uint64{}}
			disasm.RangeFunc(dis, raw[tk.lo:tk.hi], tk.baseVA, func(in disasm.Inst) bool {
				if in.Addr < tk.emitVA {
					return true // re-sync lead — already counted by the previous chunk
				}
				cf.total++
				if feat := classify(in.Text); feat != "" {
					if cf.counts[feat] == 0 || in.Addr < cf.first[feat] {
						cf.first[feat] = in.Addr
					}
					cf.counts[feat]++
				}
				return true
			})
			parts[i] = cf
		}(i, tk)
	}
	wg.Wait()

	set := CPUFeatureSet{Counts: map[string]int{}, FirstUse: map[string]uint64{}}
	for _, cf := range parts {
		set.Total += cf.total
		for feat, n := range cf.counts {
			if set.Counts[feat] == 0 || cf.first[feat] < set.FirstUse[feat] {
				set.FirstUse[feat] = cf.first[feat]
			}
			set.Counts[feat] += n
		}
	}
	if f.Arch() == arch.ArchX86 || f.Arch() == arch.ArchAMD64 {
		set.Baseline = cpufeat.BaselineX86(set.Counts)
	}
	return set, nil
}

// SortedFeatures returns the used features in display order (then by count).
func (s CPUFeatureSet) SortedFeatures() []string {
	var used []string
	for f := range s.Counts {
		used = append(used, f)
	}
	rank := map[string]int{}
	for i, f := range cpufeat.DisplayOrder {
		rank[f] = i
	}
	sort.SliceStable(used, func(i, j int) bool {
		ri, oki := rank[used[i]]
		rj, okj := rank[used[j]]
		if oki && okj && ri != rj {
			return ri < rj
		}
		return used[i] < used[j]
	})
	return used
}

// CPUFeatures renders the CPU-feature report for the `-o cpu-features` dump.
func CPUFeatures(f *binfile.File) (string, error) {
	set, err := ScanCPUFeatures(f)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "CPU features required by %s  (%d instructions scanned)\n\n", f.Arch(), set.Total)
	if set.Baseline != "" {
		fmt.Fprintf(&b, "  baseline: %s\n\n", set.Baseline)
	}
	feats := set.SortedFeatures()
	if len(feats) == 0 {
		b.WriteString("  only base instructions — no optional CPU features detected\n")
		return b.String(), nil
	}
	w := 0
	for _, fe := range feats {
		w = max(w, len(fe))
	}
	addrW := f.AddrHexWidth()
	for _, fe := range feats {
		fmt.Fprintf(&b, "  %-*s  %8d ×   first at 0x%0*x\n", w, fe, set.Counts[fe], addrW, set.FirstUse[fe])
	}
	return b.String(), nil
}
