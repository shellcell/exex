package dump

import (
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"

	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/x86/x86asm"

	"github.com/shellcell/exex/internal/arch"
	"github.com/shellcell/exex/internal/binfile"
	"github.com/shellcell/exex/internal/cpufeat"
	"github.com/shellcell/exex/internal/disasm"
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
	return ScanCPUFeaturesCancel(f, nil)
}

// ScanCPUFeaturesCancel is ScanCPUFeatures with an optional cancellation channel.
// When done is closed, workers stop decoding as soon as they observe it. The UI
// still guards stale results by sequence number; cancellation is to stop wasting
// CPU after the user dismisses/supersedes the scan.
func ScanCPUFeaturesCancel(f *binfile.File, done <-chan struct{}) (CPUFeatureSet, error) {
	classify := cpuClassifier(f.Arch())
	if classify == nil {
		return CPUFeatureSet{}, fmt.Errorf("CPU-feature detection is not supported for %s", f.Arch())
	}
	if f.Arch() == arch.ArchARM64 {
		return scanCPUFeaturesARM64(f, done), nil
	}
	if f.Arch() == arch.ArchAMD64 || f.Arch() == arch.ArchX86 {
		return scanCPUFeaturesX86(f, done), nil
	}
	dis, err := disasm.For(f.Arch())
	if err != nil || dis == nil {
		return CPUFeatureSet{}, fmt.Errorf("no disassembler for this architecture")
	}
	raw := f.Raw()

	tasks := cpuFeatureTasks(f, raw)

	parts := make([]chunkFeatures, len(tasks))
	workers := max(min(runtime.GOMAXPROCS(0), len(tasks)), 1)
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i, tk := range tasks {
		if scanCancelled(done) {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, tk chunkTask) {
			defer wg.Done()
			defer func() { <-sem }()
			cf := chunkFeatures{counts: map[string]int{}, first: map[string]uint64{}}
			disasm.RangeFunc(dis, raw[tk.lo:tk.hi], tk.baseVA, func(in disasm.Inst) bool {
				if scanCancelled(done) {
					return false
				}
				if in.Addr < tk.emitVA {
					return true // re-sync lead — already counted by the previous chunk
				}
				if in.Addr >= tk.emitEndVA {
					return false
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

func cpuFeatureTasks(f *binfile.File, raw []byte) []chunkTask {
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
				lo:        lo,
				hi:        hi,
				baseVA:    s.Addr + uint64(lo-secOff),
				emitVA:    s.Addr + uint64(p-secOff),
				emitEndVA: s.Addr + uint64(hi-secOff),
			})
		}
	}
	return tasks
}

func scanCPUFeaturesARM64(f *binfile.File, done <-chan struct{}) CPUFeatureSet {
	raw := f.Raw()
	tasks := cpuFeatureTasks(f, raw)
	parts := make([]chunkFeatures, len(tasks))
	workers := max(min(runtime.GOMAXPROCS(0), len(tasks)), 1)
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i, tk := range tasks {
		if scanCancelled(done) {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, tk chunkTask) {
			defer wg.Done()
			defer func() { <-sem }()
			cf := chunkFeatures{counts: map[string]int{}, first: map[string]uint64{}}
			code := raw[tk.lo:tk.hi]
			start := int((4 - tk.baseVA%4) % 4)
			for off := start; off+4 <= len(code); off += 4 {
				if scanCancelled(done) {
					break
				}
				addr := tk.baseVA + uint64(off)
				if addr < tk.emitVA {
					continue
				}
				if addr >= tk.emitEndVA {
					break
				}
				cf.total++
				inst, err := arm64asm.Decode(code[off:])
				if err != nil {
					continue
				}
				if feat := classifyARM64Inst(inst); feat != "" {
					if cf.counts[feat] == 0 || addr < cf.first[feat] {
						cf.first[feat] = addr
					}
					cf.counts[feat]++
				}
			}
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
	return set
}

func scanCPUFeaturesX86(f *binfile.File, done <-chan struct{}) CPUFeatureSet {
	raw := f.Raw()
	tasks := cpuFeatureTasks(f, raw)
	parts := make([]chunkFeatures, len(tasks))
	workers := max(min(runtime.GOMAXPROCS(0), len(tasks)), 1)
	sem := make(chan struct{}, workers)
	mode := 64
	if f.Arch() == arch.ArchX86 {
		mode = 32
	}
	var wg sync.WaitGroup
	for i, tk := range tasks {
		if scanCancelled(done) {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, tk chunkTask) {
			defer wg.Done()
			defer func() { <-sem }()
			cf := chunkFeatures{counts: map[string]int{}, first: map[string]uint64{}}
			code := raw[tk.lo:tk.hi]
			for p := 0; p < len(code); {
				if scanCancelled(done) {
					break
				}
				addr := tk.baseVA + uint64(p)
				inst, err := decodeX86Raw(code[p:], mode)
				if err != nil || inst.Len == 0 {
					if p+1 > len(code) {
						break
					}
					if addr >= tk.emitVA && addr < tk.emitEndVA {
						cf.total++
					}
					p++
					continue
				}
				if addr >= tk.emitEndVA {
					break
				}
				if addr >= tk.emitVA {
					cf.total++
					if feat := classifyX86Inst(inst); feat != "" {
						if cf.counts[feat] == 0 || addr < cf.first[feat] {
							cf.first[feat] = addr
						}
						cf.counts[feat]++
					}
				}
				p += inst.Len
			}
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
	set.Baseline = cpufeat.BaselineX86(set.Counts)
	return set
}

func decodeX86Raw(code []byte, mode int) (inst x86asm.Inst, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("x86 decode panic: %v", r)
		}
	}()
	return x86asm.Decode(code, mode)
}

func classifyX86Inst(inst x86asm.Inst) string {
	op := inst.Op.String()
	if len(op) > 1 && (op[0] == 'V' || op[0] == 'v') && hasX86VectorOrMaskArg(inst) {
		switch {
		case hasX86ZMMOrMaskArg(inst):
			return "AVX-512"
		case hasPrefixFoldASCII(op, "vfmadd") || hasPrefixFoldASCII(op, "vfmsub") ||
			hasPrefixFoldASCII(op, "vfnmadd") || hasPrefixFoldASCII(op, "vfnmsub"):
			return "FMA"
		case hasPrefixFoldASCII(op, "vcvtph2ps") || hasPrefixFoldASCII(op, "vcvtps2ph"):
			return "F16C"
		case hasPrefixFoldASCII(op, "vaes"):
			return "AES"
		case hasPrefixFoldASCII(op, "vpclmul"):
			return "PCLMUL"
		case hasX86YMMArg(inst) && (hasPrefixFoldASCII(op, "vp") || hasPrefixFoldASCII(op, "vperm") ||
			containsFoldASCII(op, "broadcast") || containsFoldASCII(op, "gather") || containsFoldASCII(op, "blendd")):
			return "AVX2"
		}
		return "AVX"
	}

	switch {
	case eqFoldASCII(op, "popcnt"):
		return "POPCNT"
	case hasPrefixFoldASCII(op, "crc32"):
		return "SSE4.2"
	case eqFoldASCII(op, "pcmpgtq") || hasPrefixFoldASCII(op, "pcmpistr") || hasPrefixFoldASCII(op, "pcmpestr"):
		return "SSE4.2"
	case hasPrefixFoldASCII(op, "pmovsx") || hasPrefixFoldASCII(op, "pmovzx") || eqFoldASCII(op, "ptest") ||
		eqFoldASCII(op, "pmuldq") || eqFoldASCII(op, "pmulld") || hasPrefixFoldASCII(op, "blend") || hasPrefixFoldASCII(op, "round") ||
		eqFoldASCII(op, "dpps") || eqFoldASCII(op, "dppd") || eqFoldASCII(op, "mpsadbw") || eqFoldASCII(op, "packusdw") ||
		hasPrefixFoldASCII(op, "pmaxs") || hasPrefixFoldASCII(op, "pmaxu") ||
		hasPrefixFoldASCII(op, "pmins") || hasPrefixFoldASCII(op, "pminu") ||
		eqFoldASCII(op, "phminposuw") || eqFoldASCII(op, "insertps") || eqFoldASCII(op, "extractps"):
		return "SSE4.1"
	case eqFoldASCII(op, "pshufb") || hasPrefixFoldASCII(op, "phadd") || hasPrefixFoldASCII(op, "phsub") ||
		eqFoldASCII(op, "pmaddubsw") || hasPrefixFoldASCII(op, "palignr") || hasPrefixFoldASCII(op, "psign") ||
		hasPrefixFoldASCII(op, "pabs") || eqFoldASCII(op, "pmulhrsw"):
		return "SSSE3"
	case eqFoldASCII(op, "addsubps") || eqFoldASCII(op, "addsubpd") || hasPrefixFoldASCII(op, "hadd") || hasPrefixFoldASCII(op, "hsub") ||
		eqFoldASCII(op, "movddup") || eqFoldASCII(op, "movshdup") || eqFoldASCII(op, "movsldup") || eqFoldASCII(op, "lddqu"):
		return "SSE3"
	case hasPrefixFoldASCII(op, "aes"):
		return "AES"
	case hasPrefixFoldASCII(op, "sha1") || hasPrefixFoldASCII(op, "sha256"):
		return "SHA"
	case eqFoldASCII(op, "rdrand"):
		return "RDRAND"
	case eqFoldASCII(op, "rdseed"):
		return "RDSEED"
	case eqFoldASCII(op, "movbe"):
		return "MOVBE"
	case eqFoldASCII(op, "andn") || eqFoldASCII(op, "bextr") || hasPrefixFoldASCII(op, "bls") || eqFoldASCII(op, "tzcnt"):
		return "BMI1"
	case eqFoldASCII(op, "bzhi") || eqFoldASCII(op, "mulx") || eqFoldASCII(op, "pdep") || eqFoldASCII(op, "pext") || eqFoldASCII(op, "rorx") ||
		eqFoldASCII(op, "sarx") || eqFoldASCII(op, "shlx") || eqFoldASCII(op, "shrx"):
		return "BMI2"
	case eqFoldASCII(op, "lzcnt"):
		return "ABM"
	case eqFoldASCII(op, "adcx") || eqFoldASCII(op, "adox"):
		return "ADX"
	}
	return ""
}

func hasX86VectorOrMaskArg(inst x86asm.Inst) bool {
	for _, arg := range inst.Args {
		if reg, ok := arg.(x86asm.Reg); ok && ((reg >= x86asm.X0 && reg <= x86asm.Z31) || (reg >= x86asm.K0 && reg <= x86asm.K7)) {
			return true
		}
	}
	return false
}

func hasX86ZMMOrMaskArg(inst x86asm.Inst) bool {
	for _, arg := range inst.Args {
		if reg, ok := arg.(x86asm.Reg); ok && ((reg >= x86asm.Z0 && reg <= x86asm.Z31) || (reg >= x86asm.K0 && reg <= x86asm.K7)) {
			return true
		}
	}
	return false
}

func hasX86YMMArg(inst x86asm.Inst) bool {
	for _, arg := range inst.Args {
		if reg, ok := arg.(x86asm.Reg); ok && reg >= x86asm.Y0 && reg <= x86asm.Y31 {
			return true
		}
	}
	return false
}

func classifyARM64Inst(inst arm64asm.Inst) string {
	op := inst.Op.String()
	switch {
	case hasPrefixFoldASCII(op, "aes"):
		return "AES (crypto)"
	case hasPrefixFoldASCII(op, "sha1") || hasPrefixFoldASCII(op, "sha256") || hasPrefixFoldASCII(op, "sha512"):
		return "SHA (crypto)"
	case hasPrefixFoldASCII(op, "pmull"):
		return "PMULL (crypto)"
	case hasPrefixFoldASCII(op, "crc32"):
		return "CRC32"
	case hasPrefixFoldASCII(op, "cas") || hasPrefixFoldASCII(op, "ldadd") || hasPrefixFoldASCII(op, "stadd") ||
		hasPrefixFoldASCII(op, "swp") || hasPrefixFoldASCII(op, "ldset") || hasPrefixFoldASCII(op, "stset") ||
		hasPrefixFoldASCII(op, "ldclr") || hasPrefixFoldASCII(op, "stclr") || hasPrefixFoldASCII(op, "ldeor") ||
		hasPrefixFoldASCII(op, "ldsmax") || hasPrefixFoldASCII(op, "ldsmin") ||
		hasPrefixFoldASCII(op, "ldumax") || hasPrefixFoldASCII(op, "ldumin"):
		return "LSE atomics"
	case hasPrefixFoldASCII(op, "pac") || hasPrefixFoldASCII(op, "aut") || eqFoldASCII(op, "xpaci") || eqFoldASCII(op, "xpacd") ||
		eqFoldASCII(op, "braa") || eqFoldASCII(op, "brab") || eqFoldASCII(op, "blraa") || eqFoldASCII(op, "blrab") ||
		eqFoldASCII(op, "retaa") || eqFoldASCII(op, "retab"):
		return "Pointer auth"
	case eqFoldASCII(op, "sdot") || eqFoldASCII(op, "udot"):
		return "DotProd"
	case eqFoldASCII(op, "bfdot") || hasPrefixFoldASCII(op, "bfmla") || eqFoldASCII(op, "bfmmla"):
		return "BF16"
	}
	for _, arg := range inst.Args {
		switch arg.(type) {
		case arm64asm.RegisterWithArrangement, arm64asm.RegisterWithArrangementAndIndex:
			return "NEON/ASIMD"
		}
	}
	return ""
}

func eqFoldASCII(s, lower string) bool {
	return len(s) == len(lower) && hasPrefixFoldASCII(s, lower)
}

func hasPrefixFoldASCII(s, lower string) bool {
	if len(s) < len(lower) {
		return false
	}
	for i := 0; i < len(lower); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != lower[i] {
			return false
		}
	}
	return true
}

func containsFoldASCII(s, lower string) bool {
	if len(lower) == 0 {
		return true
	}
	for i := 0; i+len(lower) <= len(s); i++ {
		if hasPrefixFoldASCII(s[i:], lower) {
			return true
		}
	}
	return false
}

func scanCancelled(done <-chan struct{}) bool {
	if done == nil {
		return false
	}
	select {
	case <-done:
		return true
	default:
		return false
	}
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
