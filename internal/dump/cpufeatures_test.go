package dump

import (
	"encoding/binary"
	"os"
	"reflect"
	"testing"

	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/x86/x86asm"

	"github.com/shellcell/exex/internal/binfile"
	"github.com/shellcell/exex/internal/cpufeat"
	"github.com/shellcell/exex/internal/disasm"
)

func TestClassifyX86InstMatchesTextClassifierSamples(t *testing.T) {
	cases := []struct {
		name    string
		code    []byte
		expects bool
	}{
		{"popcnt", []byte{0xf3, 0x48, 0x0f, 0xb8, 0xc0}, true},
		{"aesenc", []byte{0x66, 0x0f, 0x38, 0xdc, 0xc1}, true},
		{"pclmulqdq-currently-unclassified", []byte{0x66, 0x0f, 0x3a, 0x44, 0xc1, 0x00}, false},
		{"vaddps", []byte{0xc5, 0xf4, 0x58, 0xc2}, true},
		{"vpaddd", []byte{0xc5, 0xf5, 0xfe, 0xc2}, true},
		{"rdrand", []byte{0x0f, 0xc7, 0xf0}, true},
		{"lzcnt", []byte{0xf3, 0x0f, 0xbd, 0xc0}, true},
		{"tzcnt", []byte{0xf3, 0x0f, 0xbc, 0xc0}, true},
		{"movbe", []byte{0x0f, 0x38, 0xf0, 0x00}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			inst, err := x86asm.Decode(c.code, 64)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			text := x86asm.GNUSyntax(inst, 0x1000, nil)
			got := classifyX86Inst(inst)
			want := cpufeat.X86(text)
			if got != want {
				t.Fatalf("%s: classifyX86Inst=%q, text classifier=%q (%s)", c.name, got, want, text)
			}
			if c.expects && want == "" {
				t.Fatalf("%s: sample did not exercise a CPU feature (%s)", c.name, text)
			}
		})
	}
}

func TestScanCPUFeaturesX86MatchesTextPathOnBenchBinary(t *testing.T) {
	path := os.Getenv("EXEX_BENCH_BIN")
	if path == "" {
		t.Skip("set EXEX_BENCH_BIN to an x86/amd64 binary")
	}
	f, err := binfile.Open(path)
	if err != nil {
		t.Fatalf("Open(%s): %v", path, err)
	}
	defer f.Close()
	if f.Arch() != disasm.ArchAMD64 && f.Arch() != disasm.ArchX86 {
		t.Skipf("%s is %s, not x86/amd64", path, f.Arch())
	}

	got := scanCPUFeaturesX86(f, nil)
	want := scanCPUFeaturesTextForTest(t, f)
	if got.Total != want.Total || got.Baseline != want.Baseline ||
		!reflect.DeepEqual(got.Counts, want.Counts) || !reflect.DeepEqual(got.FirstUse, want.FirstUse) {
		t.Fatalf("raw x86 scan mismatch\n got:  total=%d baseline=%q counts=%v first=%v\n want: total=%d baseline=%q counts=%v first=%v",
			got.Total, got.Baseline, got.Counts, got.FirstUse,
			want.Total, want.Baseline, want.Counts, want.FirstUse)
	}
}

func TestClassifyX86InstMatchesTextClassifierOnBenchBinary(t *testing.T) {
	path := os.Getenv("EXEX_BENCH_BIN")
	if path == "" {
		t.Skip("set EXEX_BENCH_BIN to an x86/amd64 binary")
	}
	f, err := binfile.Open(path)
	if err != nil {
		t.Fatalf("Open(%s): %v", path, err)
	}
	defer f.Close()
	mode := 64
	if f.Arch() == disasm.ArchX86 {
		mode = 32
	} else if f.Arch() != disasm.ArchAMD64 {
		t.Skipf("%s is %s, not x86/amd64", path, f.Arch())
	}
	raw := f.Raw()
	checked := 0
	for _, s := range f.Sections {
		if !s.Exec || s.FileSize == 0 {
			continue
		}
		secOff := int(s.Offset)
		secEnd := min(secOff+int(s.FileSize), len(raw))
		for p := secOff; p < secEnd; {
			inst, err := decodeX86Raw(raw[p:secEnd], mode)
			if err != nil || inst.Len == 0 {
				p++
				continue
			}
			addr := s.Addr + uint64(p-secOff)
			text := x86asm.GNUSyntax(inst, addr, nil)
			got := classifyX86Inst(inst)
			want := cpufeat.X86(text)
			if got != want {
				t.Fatalf("0x%x %s: classifyX86Inst=%q, text classifier=%q", addr, text, got, want)
			}
			checked++
			p += inst.Len
		}
	}
	if checked == 0 {
		t.Fatal("no x86 instructions decoded")
	}
}

func scanCPUFeaturesTextForTest(t *testing.T, f *binfile.File) CPUFeatureSet {
	t.Helper()
	classify := cpuClassifier(f.Arch())
	dis, err := disasm.For(f.Arch())
	if err != nil || dis == nil {
		t.Fatalf("disassembler: %v", err)
	}
	raw := f.Raw()
	set := CPUFeatureSet{Counts: map[string]int{}, FirstUse: map[string]uint64{}}
	for _, tk := range cpuFeatureTasks(f, raw) {
		disasm.RangeFunc(dis, raw[tk.lo:tk.hi], tk.baseVA, func(in disasm.Inst) bool {
			if in.Addr < tk.emitVA {
				return true
			}
			if in.Addr >= tk.emitEndVA {
				return false
			}
			set.Total++
			if feat := classify(in.Text); feat != "" {
				if set.Counts[feat] == 0 || in.Addr < set.FirstUse[feat] {
					set.FirstUse[feat] = in.Addr
				}
				set.Counts[feat]++
			}
			return true
		})
	}
	set.Baseline = cpufeat.BaselineX86(set.Counts)
	return set
}

func TestClassifyARM64InstMatchesTextClassifierOnSelf(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip("no test executable path")
	}
	f, err := binfile.Open(exe)
	if err != nil {
		t.Skipf("open self: %v", err)
	}
	defer f.Close()
	if f.Arch() != disasm.ArchARM64 {
		t.Skip("self is not arm64")
	}

	raw := f.Raw()
	decoded := 0
	for _, s := range f.Sections {
		if !s.Exec || s.FileSize == 0 {
			continue
		}
		start := int(s.Offset)
		end := int(s.Offset + s.FileSize)
		if start < 0 || start >= len(raw) {
			continue
		}
		if end > len(raw) {
			end = len(raw)
		}
		align := int((4 - s.Addr%4) % 4)
		for off := start + align; off+4 <= end; off += 4 {
			inst, err := arm64asm.Decode(raw[off:])
			if err != nil {
				continue
			}
			decoded++
			got := classifyARM64Inst(inst)
			want := cpufeat.ARM64(arm64asm.GNUSyntax(inst))
			if got != want {
				addr := s.Addr + uint64(off-start)
				word := binary.LittleEndian.Uint32(raw[off:])
				t.Fatalf("0x%x %08x %s: classifyARM64Inst=%q, text classifier=%q", addr, word, arm64asm.GNUSyntax(inst), got, want)
			}
		}
	}
	if decoded == 0 {
		t.Skip("no ARM64 instructions decoded from self")
	}
}
