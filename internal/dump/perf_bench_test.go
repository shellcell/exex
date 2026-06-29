package dump

import (
	"io"
	"os"
	"testing"

	"github.com/rabarbra/exex/internal/binfile"
)

// BenchmarkDisasmDump streams the disasm dump of EXEX_BENCH_BIN; set
// -benchmem (and optionally -memprofile) to attribute allocations. all=true
// covers every section (objdump -D), false only executable ones (-d).
func benchDisasm(b *testing.B, all bool) {
	path := os.Getenv("EXEX_BENCH_BIN")
	if path == "" {
		b.Skip("set EXEX_BENCH_BIN to a real binary")
	}
	f, err := binfile.Open(path)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if err := DisasmTo(io.Discard, f, all); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDisasm(b *testing.B)    { benchDisasm(b, false) }
func BenchmarkDisasmAll(b *testing.B) { benchDisasm(b, true) }

// BenchmarkStringsDump and BenchmarkSymsDump cover the full `-o strings` / `-o
// syms` CLI paths (re-Open each iteration so the string scan / symbol parse is
// included), to profile their wall-time CPU against strings(1)/nm.
// BenchmarkRelocs covers the `-o relocs` dump for EXEX_BENCH_BIN.
func BenchmarkRelocs(b *testing.B) {
	path := os.Getenv("EXEX_BENCH_BIN")
	if path == "" {
		b.Skip("set EXEX_BENCH_BIN to a real binary")
	}
	f, err := binfile.Open(path)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for range b.N {
		_ = Relocs(f)
	}
}

// BenchmarkSyscalls covers the full `-o syscalls` scan (decode + classify +
// number resolution) for EXEX_BENCH_BIN.
func BenchmarkSyscalls(b *testing.B) {
	path := os.Getenv("EXEX_BENCH_BIN")
	if path == "" {
		b.Skip("set EXEX_BENCH_BIN to a real binary")
	}
	f, err := binfile.Open(path)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for range b.N {
		_ = Syscalls(f, false)
	}
}

func BenchmarkStringsDump(b *testing.B) {
	path := os.Getenv("EXEX_BENCH_BIN")
	if path == "" {
		b.Skip("set EXEX_BENCH_BIN to a real binary")
	}
	b.ReportAllocs()
	for range b.N {
		f, err := binfile.Open(path)
		if err != nil {
			b.Fatal(err)
		}
		_ = Strings(f)
	}
}

func BenchmarkSymsDump(b *testing.B) {
	path := os.Getenv("EXEX_BENCH_BIN")
	if path == "" {
		b.Skip("set EXEX_BENCH_BIN to a real binary")
	}
	b.ReportAllocs()
	for range b.N {
		f, err := binfile.Open(path)
		if err != nil {
			b.Fatal(err)
		}
		f.ApplyDemangled(f.ComputeDemangled())
		_ = Symbols(f)
	}
}
