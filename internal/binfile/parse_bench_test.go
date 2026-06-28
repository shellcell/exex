package binfile

import (
	"os"
	"testing"
)

// BenchmarkOpen parses EXEX_BENCH_BIN; -benchmem/-memprofile/-cpuprofile
// attribute the startup cost. Skipped unless the env var points at a real binary.
func BenchmarkOpen(b *testing.B) {
	path := os.Getenv("EXEX_BENCH_BIN")
	if path == "" {
		b.Skip("set EXEX_BENCH_BIN to a real binary")
	}
	b.ReportAllocs()
	for range b.N {
		f, err := Open(path)
		if err != nil {
			b.Fatal(err)
		}
		_ = f
	}
}
