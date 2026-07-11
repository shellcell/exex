package binfile

import (
	"os"
	"runtime"
	"testing"
)

var retainedSourceBenchmarkFile *File

func BenchmarkSourceFiles(b *testing.B) {
	path := os.Getenv("EXEX_BENCH_BIN")
	if path == "" {
		b.Skip("set EXEX_BENCH_BIN to a real binary")
	}
	b.ReportAllocs()
	for range b.N {
		b.StopTimer()
		f, err := Open(path)
		if err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		f.SourceFiles()
		b.StopTimer()
		f.Close()
	}
}

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
		if err := f.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkOpenLayout measures the cheap metadata/raw path used by -o sections,
// segments, strings, and cpu-features.
func BenchmarkOpenLayout(b *testing.B) {
	path := os.Getenv("EXEX_BENCH_BIN")
	if path == "" {
		b.Skip("set EXEX_BENCH_BIN to a real binary")
	}
	b.ReportAllocs()
	for range b.N {
		f, err := Open(path, WithLayoutOnly())
		if err != nil {
			b.Fatal(err)
		}
		if err := f.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSourceIndexes measures the first Sources open followed by the
// address/line indexes needed by source-aware disassembly. retained-B is the
// live-heap increase after a GC, excluding the already-open File.
func BenchmarkSourceIndexes(b *testing.B) {
	path := os.Getenv("EXEX_BENCH_BIN")
	if path == "" {
		b.Skip("set EXEX_BENCH_BIN to a real binary")
	}
	b.ReportAllocs()
	for range b.N {
		b.StopTimer()
		f, err := Open(path)
		if err != nil {
			b.Fatal(err)
		}
		runtime.GC()
		var before runtime.MemStats
		runtime.ReadMemStats(&before)
		b.StartTimer()
		files := f.SourceFiles()
		if len(files) > 0 {
			f.MappedLines(files[0])
		}
		b.StopTimer()
		retainedSourceBenchmarkFile = f
		runtime.GC()
		var after runtime.MemStats
		runtime.ReadMemStats(&after)
		if after.HeapAlloc >= before.HeapAlloc {
			b.ReportMetric(float64(after.HeapAlloc-before.HeapAlloc), "retained-B")
		}
		f.Close()
		retainedSourceBenchmarkFile = nil
	}
}
