package ui

import (
	"os"
	"testing"

	"github.com/rabarbra/exex/internal/binfile"
)

func benchmarkDisasmSearchStep(b *testing.B, query string) {
	path := os.Getenv("EXEX_BENCH_BIN")
	if path == "" {
		b.Skip("set EXEX_BENCH_BIN to a real binary")
	}
	f, err := binfile.Open(path)
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()
	m, err := New(f)
	if err != nil {
		b.Fatal(err)
	}
	img := f.ExecImage()
	step := disasmSearchStep{
		file:    f,
		seq:     1,
		label:   query,
		query:   canonicalSearchQuery(query),
		forward: true,
		total:   img.Len(),
		chunk:   m.disasmSearchChunkBytes(),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		msg, ok := m.searchDisasmStepCmd(step)().(disasmSearchProgressMsg)
		if !ok {
			b.Fatal("unexpected search message")
		}
		if query == "add" && len(msg.found) == 0 {
			b.Fatal("common query returned no hits")
		}
	}
}

func BenchmarkDisasmSearchCommon(b *testing.B) {
	benchmarkDisasmSearchStep(b, "add")
}

func BenchmarkDisasmSearchMissing(b *testing.B) {
	benchmarkDisasmSearchStep(b, "definitely-not-present-search-token")
}
