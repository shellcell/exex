package ui

import (
	"os"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/config"
)

func settleBenchmarkProgram(model tea.Model, initial tea.Cmd) tea.Model {
	results := make(chan tea.Msg)
	active := 0
	start := func(cmd tea.Cmd) {
		if cmd == nil {
			return
		}
		active++
		go func() { results <- cmd() }()
	}
	start(initial)
	for active > 0 {
		msg := <-results
		active--
		if batch, ok := msg.(tea.BatchMsg); ok {
			for _, cmd := range batch {
				start(cmd)
			}
			continue
		}
		var next tea.Cmd
		model, next = model.Update(msg)
		start(next)
	}
	return model
}

func BenchmarkInitSettled(b *testing.B) {
	path := os.Getenv("EXEX_BENCH_BIN")
	if path == "" {
		b.Skip("set EXEX_BENCH_BIN to a real binary")
	}
	b.ReportAllocs()
	for range b.N {
		b.StopTimer()
		f, err := binfile.Open(path)
		if err != nil {
			b.Fatal(err)
		}
		m, err := New(f, Options{Config: &config.Config{}})
		if err != nil {
			f.Close()
			b.Fatal(err)
		}
		b.StartTimer()
		settleBenchmarkProgram(m, m.Init())
		b.StopTimer()
		f.Close()
	}
}
