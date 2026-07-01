package ui

import (
	"os"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/config"
)

// benchView renders full frames of one view for EXEX_BENCH_BIN, for allocation
// profiling of the interactive paths. -benchmem/-memprofile attribute the cost.
func benchView(b *testing.B, md mode) {
	path := os.Getenv("EXEX_BENCH_BIN")
	if path == "" {
		b.Skip("set EXEX_BENCH_BIN to a real binary")
	}
	f, err := binfile.Open(path)
	if err != nil {
		b.Fatal(err)
	}
	model, err := New(f, Options{Config: &config.Config{}})
	if err != nil {
		b.Fatal(err)
	}
	var m tea.Model = model
	m, _ = m.Update(tea.WindowSizeMsg{Width: 160, Height: 48})
	mm := m.(*Model)
	mm.switchMode(md)
	for mm.disasmDecoding {
		addr := mm.disasmPendingAddr
		win, insts := mm.decodeDisasmAt(addr, mm.disasmLeadBytes())
		m, _ = mm.Update(disasmReadyMsg{addr: addr, posLo: win.Start, posHi: win.End, insts: insts})
		mm = m.(*Model)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		mm.viewDirty = true
		_ = mm.View()
	}
}

func BenchmarkViewDisasm(b *testing.B)  { benchView(b, modeDisasm) }
func BenchmarkViewHex(b *testing.B)     { benchView(b, modeHex) }
func BenchmarkViewSymbols(b *testing.B) { benchView(b, modeSymbols) }
func BenchmarkViewRelocs(b *testing.B)  { benchView(b, modeRelocs) }
