package ui

// Support for the perfreport tool: measure each TUI view's render cost. The mode
// switching and background-decode completion are unexported, so this lives in the
// ui package and exposes a single typed entry point.

import (
	"runtime"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/config"
)

// PerfStat is one view's measured render cost.
type PerfStat struct {
	View  string
	Dur   time.Duration // best wall time of `runs` full-frame renders
	Alloc uint64        // bytes allocated by one render
}

var perfViews = []struct {
	name string
	mode mode
	all  bool // disasm-all mode: every section, via the windowed region decode
}{
	{"info", modeInfo, false}, {"sections", modeSections, false}, {"symbols", modeSymbols, false},
	{"disasm", modeDisasm, false}, {"disasm-all", modeDisasm, true},
	{"hex", modeHex, false}, {"raw", modeRaw, false},
	{"strings", modeStrings, false}, {"libs", modeLibs, false}, {"sources", modeSources, false},
	{"relocs", modeRelocs, false},
}

// RenderViewStats builds a model at w×h on f and measures every view's
// full-frame render: best wall time over `runs` and the bytes one render
// allocates. Background disasm decoding is completed synchronously so the disasm
// view is fully populated, mirroring what the interactive program renders.
func RenderViewStats(f *binfile.File, w, h, runs int) []PerfStat {
	model, err := New(f, Options{Config: &config.Config{}})
	if err != nil {
		return nil
	}
	var m tea.Model = model
	m, _ = m.Update(tea.WindowSizeMsg{Width: w, Height: h})

	out := make([]PerfStat, 0, len(perfViews))
	for _, v := range perfViews {
		mm := m.(*Model)
		// disasm-all sweeps every section through the windowed region-by-region
		// decode; toggle it on for that row and back off afterwards.
		if mm.file.DisasmAll() != v.all {
			mm.file.SetDisasmAll(v.all)
			mm.resetDisasmImageState()
		}
		mm.switchMode(v.mode)
		// Finish any background decode the disasm view kicked off so the frame is
		// measured fully rendered, not mid-"decoding…".
		for mm.disasmDecoding {
			addr := mm.disasmPendingAddr
			win, insts := mm.decodeDisasmAt(addr, mm.disasmLeadBytes())
			m, _ = mm.Update(disasmReadyMsg{addr: addr, posLo: win.Start, posHi: win.End, insts: insts})
			mm = m.(*Model)
		}

		best := time.Duration(1<<63 - 1)
		for range runs {
			mm.viewDirty = true // defeat the frame cache so each call re-renders
			t := time.Now()
			_ = mm.View()
			if d := time.Since(t); d < best {
				best = d
			}
		}
		var m0, m1 runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&m0)
		mm.viewDirty = true
		_ = mm.View()
		runtime.ReadMemStats(&m1)
		out = append(out, PerfStat{View: v.name, Dur: best, Alloc: m1.TotalAlloc - m0.TotalAlloc})
	}
	f.SetDisasmAll(false) // leave the shared file in its default mode
	return out
}
