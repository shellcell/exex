package ui

// Shell-side Libs actions: opening a library as the primary file replaces the
// whole model (file navigation), and jumping to a library's imported symbols
// switches modes — both need shell internals, so they live here and the Libs
// view (internal/ui/views/libs) reaches them via view.Host / the key adapter.

import (
	"fmt"
	"path/filepath"

	tea "charm.land/bubbletea/v2"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/explorer"
)

// openSymbolsForLib shows the Symbols view filtered to the imports bound to lib.
func (m *Model) openSymbolsForLib(lib string) {
	n := 0
	for _, s := range m.file.Symbols {
		if s.Library == lib {
			n++
		}
	}
	if n == 0 {
		m.setStatus("no imported symbols resolved to "+lib, true)
		return
	}
	m.symbols.FilterByLib(m.viewContext(), lib)
	m.setMode(modeSymbols)
	m.setStatus(fmt.Sprintf("%d symbols imported from %s — Esc clears", n, lib), false)
}

// openLibAsPrimary resolves lib on disk and opens it as the primary file,
// remembering where we came from so Back (ctrl+o) returns.
func (m *Model) openLibAsPrimary(lib string) (tea.Model, tea.Cmd) {
	path, ok := explorer.ResolveLibPath(lib, m.file.Path, m.file.Info, nil)
	if !ok {
		if explorer.IsDyldSharedCacheLib(lib) {
			m.setStatus("system library "+lib+" lives in the dyld shared cache, not on disk — can't open", true)
		} else {
			m.setStatus("could not resolve library on disk: "+lib, true)
		}
		return m, nil
	}
	f, err := binfile.Open(path)
	if err != nil {
		m.setStatus("open library: "+err.Error(), true)
		return m, nil
	}
	nm, err := New(f, Options{Config: &m.cfg})
	if err != nil {
		m.setStatus("open library: "+err.Error(), true)
		return m, nil
	}
	// Descending into a dependency — remember where we came from so Back returns.
	m.enterFile(nm, filepath.Base(path))
	nm.setStatus("opened dependency "+filepath.Base(path)+"  (Ctrl+O: back)", false)
	return nm, nm.switchMode(modeInfo)
}
