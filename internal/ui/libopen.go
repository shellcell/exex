package ui

// Shell-side Libs actions: opening a library as the primary file replaces the
// whole model (file navigation), and jumping to a library's imported symbols
// switches modes — both need shell internals, so they live here and the Libs
// view (internal/ui/views/libs) reaches them via view.Host / the key adapter.

import (
	"fmt"
	"os"
	"path/filepath"

	tea "charm.land/bubbletea/v2"

	"github.com/shellcell/exex/internal/binfile"
	"github.com/shellcell/exex/internal/dyldcache"
	"github.com/shellcell/exex/internal/explorer"
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

// openLibAsPrimary opens lib as the primary file, remembering where we came from
// so Back (ctrl+o) returns. It first resolves lib to a standalone file on disk;
// failing that, and when lib is a dyld-shared-cache system library, it extracts
// the dylib straight out of the host's shared cache.
func (m *Model) openLibAsPrimary(lib string) (tea.Model, tea.Cmd) {
	if path, ok := explorer.ResolveLibPath(lib, m.file.Path, m.file.Info, nil); ok {
		f, err := binfile.Open(path)
		if err != nil {
			m.setStatus("open library: "+err.Error(), true)
			return m, nil
		}
		return m.enterLibFile(f, filepath.Base(path))
	}
	if explorer.IsDyldSharedCacheLib(lib) {
		return m.openCacheLib(lib)
	}
	m.setStatus("could not resolve library on disk: "+lib, true)
	return m, nil
}

// openCacheLib extracts a cache-resident system library out of the host's dyld
// shared cache and opens the stitched image as the primary file.
func (m *Model) openCacheLib(lib string) (tea.Model, tea.Cmd) {
	cachePath, ok := dyldcache.HostCachePath(m.file.Arch().String(), func(p string) bool {
		_, err := os.Stat(p)
		return err == nil
	})
	if !ok {
		m.setStatus("system library "+lib+" is in the dyld shared cache, which isn't present on this host", true)
		return m, nil
	}
	c, err := dyldcache.Open(cachePath)
	if err != nil {
		m.setStatus("open dyld cache: "+err.Error(), true)
		return m, nil
	}
	defer c.Close() // the stitched buffer is independent of the mapped cache
	im, found := c.FindImage(lib)
	if !found {
		m.setStatus(lib+" is not in the dyld shared cache image table", true)
		return m, nil
	}
	buf, err := c.ExtractImage(im)
	if err != nil {
		m.setStatus("extract "+filepath.Base(lib)+" from cache: "+err.Error(), true)
		return m, nil
	}
	f, err := binfile.OpenBytes(im.Path, buf)
	if err != nil {
		m.setStatus("parse "+filepath.Base(lib)+" from cache: "+err.Error(), true)
		return m, nil
	}
	return m.enterLibFile(f, filepath.Base(lib)+" (cache)")
}

// enterLibFile builds a model for the opened dependency f and descends into it.
func (m *Model) enterLibFile(f *binfile.File, label string) (tea.Model, tea.Cmd) {
	nm, err := New(f, Options{Config: &m.cfg})
	if err != nil {
		f.Close()
		m.setStatus("open library: "+err.Error(), true)
		return m, nil
	}
	m.enterFile(nm, label)
	nm.setStatus("opened dependency "+label+"  (Ctrl+O: back)", false)
	return nm, tea.Batch(nm.Init(), nm.switchMode(modeInfo))
}
