package ui

// In-view search: the hex and raw views match byte/text patterns, the disasm
// view matches instruction text and symbol names. The query is remembered so
// n / N can repeat forward / backward.

import (
	"fmt"

	tea "charm.land/bubbletea/v2"

	searchutil "github.com/rabarbra/exex/internal/bytesearch"
	searchmodal "github.com/rabarbra/exex/internal/ui/modals/search"
	"github.com/rabarbra/exex/internal/ui/views/hexraw"
)

// openSearch opens the in-view search prompt.
func (m *Model) openSearch() { m.search.Open() }

// SearchCaseChanged drops the disasm search cache, whose hits were computed
// under the previous case setting. It satisfies search.Host.
func (m *Model) SearchCaseChanged() { m.searchResults.Reset("") }

// SearchHint describes what the active view searches. It satisfies search.Host.
func (m *Model) SearchHint() string { return m.current().searchHint() }

// SubmitSearch runs the typed query in the active view, re-pinning the byte views
// when the search moved the cursor. It satisfies search.Host.
func (m *Model) SubmitSearch(query string, o searchmodal.Options) tea.Cmd {
	before := m.activeCursorState()
	m.searchQuery = query
	inclusive := o.FromCursor
	cmd := m.runSearchWithOrigin(o.Forward, inclusive, o.FromCursor)
	if before != m.activeCursorState() {
		m.viewportDetached = false
		switch m.mode {
		case modeHex:
			m.byteViews.PinCurrentSectionStart(m.viewContextPtr(), hexraw.Hex)
		case modeRaw:
			m.byteViews.PinCurrentSectionStart(m.viewContextPtr(), hexraw.Raw)
		}
	}
	return cmd
}

// runSearch finds the next/previous match for the current query in the active
// view and moves the cursor onto it. inclusive includes the current position
// (used for the initial Enter); n / N pass inclusive=false to step past it.
func (m *Model) runSearch(forward, inclusive bool) tea.Cmd {
	return m.runSearchWithOrigin(forward, inclusive, true)
}

func (m *Model) runSearchWithOrigin(forward, inclusive bool, fromCursor bool) tea.Cmd {
	if m.searchQuery == "" {
		m.setStatus("no search query", true)
		return nil
	}
	return m.current().runSearch(forward, inclusive, fromCursor)
}

func (m *Model) runDisasmSearch(forward, inclusive, fromCursor bool) tea.Cmd {
	if m.dasm.SourceFirst && m.dasm.SrcFile != "" {
		m.searchInSourceFile(forward, inclusive)
		return nil
	}
	return m.startDisasmSearch(forward, inclusive, fromCursor)
}

func (m *Model) runHexSearch(forward, inclusive, fromCursor bool) {
	ctx := m.viewContext()
	data, cur, ok := m.byteViews.Data(&ctx, hexraw.Hex)
	if !ok {
		return
	}
	start := cur
	if !fromCursor {
		if forward {
			start = -1
		} else {
			start = data.Len() - 1
		}
	}
	m.byteViews.SetCursor(hexraw.Hex, m.searchBytesAt(data, start, forward, inclusive))
}

func (m *Model) runRawSearch(forward, inclusive, fromCursor bool) {
	ctx := m.viewContext()
	data, cur, ok := m.byteViews.Data(&ctx, hexraw.Raw)
	if !ok {
		return
	}
	start := cur
	if !fromCursor {
		if forward {
			start = -1
		} else {
			start = data.Len() - 1
		}
	}
	m.byteViews.SetCursor(hexraw.Raw, m.searchBytesAt(data, start, forward, inclusive))
}

func (m *Model) runSourcesSearch(forward, inclusive bool) {
	if m.srcSearchAll {
		m.searchAllSources(forward, inclusive)
		return
	}
	m.searchInSourceFile(forward, inclusive)
}

func (m *Model) cancelSearch(status string) {
	m.searchSeq++
	m.searchRunning = false
	m.searchCancelable = false
	m.stopDisasmSearch()
	m.setStatus(status, false)
}

func (m *Model) stopDisasmSearch() {
	if m.searchCancel != nil {
		close(m.searchCancel)
		m.searchCancel = nil
	}
}

func (m *Model) searchBytesAt(data byteSource, cur int, forward, inclusive bool) int {
	pat := searchutil.ParsePattern(m.searchQuery, m.search.Mode())
	if len(pat) == 0 {
		m.setStatus("empty search pattern", true)
		return cur
	}
	// Case-insensitive only for text patterns (folding a hex byte pattern would
	// wrongly match unrelated letter values).
	fold := !m.search.CaseSensitive() && searchutil.IsTextPattern(m.searchQuery, m.search.Mode())
	start := cur
	if !inclusive {
		if forward {
			start++
		} else {
			start--
		}
	}
	if i := findBytesSrc(data, pat, start, forward, fold); i >= 0 {
		m.setStatus(fmt.Sprintf("match at offset +0x%x", i), false)
		return i
	}
	m.setStatus("not found: "+m.searchQuery, true)
	return cur
}

// findBytesSrc finds pat in data scanning from start (forward or backward)
// without materializing the whole stream: it runs bytes.Index/LastIndex on each
// region's native bytes in turn (zero-copy), so a 100 MB binary is scanned at the
// same speed as a flat []byte and never allocates. Matches are within a region
// (sections) — the meaningful scope; a pattern straddling a section boundary in
// the flattened image is not matched.
func findBytesSrc(data byteSource, pat []byte, start int, forward, fold bool) int {
	n := data.Len()
	if len(pat) == 0 || len(pat) > n {
		return -1
	}
	runs := data.Runs()
	if forward {
		if start < 0 {
			start = 0
		}
		for _, r := range runs {
			if r.Off+len(r.B) <= start {
				continue // region ends at/before start
			}
			from := max(start-r.Off, 0)
			if from <= len(r.B)-len(pat) {
				if j := searchutil.FindBytesFold(r.B, pat, from, true, fold); j >= 0 {
					return r.Off + j
				}
			}
		}
		return -1
	}
	if start > n-len(pat) {
		start = n - len(pat)
	}
	for i := len(runs) - 1; i >= 0; i-- {
		r := runs[i]
		if r.Off > start {
			continue // every match start in this region would exceed start
		}
		hi := min(start-r.Off, len(r.B)-len(pat)) // greatest local start to consider
		if hi >= 0 {
			if j := searchutil.FindBytesFold(r.B, pat, hi, false, fold); j >= 0 {
				return r.Off + j
			}
		}
	}
	return -1
}
