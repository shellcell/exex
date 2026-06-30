package ui

// In-view search: the hex and raw views match byte/text patterns, the disasm
// view matches instruction text and symbol names. The query is remembered so
// n / N can repeat forward / backward.

import (
	"fmt"

	tea "charm.land/bubbletea/v2"

	searchutil "github.com/rabarbra/exex/internal/bytesearch"
)

type searchMode = searchutil.Mode

const (
	searchModeAuto = searchutil.ModeAuto
	searchModeText = searchutil.ModeText
	searchModeHex  = searchutil.ModeHex
)

func searchModeName(mode searchMode) string {
	return mode.String()
}

func (m *Model) cycleSearchMode() {
	m.searchMode = searchutil.NextMode(m.searchMode)
}

// searchSwitch is one clickable toggle in the search popup: a dim name and the
// current value rendered as a pill ("name ⟦value⟧").
type searchSwitch struct {
	name   string
	value  string
	toggle func()
}

// label is the plain "name ⟦value⟧" text; its width drives both the render and
// the mouse hit-test so they can't drift.
func (s searchSwitch) label() string { return s.name + " ⟦" + s.value + "⟧" }

// searchSwitchSep separates the switch segments; searchSwitchLine is the 0-based
// content row the switch strip occupies inside the modal (header, hint, blank,
// input, blank, switches).
const (
	searchSwitchSep  = "   "
	searchSwitchLine = 5
)

// searchSwitches returns the mode / direction / origin toggles. The render and
// the mouse hit-test both build from this, so they can't drift.
func (m *Model) searchSwitches() []searchSwitch {
	dir := "→ forward"
	if !m.searchForward {
		dir = "← backward"
	}
	origin := "cursor"
	if !m.searchFromCursor {
		if m.searchForward {
			origin = "start"
		} else {
			origin = "end"
		}
	}
	return []searchSwitch{
		{"mode", searchModeName(m.searchMode), m.cycleSearchMode},
		{"dir", dir, func() { m.searchForward = !m.searchForward }},
		{"origin", origin, func() { m.searchFromCursor = !m.searchFromCursor }},
	}
}

// openSearch opens the search prompt. Repeat search still uses searchQuery via
// n/N, but each new prompt starts empty so stale input is not accidentally reused.
func (m *Model) openSearch() {
	m.searchActive = true
	m.searchInput.SetValue("")
	m.searchInput.Focus()
}

// runSearch finds the next/previous match for the current query in the active
// view and moves the cursor onto it. inclusive includes the current position
// (used for the initial Enter); n / N pass inclusive=false to step past it.
func (m *Model) runSearch(forward, inclusive bool) tea.Cmd {
	return m.runSearchWithOrigin(forward, inclusive, true)
}

func (m *Model) runSearchFromPrompt() tea.Cmd {
	inclusive := true
	if !m.searchFromCursor {
		inclusive = false
	}
	return m.runSearchWithOrigin(m.searchForward, inclusive, m.searchFromCursor)
}

func (m *Model) runSearchWithOrigin(forward, inclusive bool, fromCursor bool) tea.Cmd {
	if m.searchQuery == "" {
		m.setStatus("no search query", true)
		return nil
	}
	switch m.mode {
	case modeDisasm:
		return m.runDisasmSearch(forward, inclusive, fromCursor)
	case modeHex:
		m.runHexSearch(forward, inclusive, fromCursor)
	case modeRaw:
		m.runRawSearch(forward, inclusive, fromCursor)
	case modeSources:
		m.runSourcesSearch(forward, inclusive)
	default:
		m.setStatus("search isn't available in this view", true)
	}
	return nil
}

func (m *Model) runDisasmSearch(forward, inclusive, fromCursor bool) tea.Cmd {
	if m.sourceFirst && m.srcFile != "" {
		m.searchInSourceFile(forward, inclusive)
		return nil
	}
	return m.startDisasmSearch(forward, inclusive, fromCursor)
}

func (m *Model) runHexSearch(forward, inclusive, fromCursor bool) {
	m.ensureHex()
	start := m.hexCur
	if !fromCursor {
		if forward {
			start = -1
		} else {
			start = m.hexImg.Len() - 1
		}
	}
	m.hexCur = m.searchBytesAt(m.hexImg, start, forward, inclusive)
}

func (m *Model) runRawSearch(forward, inclusive, fromCursor bool) {
	m.ensureRaw()
	start := m.rawCur
	if !fromCursor {
		if forward {
			start = -1
		} else {
			start = len(m.rawData) - 1
		}
	}
	m.rawCur = m.searchBytesAt(rawBytes(m.rawData), start, forward, inclusive)
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
	pat := searchutil.ParsePattern(m.searchQuery, m.searchMode)
	if len(pat) == 0 {
		m.setStatus("empty search pattern", true)
		return cur
	}
	start := cur
	if !inclusive {
		if forward {
			start++
		} else {
			start--
		}
	}
	if i := findBytesSrc(data, pat, start, forward); i >= 0 {
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
func findBytesSrc(data byteSource, pat []byte, start int, forward bool) int {
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
				if j := searchutil.FindBytes(r.B, pat, from, true); j >= 0 {
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
			if j := searchutil.FindBytes(r.B, pat, hi, false); j >= 0 {
				return r.Off + j
			}
		}
	}
	return -1
}
