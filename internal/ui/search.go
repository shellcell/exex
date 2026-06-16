package ui

// In-view search: the hex and raw views match byte/text patterns, the disasm
// view matches instruction text and symbol names. The query is remembered so
// n / N can repeat forward / backward.

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"

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

// searchSwitch is one clickable toggle in the search popup.
type searchSwitch struct {
	label  string
	toggle func()
}

// searchSwitchSep separates the switch segments; searchSwitchLine is the
// 0-based content row the switch strip occupies inside the modal (hint, blank,
// input, blank, switches, help).
const (
	searchSwitchSep  = "   "
	searchSwitchLine = 4
)

// searchSwitches returns the mode / direction / origin toggles. The render and
// the mouse hit-test both build from this, so they can't drift.
func (m *Model) searchSwitches() []searchSwitch {
	dir := "forward"
	if !m.searchForward {
		dir = "backward"
	}
	origin := "from cursor"
	if !m.searchFromCursor {
		if m.searchForward {
			origin = "from start"
		} else {
			origin = "from end"
		}
	}
	return []searchSwitch{
		{"[ mode: " + searchModeName(m.searchMode) + " ]", m.cycleSearchMode},
		{"[ dir: " + dir + " ]", func() { m.searchForward = !m.searchForward }},
		{"[ origin: " + origin + " ]", func() { m.searchFromCursor = !m.searchFromCursor }},
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
	case modeStrings:
		m.runStringsSearch(forward, inclusive, fromCursor)
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
			start = len(m.hexImg.Data) - 1
		}
	}
	m.hexCur = m.searchBytesAt(m.hexImg.Data, start, forward, inclusive)
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
	m.rawCur = m.searchBytesAt(m.rawData, start, forward, inclusive)
}

func (m *Model) runStringsSearch(forward, inclusive, fromCursor bool) {
	m.ensureStrings()
	start := m.stringsCur
	if !fromCursor {
		if forward {
			start = 0
		} else {
			start = len(m.stringsList) - 1
		}
	} else if !inclusive {
		if forward {
			start++
		} else {
			start--
		}
	}
	if i := m.searchStrings(start, forward); i >= 0 {
		m.stringsCur = i
		m.setStatus("match: "+truncate(m.stringsList[i].Text, 40), false)
	} else {
		m.setStatus("not found: "+m.searchQuery, true)
	}
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
	m.setStatus(status, false)
}

func (m *Model) searchBytesAt(data []byte, cur int, forward, inclusive bool) int {
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
	if i := searchutil.FindBytes(data, pat, start, forward); i >= 0 {
		m.setStatus(fmt.Sprintf("match at offset +0x%x", i), false)
		return i
	}
	m.setStatus("not found: "+m.searchQuery, true)
	return cur
}
