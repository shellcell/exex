package ui

// In-view search: the hex and raw views match byte/text patterns, the disasm
// view matches instruction text and symbol names. The query is remembered so
// n / N can repeat forward / backward.

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

const (
	searchModeAuto = iota
	searchModeText
	searchModeHex
)

func searchModeName(mode int) string {
	switch mode {
	case searchModeText:
		return "text"
	case searchModeHex:
		return "hex"
	default:
		return "auto"
	}
}

func (m *Model) cycleSearchMode() {
	m.searchMode = (m.searchMode + 1) % 3
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
		if m.sourceFirst && m.srcFile != "" {
			m.searchInSourceFile(forward, inclusive)
			return nil
		}
		return m.startDisasmSearch(forward, inclusive, fromCursor)
	case modeHex:
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
	case modeRaw:
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
	case modeStrings:
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
	case modeSources:
		if m.srcSearchAll {
			m.searchAllSources(forward, inclusive)
		} else {
			m.searchInSourceFile(forward, inclusive)
		}
	default:
		m.setStatus("search isn't available in this view", true)
	}
	return nil
}

func (m *Model) cancelSearch(status string) {
	m.searchSeq++
	m.searchRunning = false
	m.searchCancelable = false
	m.setStatus(status, false)
}

func (m *Model) searchBytesAt(data []byte, cur int, forward, inclusive bool) int {
	pat := searchPattern(m.searchQuery, m.searchMode)
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
	if i := findBytes(data, pat, start, forward); i >= 0 {
		m.setStatus(fmt.Sprintf("match at offset +0x%x", i), false)
		return i
	}
	m.setStatus("not found: "+m.searchQuery, true)
	return cur
}

// findBytes returns the index of pat in data at or after (forward) / at or
// before (backward) start, or -1.
func findBytes(data, pat []byte, start int, forward bool) int {
	if len(pat) == 0 || len(pat) > len(data) {
		return -1
	}
	if forward {
		if start < 0 {
			start = 0
		}
		if start > len(data)-len(pat) {
			return -1
		}
		if j := bytes.Index(data[start:], pat); j >= 0 {
			return start + j
		}
		return -1
	}
	end := start + len(pat)
	if end > len(data) {
		end = len(data)
	}
	if end < len(pat) {
		return -1
	}
	return bytes.LastIndex(data[:end], pat)
}

// searchPattern interprets a query as bytes or text:
//   - "quoted text"   → literal bytes of the text
//   - hex digits / 0x → byte pattern (spaces allowed: "de ad be ef")
//   - anything else   → literal text bytes
func searchPattern(q string, mode int) []byte {
	trimmed := strings.TrimSpace(q)
	if mode == searchModeText {
		if len(trimmed) >= 2 && trimmed[0] == '"' && trimmed[len(trimmed)-1] == '"' {
			return []byte(trimmed[1 : len(trimmed)-1])
		}
		return []byte(q)
	}
	if mode == searchModeHex {
		compact := strings.TrimPrefix(strings.ReplaceAll(trimmed, " ", ""), "0x")
		if len(compact)%2 != 0 || !isHexStr(compact) {
			return nil
		}
		b := make([]byte, len(compact)/2)
		for i := range b {
			v, _ := strconv.ParseUint(compact[2*i:2*i+2], 16, 8)
			b[i] = byte(v)
		}
		return b
	}
	if len(trimmed) >= 2 && trimmed[0] == '"' && trimmed[len(trimmed)-1] == '"' {
		return []byte(trimmed[1 : len(trimmed)-1])
	}
	compact := strings.TrimPrefix(strings.ReplaceAll(trimmed, " ", ""), "0x")
	if q == trimmed && len(compact) >= 2 && len(compact)%2 == 0 && isHexStr(compact) {
		b := make([]byte, len(compact)/2)
		for i := range b {
			v, _ := strconv.ParseUint(compact[2*i:2*i+2], 16, 8)
			b[i] = byte(v)
		}
		return b
	}
	return []byte(q)
}

func isHexStr(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
