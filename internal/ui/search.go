package ui

// In-view search: the hex and raw views match byte/text patterns, the disasm
// view matches instruction text and symbol names. The query is remembered so
// n / N can repeat forward / backward.

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// openSearch opens the search prompt, pre-filled with the last query.
func (m *Model) openSearch() {
	m.searchActive = true
	m.searchInput.SetValue(m.searchQuery)
	m.searchInput.CursorEnd()
	m.searchInput.Focus()
}

// runSearch finds the next/previous match for the current query in the active
// view and moves the cursor onto it. inclusive includes the current position
// (used for the initial Enter); n / N pass inclusive=false to step past it.
func (m *Model) runSearch(forward, inclusive bool) {
	if m.searchQuery == "" {
		m.setStatus("no search query", true)
		return
	}
	switch m.mode {
	case modeDisasm:
		start := m.disasmCur
		if !inclusive {
			if forward {
				start++
			} else {
				start--
			}
		}
		if i := m.searchDisasm(start, forward); i >= 0 {
			m.disasmCur, m.disasmTop = i, i
			m.setStatus("match: "+strings.TrimSpace(m.disasmInst[i].Text), false)
		} else {
			m.setStatus("not found: "+m.searchQuery, true)
		}
	case modeHex:
		m.ensureHex()
		m.hexCur = m.searchBytesAt(m.hexImg.Data, m.hexCur, forward, inclusive)
	case modeRaw:
		m.ensureRaw()
		m.rawCur = m.searchBytesAt(m.rawData, m.rawCur, forward, inclusive)
	case modeStrings:
		m.ensureStrings()
		start := m.stringsCur
		if !inclusive {
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
	default:
		m.setStatus("search isn't available in this view", true)
	}
}

func (m *Model) searchBytesAt(data []byte, cur int, forward, inclusive bool) int {
	pat := searchPattern(m.searchQuery)
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

func (m *Model) searchDisasm(start int, forward bool) int {
	q := strings.ToLower(m.searchQuery)
	n := len(m.disasmInst)
	if n == 0 {
		return -1
	}
	match := func(i int) bool {
		addr := m.disasmInst[i].Addr
		if strings.Contains(strings.ToLower(m.disasmInst[i].Text), q) {
			return true
		}
		// A symbol-name hit only counts at the symbol's first instruction, so
		// searching a function name lands on its entry, not on every line of it.
		if sym, ok := m.file.SymbolAt(addr); ok && sym.Addr == addr &&
			strings.Contains(strings.ToLower(sym.Display()), q) {
			return true
		}
		return false
	}
	if forward {
		for i := start; i < n; i++ {
			if i >= 0 && match(i) {
				return i
			}
		}
		return -1
	}
	if start > n-1 {
		start = n - 1
	}
	for i := start; i >= 0; i-- {
		if match(i) {
			return i
		}
	}
	return -1
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
func searchPattern(q string) []byte {
	q = strings.TrimSpace(q)
	if len(q) >= 2 && q[0] == '"' && q[len(q)-1] == '"' {
		return []byte(q[1 : len(q)-1])
	}
	compact := strings.TrimPrefix(strings.ReplaceAll(q, " ", ""), "0x")
	if len(compact) >= 2 && len(compact)%2 == 0 && isHexStr(compact) {
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
