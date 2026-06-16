package ui

// The strings view lists printable runs found in the file (à la strings(1)),
// each annotated with its file offset and — when the bytes are mapped — the
// virtual address and owning section. Enter jumps a mapped string into the hex
// view; copy keys grab the address/offset or the string text.

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/rabarbra/exex/internal/binfile"
)

// ensureStrings extracts the file's printable strings lazily.
func (m *Model) ensureStrings() {
	if m.stringsList == nil {
		m.stringsList = m.file.Strings()
	}
}

func (m *Model) updateStrings(key string) (tea.Model, tea.Cmd) {
	m.ensureStrings()
	n := len(m.stringsList)
	if n == 0 {
		return m, nil
	}
	if navKey(&m.stringsCur, n, m.bodyHeight(), key) {
		return m, nil
	}
	switch key {
	case "w":
		m.toggleWrap()
	case "enter":
		s := m.stringsList[m.stringsCur]
		if s.HasAddr {
			m.openHexAt(s.Addr)
		} else {
			m.openRawAt(s.Offset)
		}
	case "a":
		s := m.stringsList[m.stringsCur]
		if s.HasAddr {
			m.copyToClipboard(fmt.Sprintf("0x%0*x", m.file.AddrHexWidth(), s.Addr), "address")
		} else {
			m.copyToClipboard(fmt.Sprintf("0x%x", s.Offset), "offset")
		}
	case "s":
		m.copyToClipboard(m.stringsList[m.stringsCur].Text, "string")
	case "/":
		m.openSearch()
	case "n":
		m.runSearch(true, false)
	case "N":
		m.runSearch(false, false)
	}
	return m, nil
}

// searchStrings finds the next/previous string whose text contains the query.
func (m *Model) searchStrings(start int, forward bool) int {
	q := strings.ToLower(m.searchQuery)
	n := len(m.stringsList)
	if forward {
		for i := start; i < n; i++ {
			if i >= 0 && strings.Contains(strings.ToLower(m.stringsList[i].Text), q) {
				return i
			}
		}
		return -1
	}
	if start > n-1 {
		start = n - 1
	}
	for i := start; i >= 0; i-- {
		if strings.Contains(strings.ToLower(m.stringsList[i].Text), q) {
			return i
		}
	}
	return -1
}

func (m *Model) renderStrings() string {
	bodyH := m.bodyHeight()
	m.ensureStrings()
	if len(m.stringsList) == 0 {
		return padBody("no printable strings found\n", m.width, bodyH)
	}

	addrW := m.file.AddrHexWidth()
	hdr := fmt.Sprintf(" %-10s %-*s %-16s  %s", "Offset", 2+addrW, "Address", "Section", "String")
	header := m.tableHeader(hdr)

	visible := bodyH - 1
	if visible < 1 {
		visible = 1
	}
	rowHeight := func(i int) int {
		return m.stringRowHeight(i)
	}
	top := m.visualTopForView(m.stringsCur, m.stringsTop, len(m.stringsList), visible, rowHeight)
	m.stringsTop = top
	m.renderedStringsTop = top

	rows := []string{header}
	for i := top; i < len(m.stringsList); i++ {
		line := m.stringRow(i, addrW)
		if i == m.stringsCur {
			line = m.theme.tableSelStyle.Render(stripANSI(line))
		}
		if !appendRenderedRowsIndented(&rows, line, m.width, m.wrap, addrW+33, bodyH) {
			break
		}
	}
	return padBodyRows(rows, m.width, bodyH)
}

func (m *Model) stringRowHeight(i int) int {
	if i < 0 || i >= len(m.stringsList) {
		return 1
	}
	addrW := m.file.AddrHexWidth()
	key := stringRowCacheKey{i, m.width, addrW, m.wrap}
	if m.stringHeightCache != nil {
		if h, ok := m.stringHeightCache[key]; ok {
			return h
		}
	}
	line := m.stringRow(i, addrW)
	h := len(renderLineRowsIndented(line, m.width, m.wrap, addrW+33))
	if m.stringHeightCache == nil {
		m.stringHeightCache = make(map[stringRowCacheKey]int)
	}
	m.stringHeightCache[key] = h
	return h
}

func (m *Model) stringRow(i, addrW int) string {
	key := stringRowCacheKey{i, m.width, addrW, m.wrap}
	if m.stringRowCache != nil {
		if s, ok := m.stringRowCache[key]; ok {
			return s
		}
	}

	s := m.stringsList[i]
	addr := strings.Repeat(" ", 2+addrW)
	if s.HasAddr {
		addr = fmt.Sprintf("0x%0*x", addrW, s.Addr)
	}
	text := sanitizeString(s.Text)
	if m.wrap {
		text = s.Text
	}
	line := fmt.Sprintf(" %s %-*s %-16s  %s",
		m.theme.addrStyle.Render(fmt.Sprintf("0x%-8x", s.Offset)), 2+addrW, m.theme.addrStyle.Render(addr), m.theme.footerStyle.Render(truncateMiddle(s.Section, 16)), m.theme.tableRowStyle.Render(text))
	line = m.stringRowStyle(s).Render(line)

	if m.stringRowCache == nil {
		m.stringRowCache = make(map[stringRowCacheKey]string)
	}
	m.stringRowCache[key] = line
	return line
}

// stringRowStyle colours a string row by the category of its owning section
// (matching the Sections and Hex views); unmapped strings render dim.
func (m *Model) stringRowStyle(s binfile.StringEntry) lipgloss.Style {
	if sec := m.sectionAtOffset(s.Offset); sec != nil {
		return m.theme.styleForSection(sec)
	}
	// srcShadowStyle is dim like footerStyle but, unlike it, carries no
	// horizontal padding (which would over-widen a full-width row and wrap).
	return m.theme.srcShadowStyle
}

// sanitizeString collapses control bytes (none should remain from extraction,
// but be defensive) and caps the visible length so one long string can't blow
// out the row.
func sanitizeString(s string) string {
	const maxLen = 160
	if len(s) > maxLen {
		s = s[:maxLen-1] + "…"
	}
	return s
}
