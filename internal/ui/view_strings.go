package ui

// The strings view lists printable runs found in the file (à la strings(1)),
// each annotated with its file offset and — when the bytes are mapped — the
// virtual address and owning section. Enter jumps a mapped string into the hex
// view; copy keys grab the address/offset or the string text.

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/rabarbra/exex/internal/binfile"
)

// ensureStrings extracts the file's printable strings lazily and builds the
// (initially unfiltered) view list.
func (m *Model) ensureStrings() {
	if m.stringsList == nil {
		m.stringsList = m.file.Strings()
		m.recomputeStrings()
	}
}

// recomputeStrings rebuilds stringsFiltered from the current filter text,
// matching on the string text and its owning section.
func (m *Model) recomputeStrings() {
	m.clearStringCaches()
	needle := strings.ToLower(m.stringsFilter.Value())
	m.stringsFiltered = m.stringsFiltered[:0]
	for i, s := range m.stringsList {
		if needle == "" || containsFold(s.Text, needle) || containsFold(s.Section, needle) {
			m.stringsFiltered = append(m.stringsFiltered, i)
		}
	}
	if m.stringsCur >= len(m.stringsFiltered) {
		m.stringsCur = max(0, len(m.stringsFiltered)-1)
	}
}

// openStringSearch implements the -s CLI flag: it filters the printable strings
// by s and either jumps to the single match (Hex if mapped, else Raw) or opens
// the Strings view with the filter applied when several match.
func (m *Model) openStringSearch(s string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return
	}
	m.ensureStrings()
	m.stringsFilter.SetValue(s)
	m.recomputeStrings()
	m.stringsCur, m.stringsTop = 0, 0
	switch len(m.stringsFiltered) {
	case 0:
		m.setMode(modeStrings)
		m.setStatus(fmt.Sprintf("no strings match %q", s), true)
	case 1:
		e := m.stringsList[m.stringsFiltered[0]]
		if e.HasAddr {
			m.openHexAt(e.Addr)
		} else {
			m.openRawAt(e.Offset)
		}
		m.setStatus(fmt.Sprintf("string %q", s), false)
	default:
		m.setMode(modeStrings)
		m.setStatus(fmt.Sprintf("%d strings match %q", len(m.stringsFiltered), s), false)
	}
}

// currentString returns the selected string through the active filter.
func (m *Model) currentString() (binfile.StringEntry, bool) {
	if m.stringsCur < 0 || m.stringsCur >= len(m.stringsFiltered) {
		return binfile.StringEntry{}, false
	}
	return m.stringsList[m.stringsFiltered[m.stringsCur]], true
}

func (m *Model) updateStrings(key string) (tea.Model, tea.Cmd) {
	m.ensureStrings()
	if navKey(&m.stringsCur, len(m.stringsFiltered), m.listPage(), key) {
		return m, nil
	}
	switch key {
	case "/":
		m.stringsFilter.Focus()
	case "w":
		m.toggleWrap()
	case "enter":
		if s, ok := m.currentString(); ok {
			if s.HasAddr {
				m.openHexAt(s.Addr)
			} else {
				m.openRawAt(s.Offset)
			}
		}
	case "a":
		if s, ok := m.currentString(); ok {
			if s.HasAddr {
				m.copyToClipboard(fmt.Sprintf("0x%0*x", m.file.AddrHexWidth(), s.Addr), "address")
			} else {
				m.copyToClipboard(fmt.Sprintf("0x%x", s.Offset), "offset")
			}
		}
	case "s":
		if s, ok := m.currentString(); ok {
			m.copyToClipboard(s.Text, "string")
		}
	}
	return m, nil
}

func (m *Model) renderStrings() string {
	bodyH := m.bodyHeight()
	if bodyH < 2 {
		bodyH = 2
	}
	m.ensureStrings()
	if len(m.stringsList) == 0 {
		return padBody("no printable strings found\n", m.width, bodyH)
	}

	filterRow := m.stringsFilter.View()
	if !m.stringsFilter.Focused() {
		filterRow = m.theme.footerStyle.Render(fmt.Sprintf("/ %s   (%d / %d)",
			m.stringsFilter.Value(), len(m.stringsFiltered), len(m.stringsList)))
	}

	addrW := m.file.AddrHexWidth()
	hdr := fmt.Sprintf(" %-10s %-*s %-16s  %s", "Offset", 2+addrW, "Address", "Section", "String")
	header := m.tableHeader(hdr)

	visible := bodyH - 2 // filter row + header
	if visible < 1 {
		visible = 1
	}
	rowHeight := func(i int) int {
		return m.stringRowHeight(i)
	}
	top := m.visualTopForView(m.stringsCur, m.stringsTop, len(m.stringsFiltered), visible, rowHeight)
	m.stringsTop = top
	m.renderedStringsTop = top
	m.pageRows = pageStep(top, len(m.stringsFiltered), visible, rowHeight)

	rows := []string{filterRow, header}
	for i := top; i < len(m.stringsFiltered); i++ {
		line := m.stringRow(i, addrW)
		if i == m.stringsCur {
			line = m.theme.tableSelStyle.Render(ansi.Strip(line))
		}
		if !appendRenderedRowsIndented(&rows, line, m.width, m.wrap, addrW+33, bodyH) {
			break
		}
	}
	return padBodyRows(rows, m.width, bodyH)
}

func (m *Model) stringRowHeight(i int) int {
	if i < 0 || i >= len(m.stringsFiltered) {
		return 1
	}
	addrW := m.file.AddrHexWidth()
	key := rowCacheKey{i, m.width, addrW, m.wrap}
	if m.stringHeightCache != nil {
		if h, ok := m.stringHeightCache[key]; ok {
			return h
		}
	}
	line := m.stringRow(i, addrW)
	h := len(renderLineRowsIndented(line, m.width, m.wrap, addrW+33))
	if m.stringHeightCache == nil {
		m.stringHeightCache = make(map[rowCacheKey]int)
	}
	m.stringHeightCache[key] = h
	return h
}

func (m *Model) stringRow(i, addrW int) string {
	key := rowCacheKey{i, m.width, addrW, m.wrap}
	if m.stringRowCache != nil {
		if s, ok := m.stringRowCache[key]; ok {
			return s
		}
	}

	s := m.stringsList[m.stringsFiltered[i]]
	addr := strings.Repeat(" ", 2+addrW)
	if s.HasAddr {
		addr = fmt.Sprintf("0x%0*x", addrW, s.Addr)
	}
	text := sanitizeString(s.Text)
	if m.wrap {
		text = s.Text
	}
	line := fmt.Sprintf(" %s %s %s  %s",
		m.theme.addrStyle.Render(fmt.Sprintf("0x%-8x", s.Offset)),
		m.theme.addrStyle.Render(padVisual(addr, 2+addrW)),
		m.theme.footerStyle.Render(padVisual(truncateMiddle(s.Section, 16), 16)),
		m.theme.tableRowStyle.Render(text))
	line = m.stringRowStyle(s).Render(line)

	if m.stringRowCache == nil {
		m.stringRowCache = make(map[rowCacheKey]string)
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
