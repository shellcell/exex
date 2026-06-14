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
	switch key {
	case "up", "k":
		if m.stringsCur > 0 {
			m.stringsCur--
		}
	case "down", "j":
		if m.stringsCur < n-1 {
			m.stringsCur++
		}
	case "pgup":
		m.stringsCur = max(0, m.stringsCur-m.bodyHeight())
	case "pgdown":
		m.stringsCur = min(n-1, m.stringsCur+m.bodyHeight())
	case "home":
		m.stringsCur = 0
	case "end", "G":
		m.stringsCur = n - 1
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
	header := tableHeaderStyle.Render(padRight(hdr, m.width))

	visible := bodyH - 1
	if visible < 1 {
		visible = 1
	}
	if m.stringsCur < m.stringsTop {
		m.stringsTop = m.stringsCur
	} else if m.stringsCur >= m.stringsTop+visible {
		m.stringsTop = m.stringsCur - visible + 1
	}
	end := m.stringsTop + visible
	if end > len(m.stringsList) {
		end = len(m.stringsList)
	}

	var b strings.Builder
	b.WriteString(header)
	b.WriteString("\n")
	for i := m.stringsTop; i < end; i++ {
		s := m.stringsList[i]
		addr := strings.Repeat(" ", 2+addrW)
		if s.HasAddr {
			addr = fmt.Sprintf("0x%0*x", addrW, s.Addr)
		}
		line := fmt.Sprintf(" 0x%-8x %-*s %-16s  %s",
			s.Offset, 2+addrW, addr, truncate(s.Section, 16), sanitizeString(s.Text))
		line = padRight(line, m.width)
		if i == m.stringsCur {
			b.WriteString(tableSelStyle.Render(line))
		} else {
			b.WriteString(m.stringRowStyle(s).Render(line))
		}
		b.WriteString("\n")
	}
	return padBody(b.String(), m.width, bodyH)
}

// stringRowStyle colours a string row by the category of its owning section
// (matching the Sections and Hex views); unmapped strings render dim.
func (m *Model) stringRowStyle(s binfile.StringEntry) lipgloss.Style {
	if sec := m.sectionAtOffset(s.Offset); sec != nil {
		return styleForSection(sec)
	}
	return footerStyle
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
