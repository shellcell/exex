package ui

// This file owns the sections view: a filterable table of the binary's
// sections. Enter routes a section to the most useful view (disasm for code,
// hex for other mapped sections, raw for unmapped ones).

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/rabarbra/exex/internal/binfile"
)

// recomputeSections rebuilds sectionsFiltered from the current filter text,
// matching on section name.
func (m *Model) recomputeSections() {
	needle := strings.ToLower(m.sectionsFilter.Value())
	m.sectionsFiltered = m.sectionsFiltered[:0]
	for i, s := range m.sections {
		if needle == "" || strings.Contains(strings.ToLower(s.Name), needle) {
			m.sectionsFiltered = append(m.sectionsFiltered, i)
		}
	}
	if m.sectionsCur >= len(m.sectionsFiltered) {
		m.sectionsCur = max(0, len(m.sectionsFiltered)-1)
	}
}

func (m *Model) updateSections(key string) (tea.Model, tea.Cmd) {
	n := len(m.sectionsFiltered)
	switch key {
	case "/":
		m.sectionsFilter.Focus()
		return m, nil
	case "up", "k":
		if m.sectionsCur > 0 {
			m.sectionsCur--
		}
	case "down", "j":
		if m.sectionsCur < n-1 {
			m.sectionsCur++
		}
	case "pgup":
		m.sectionsCur = max(0, m.sectionsCur-m.bodyHeight())
	case "pgdown":
		m.sectionsCur = min(n-1, m.sectionsCur+m.bodyHeight())
	case "home":
		m.sectionsCur = 0
	case "end", "G":
		m.sectionsCur = n - 1
	case "enter":
		sec, ok := m.currentSection()
		if !ok {
			return m, nil
		}
		switch {
		case binfile.IsExecSection(&sec) && m.dis != nil:
			m.loadDisasmAt(sec.Addr)
		case sec.Alloc && sec.Addr != 0:
			m.openHexAt(sec.Addr)
		default:
			// No virtual address (debug, symbol tables, …): show its bytes in
			// the raw file view at the section's file offset.
			m.openRawAt(sec.Offset)
		}
	case "a":
		if sec, ok := m.currentSection(); ok {
			m.copyToClipboard(fmt.Sprintf("0x%0*x", m.file.AddrHexWidth(), sec.Addr), "address")
		}
	case "s":
		if sec, ok := m.currentSection(); ok {
			m.copyToClipboard(sec.Name, "section name")
		}
	}
	return m, nil
}

// currentSection returns the selected section through the active filter.
func (m *Model) currentSection() (binfile.Section, bool) {
	if m.sectionsCur < 0 || m.sectionsCur >= len(m.sectionsFiltered) {
		return binfile.Section{}, false
	}
	return m.sections[m.sectionsFiltered[m.sectionsCur]], true
}

func (m *Model) renderSections() string {
	bodyH := m.bodyHeight()
	if bodyH < 3 {
		bodyH = 3
	}

	filterRow := m.sectionsFilter.View()
	if !m.sectionsFilter.Focused() {
		filterRow = footerStyle.Render(fmt.Sprintf("/ %s   (%d / %d)",
			m.sectionsFilter.Value(), len(m.sectionsFiltered), len(m.sections)))
	}

	// columns: idx, name, type, addr, size, flags
	addrW := m.file.AddrHexWidth() // hex digits in an address
	addrCol := 2 + addrW           // "0x" + digits
	hdr := fmt.Sprintf(" %3s  %-22s %-14s %-*s %-12s  %s",
		"#", "Name", "Type", addrCol, "Addr", "Size", "Flags")
	header := tableHeaderStyle.Render(padRight(hdr, m.width))

	visible := bodyH - 2 // filter row + header
	if visible < 1 {
		visible = 1
	}
	if m.sectionsCur < m.sectionsTop {
		m.sectionsTop = m.sectionsCur
	} else if m.sectionsCur >= m.sectionsTop+visible {
		m.sectionsTop = m.sectionsCur - visible + 1
	}
	end := m.sectionsTop + visible
	if end > len(m.sectionsFiltered) {
		end = len(m.sectionsFiltered)
	}

	var b strings.Builder
	b.WriteString(filterRow)
	b.WriteString("\n")
	b.WriteString(header)
	b.WriteString("\n")
	for i := m.sectionsTop; i < end; i++ {
		idx := m.sectionsFiltered[i]
		s := m.sections[idx]
		line := fmt.Sprintf(" %3d  %-22s %-14s 0x%0*x %-12d  %s",
			idx, truncate(s.Name, 22), truncate(s.TypeName, 14), addrW, s.Addr, s.Size, s.Flags)
		line = padRight(line, m.width)
		if i == m.sectionsCur {
			b.WriteString(tableSelStyle.Render(line))
		} else {
			b.WriteString(styleForSection(&s).Render(line))
		}
		b.WriteString("\n")
	}
	return padBody(b.String(), m.width, bodyH)
}
