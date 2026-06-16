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
	if navKey(&m.sectionsCur, n, m.bodyHeight(), key) {
		return m, nil
	}
	switch key {
	case "/":
		m.sectionsFilter.Focus()
		return m, nil
	case "enter":
		sec, ok := m.currentSection()
		if !ok {
			return m, nil
		}
		if sec.Alloc && sec.Addr != 0 {
			m.openHexAt(sec.Addr)
		} else {
			m.openRawAt(sec.Offset)
		}
	case "d":
		sec, ok := m.currentSection()
		if !ok {
			return m, nil
		}
		if binfile.IsExecSection(&sec) && m.dis != nil {
			m.loadDisasmAt(sec.Addr)
		} else {
			m.setStatus("section is not executable", true)
		}
	case "w":
		m.toggleWrap()
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
		filterRow = m.theme.footerStyle.Render(fmt.Sprintf("/ %s   (%d / %d)",
			m.sectionsFilter.Value(), len(m.sectionsFiltered), len(m.sections)))
	}

	// columns: idx, name, type, addr, size, flags
	addrW := m.file.AddrHexWidth() // hex digits in an address
	addrCol := 2 + addrW           // "0x" + digits
	hdr := fmt.Sprintf(" %3s  %-22s %-14s %-*s %-12s  %s",
		"#", "Name", "Type", addrCol, "Addr", "Size", "Flags")
	header := m.theme.tableHeaderStyle.Render(padRight(hdr, m.width))

	visible := bodyH - 2 // filter row + header
	if visible < 1 {
		visible = 1
	}
	rowHeight := func(i int) int {
		return m.sectionRowHeight(i)
	}
	top := visualTop(m.sectionsCur, m.sectionsTop, len(m.sectionsFiltered), visible, rowHeight)

	rows := []string{padRight(filterRow, m.width), padRight(header, m.width)}
	for i := top; i < len(m.sectionsFiltered); i++ {
		line := m.sectionRow(i, addrW, i == m.sectionsCur)
		if !appendRenderedRowsIndented(&rows, line, m.width, m.wrap, 6, bodyH) {
			break
		}
	}
	return padBodyRows(rows, m.width, bodyH)
}

func (m *Model) sectionRowHeight(i int) int {
	if i < 0 || i >= len(m.sectionsFiltered) {
		return 1
	}
	return len(renderLineRowsIndented(m.sectionRow(i, m.file.AddrHexWidth(), false), m.width, m.wrap, 6))
}

func (m *Model) sectionRow(i, addrW int, selected bool) string {
	idx := m.sectionsFiltered[i]
	s := m.sections[idx]
	name := s.Name
	typeName := s.TypeName
	if !m.wrap {
		name = truncate(name, 22)
		typeName = truncate(typeName, 14)
	}
	line := fmt.Sprintf(" %s  %-22s %-14s %s %-12d  %s",
		m.theme.addrStyle.Render(fmt.Sprintf("%3d", idx)), name, typeName, m.theme.addrStyle.Render(fmt.Sprintf("0x%0*x", addrW, s.Addr)), s.Size, s.Flags)
	if selected {
		return m.theme.tableSelStyle.Render(stripANSI(line))
	}
	return m.theme.styleForSection(&s).Render(line)
}
