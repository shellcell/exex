package ui

// This file owns the sections view: a filterable table of the binary's
// sections. Enter routes a section to the most useful view (disasm for code,
// hex for other mapped sections, raw for unmapped ones). The `t` key toggles to
// the coarser segment (memory-region) table, which sections live inside.

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/rabarbra/exex/internal/binfile"
)

// recomputeSections rebuilds sectionsFiltered from the current filter text,
// matching on the name of the active table (sections or segments).
func (m *Model) recomputeSections() {
	m.clearSectionCaches()
	needle := strings.ToLower(m.sectionsFilter.Value())
	m.sectionsFiltered = m.sectionsFiltered[:0]
	names := func() int {
		if m.showSegments {
			return len(m.segments)
		}
		return len(m.sections)
	}()
	for i := 0; i < names; i++ {
		var name string
		if m.showSegments {
			name = m.segments[i].Name
		} else {
			name = m.sections[i].Name
		}
		if needle == "" || containsFold(name, needle) {
			m.sectionsFiltered = append(m.sectionsFiltered, i)
		}
	}
	if m.sectionsCur >= len(m.sectionsFiltered) {
		m.sectionsCur = max(0, len(m.sectionsFiltered)-1)
	}
}

func (m *Model) updateSections(key string) (tea.Model, tea.Cmd) {
	n := len(m.sectionsFiltered)
	if navKey(&m.sectionsCur, n, m.listPage(), key) {
		return m, nil
	}
	switch key {
	case "/":
		m.sectionsFilter.Focus()
		return m, nil
	case "t":
		// Toggle sections ⇄ segments. No segments (e.g. PE) → stay on sections.
		if !m.showSegments && len(m.segments) == 0 {
			m.setStatus("no segments in this binary", false)
			return m, nil
		}
		m.showSegments = !m.showSegments
		m.sectionsCur, m.sectionsTop = 0, 0
		m.sectionsFilter.SetValue("")
		m.recomputeSections()
		if m.showSegments {
			m.setStatus("showing segments (t for sections)", false)
		} else {
			m.setStatus("showing sections (t for segments)", false)
		}
		return m, nil
	case "enter":
		if m.showSegments {
			if seg, ok := m.currentSegment(); ok {
				if seg.Addr != 0 {
					m.openHexAt(seg.Addr)
				} else {
					m.openRawAt(seg.Offset)
				}
			}
			return m, nil
		}
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
		if m.showSegments {
			if seg, ok := m.currentSegment(); ok && seg.X && seg.Addr != 0 && m.dis != nil {
				m.loadDisasmAt(seg.Addr)
			} else {
				m.setStatus("segment is not executable", true)
			}
			return m, nil
		}
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
		if m.showSegments {
			if seg, ok := m.currentSegment(); ok {
				m.copyToClipboard(fmt.Sprintf("0x%0*x", m.file.AddrHexWidth(), seg.Addr), "address")
			}
			return m, nil
		}
		if sec, ok := m.currentSection(); ok {
			m.copyToClipboard(fmt.Sprintf("0x%0*x", m.file.AddrHexWidth(), sec.Addr), "address")
		}
	case "s":
		if m.showSegments {
			if seg, ok := m.currentSegment(); ok {
				m.copyToClipboard(seg.Name, "segment name")
			}
			return m, nil
		}
		if sec, ok := m.currentSection(); ok {
			m.copyToClipboard(sec.Name, "section name")
		}
	}
	return m, nil
}

// currentSection returns the selected section through the active filter.
func (m *Model) currentSection() (binfile.Section, bool) {
	if m.showSegments || m.sectionsCur < 0 || m.sectionsCur >= len(m.sectionsFiltered) {
		return binfile.Section{}, false
	}
	return m.sections[m.sectionsFiltered[m.sectionsCur]], true
}

// currentSegment returns the selected segment through the active filter.
func (m *Model) currentSegment() (binfile.Segment, bool) {
	if !m.showSegments || m.sectionsCur < 0 || m.sectionsCur >= len(m.sectionsFiltered) {
		return binfile.Segment{}, false
	}
	return m.segments[m.sectionsFiltered[m.sectionsCur]], true
}

func (m *Model) renderSections() string {
	bodyH := m.bodyHeight()
	if bodyH < 3 {
		bodyH = 3
	}

	total := len(m.sections)
	kind := "sections"
	if m.showSegments {
		total = len(m.segments)
		kind = "segments"
	}
	filterRow := m.sectionsFilter.View()
	if !m.sectionsFilter.Focused() {
		filterRow = m.theme.footerStyle.Render(fmt.Sprintf("/ %s   %s (%d / %d)   t: toggle",
			m.sectionsFilter.Value(), kind, len(m.sectionsFiltered), total))
	}

	addrW := m.file.AddrHexWidth()
	addrCol := 2 + addrW
	phys := m.sectionsHavePhys()
	if m.showSegments {
		phys = m.segmentsHavePhys()
	}
	var hdr string
	switch {
	case m.showSegments && phys:
		hdr = fmt.Sprintf(" %3s  %-16s %-5s %-*s %-*s %-12s %-12s  %s",
			"#", "Type", "Perms", addrCol, "Addr", addrCol, "PAddr", "MemSize", "FileSize", "Align")
	case m.showSegments:
		hdr = fmt.Sprintf(" %3s  %-16s %-5s %-*s %-12s %-12s  %s",
			"#", "Type", "Perms", addrCol, "Addr", "MemSize", "FileSize", "Align")
	case phys:
		hdr = fmt.Sprintf(" %3s  %-22s %-14s %-*s %-*s %-12s  %s",
			"#", "Name", "Type", addrCol, "Addr", addrCol, "LMA", "Size", "Flags")
	default:
		hdr = fmt.Sprintf(" %3s  %-22s %-14s %-*s %-12s  %s",
			"#", "Name", "Type", addrCol, "Addr", "Size", "Flags")
	}
	header := m.tableHeader(hdr)

	visible := bodyH - 2 // filter row + header
	if visible < 1 {
		visible = 1
	}
	rowHeight := func(i int) int {
		return m.sectionRowHeight(i)
	}
	top := m.visualTopForView(m.sectionsCur, m.sectionsTop, len(m.sectionsFiltered), visible, rowHeight)
	m.pageRows = pageStep(top, len(m.sectionsFiltered), visible, rowHeight)
	m.sectionsTop = top
	m.renderedSectionsTop = top

	rows := []string{filterRow, header}
	for i := top; i < len(m.sectionsFiltered); i++ {
		line := m.sectionRow(i, addrW)
		if i == m.sectionsCur {
			line = m.theme.tableSelStyle.Render(ansi.Strip(line))
		}
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
	addrW := m.file.AddrHexWidth()
	key := rowCacheKey{i, m.width, addrW, m.wrap}
	if m.sectionHeightCache != nil {
		if h, ok := m.sectionHeightCache[key]; ok {
			return h
		}
	}
	line := m.sectionRow(i, addrW)
	h := len(renderLineRowsIndented(line, m.width, m.wrap, 6))
	if m.sectionHeightCache == nil {
		m.sectionHeightCache = make(map[rowCacheKey]int)
	}
	m.sectionHeightCache[key] = h
	return h
}

func (m *Model) sectionRow(i, addrW int) string {
	key := rowCacheKey{i, m.width, addrW, m.wrap}
	if m.sectionRowCache != nil {
		if s, ok := m.sectionRowCache[key]; ok {
			return s
		}
	}

	var line string
	if m.showSegments {
		line = m.segmentRow(i, addrW)
	} else {
		line = m.sectionRowText(i, addrW)
	}

	if m.sectionRowCache == nil {
		m.sectionRowCache = make(map[rowCacheKey]string)
	}
	m.sectionRowCache[key] = line
	return line
}

// sectionsHavePhys / segmentsHavePhys report whether any row carries a distinct
// load/physical address, so the views add an LMA / PAddr column only then.
func (m *Model) sectionsHavePhys() bool {
	for i := range m.sections {
		if m.sections[i].PhysAddr != 0 {
			return true
		}
	}
	return false
}

func (m *Model) segmentsHavePhys() bool {
	for i := range m.segments {
		if m.segments[i].PhysAddr != 0 {
			return true
		}
	}
	return false
}

// physCell renders a load/physical address column, or a dim "-" when unset.
func (m *Model) physCell(phys uint64, addrW int) string {
	if phys == 0 {
		return m.theme.srcShadowStyle.Render(padVisual("-", 2+addrW))
	}
	return m.theme.addrStyle.Render(fmt.Sprintf("0x%0*x", addrW, phys))
}

func (m *Model) sectionRowText(i, addrW int) string {
	idx := m.sectionsFiltered[i]
	s := m.sections[idx]
	name := s.Name
	typeName := s.TypeName
	if !m.wrap {
		name = truncateMiddle(name, 22)
		typeName = truncateMiddle(typeName, 14)
	}
	rowStyle := m.theme.styleForSection(&s)
	lma := ""
	if m.sectionsHavePhys() {
		lma = " " + m.physCell(s.PhysAddr, addrW)
	}
	return fmt.Sprintf(" %s  %s %s %s%s %s  %s",
		m.theme.addrStyle.Render(fmt.Sprintf("%3d", idx)),
		rowStyle.Render(padVisual(name, 22)),
		rowStyle.Render(padVisual(typeName, 14)),
		m.theme.addrStyle.Render(fmt.Sprintf("0x%0*x", addrW, s.Addr)),
		lma,
		rowStyle.Render(fmt.Sprintf("%-12d", s.Size)),
		rowStyle.Render(s.Flags))
}

// segmentRow renders one segment row. Executable segments reuse the .text row
// colour, writable ones the data colour, the rest read-only data — so segment
// colours read like the section table.
func (m *Model) segmentRow(i, addrW int) string {
	idx := m.sectionsFiltered[i]
	s := m.segments[idx]
	name := s.Name
	if !m.wrap {
		name = truncateMiddle(name, 16)
	}
	rowStyle := m.theme.secRodataStyle
	switch {
	case s.X:
		rowStyle = m.theme.secTextStyle
	case s.W:
		rowStyle = m.theme.secDataStyle
	}
	align := "-"
	if s.Align > 0 {
		align = fmt.Sprintf("0x%x", s.Align)
	}
	paddr := ""
	if m.segmentsHavePhys() {
		paddr = " " + m.physCell(s.PhysAddr, addrW)
	}
	return fmt.Sprintf(" %s  %s %s %s%s %s %s  %s",
		m.theme.addrStyle.Render(fmt.Sprintf("%3d", idx)),
		rowStyle.Render(padVisual(name, 16)),
		rowStyle.Render(padVisual(s.Perms(), 5)),
		m.theme.addrStyle.Render(fmt.Sprintf("0x%0*x", addrW, s.Addr)),
		paddr,
		rowStyle.Render(fmt.Sprintf("%-12d", s.Size)),
		rowStyle.Render(fmt.Sprintf("%-12d", s.FileSize)),
		rowStyle.Render(align))
}
