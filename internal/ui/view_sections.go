package ui

// This file owns the sections view: a filterable table of the binary's
// sections. Enter routes a section to the most useful view (disasm for code,
// hex for other mapped sections, raw for unmapped ones). The `t` key toggles to
// the coarser segment (memory-region) table, which sections live inside.

import (
	"fmt"
	"sort"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/rabarbra/exex/internal/binfile"
)

// sectionSort is the display order of the (filtered) section/segment list.
type sectionSort uint8

const (
	secSortIndex sectionSort = iota // file order (the natural section index)
	secSortName
	secSortAddr
	secSortSize
)

// String returns the sort's filter-status label.
func (s sectionSort) String() string {
	switch s {
	case secSortName:
		return "name"
	case secSortAddr:
		return "address"
	case secSortSize:
		return "size"
	}
	return "index"
}

// secSortValue returns the name/addr/size of the active table's row idx, for the
// sort comparators (works for both the section and segment tables).
func (m *Model) secSortValue(idx int) (name string, addr, size uint64) {
	if m.showSegments {
		s := m.segments[idx]
		return s.Name, s.Addr, s.Size
	}
	s := m.sections[idx]
	return s.Name, s.Addr, s.Size
}

// applySectionSort orders sectionsFiltered by the active field. Index order is
// the slice's natural order, so it only needs reversing for descending.
func (m *Model) applySectionSort() {
	desc := m.sectionsSortDesc
	if m.sectionsSort == secSortIndex {
		if desc {
			reverseInts(m.sectionsFiltered)
		}
		return
	}
	sort.SliceStable(m.sectionsFiltered, func(a, b int) bool {
		na, aa, sa := m.secSortValue(m.sectionsFiltered[a])
		nb, ab, sb := m.secSortValue(m.sectionsFiltered[b])
		var less bool
		switch m.sectionsSort {
		case secSortName:
			less = na < nb
		case secSortAddr:
			less = aa < ab
		case secSortSize:
			less = sa < sb
		}
		if desc {
			return !less
		}
		return less
	})
}

// buildSectionFacets collects the distinct type names and flag strings of the
// section table, so the alt+t / alt+f filters can cycle through them.
func (m *Model) buildSectionFacets() {
	seenT, seenF := map[string]bool{}, map[string]bool{}
	m.sectionsTypes = m.sectionsTypes[:0]
	m.sectionsFlagsList = m.sectionsFlagsList[:0]
	for i := range m.sections {
		if t := m.sections[i].TypeName; t != "" && !seenT[t] {
			seenT[t] = true
			m.sectionsTypes = append(m.sectionsTypes, t)
		}
		if fl := m.sections[i].Flags; fl != "" && !seenF[fl] {
			seenF[fl] = true
			m.sectionsFlagsList = append(m.sectionsFlagsList, fl)
		}
	}
	sort.Strings(m.sectionsTypes)
	sort.Strings(m.sectionsFlagsList)
}

// cycleStringList steps a value through off → list[0] → … → list[n-1] → off,
// shared by the section type/flags filters.
func cycleStringList(on *bool, cur *string, list []string) {
	if len(list) == 0 {
		return
	}
	if !*on {
		*on, *cur = true, list[0]
		return
	}
	for i, v := range list {
		if v == *cur {
			if i == len(list)-1 {
				*on = false
				return
			}
			*cur = list[i+1]
			return
		}
	}
	*on = false
}

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
			// The type/flags filters only apply to the section table.
			if m.sectionsTypeOn && m.sections[i].TypeName != m.sectionsType {
				continue
			}
			if m.sectionsFlagsOn && m.sections[i].Flags != m.sectionsFlags {
				continue
			}
		}
		if needle == "" || containsFold(name, needle) {
			m.sectionsFiltered = append(m.sectionsFiltered, i)
		}
	}
	m.applySectionSort()
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
	case "esc":
		dirty := m.sectionsTypeOn || m.sectionsFlagsOn || m.sectionsFilter.Value() != "" || m.sectionsFilter.Focused()
		m.sectionsFilter.SetValue("")
		m.sectionsFilter.Blur()
		m.sectionsTypeOn = false
		m.sectionsFlagsOn = false
		m.sectionsCur, m.sectionsTop = 0, 0
		m.recomputeSections()
		if dirty {
			m.setStatus("filters cleared", false)
		}
		return m, nil
	case "alt+t":
		if m.showSegments {
			return m, nil
		}
		cycleStringList(&m.sectionsTypeOn, &m.sectionsType, m.sectionsTypes)
		m.sectionsCur, m.sectionsTop = 0, 0
		m.recomputeSections()
		if m.sectionsTypeOn {
			m.setStatus("section type filter: "+m.sectionsType, false)
		} else {
			m.setStatus("section type filter: all", false)
		}
		return m, nil
	case "alt+f":
		if m.showSegments {
			return m, nil
		}
		cycleStringList(&m.sectionsFlagsOn, &m.sectionsFlags, m.sectionsFlagsList)
		m.sectionsCur, m.sectionsTop = 0, 0
		m.recomputeSections()
		if m.sectionsFlagsOn {
			m.setStatus("section flags filter: "+m.sectionsFlags, false)
		} else {
			m.setStatus("section flags filter: all", false)
		}
		return m, nil
	case "t":
		// Cycle sections → segments → header → sections (segments skipped when the
		// binary has none, e.g. PE).
		m.setStatus(m.cycleSectionsMode(), false)
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
		// jumpDisasmAtAddr falls back to disasm-all when the target isn't in an
		// executable section (e.g. a multiboot/boot section), so kernel code that
		// isn't flagged executable can still be disassembled.
		if m.showSegments {
			if seg, ok := m.currentSegment(); ok && seg.Addr != 0 {
				m.jumpDisasmAtAddr(seg.Addr)
			} else {
				m.setStatus("segment has no address to disassemble", true)
			}
			return m, nil
		}
		if sec, ok := m.currentSection(); ok {
			m.jumpDisasmAtAddr(sec.Addr)
		}
	case "h":
		if addr, ok := m.currentSectionAddr(); ok {
			m.jumpHexAtAddr(addr)
		}
	case "m":
		// Raw is file-offset based, so jump by the section/segment's file offset
		// directly — non-allocated sections (.symtab, .strtab, …) have no virtual
		// address but do have file bytes, so an address-based jump would fail.
		if m.showSegments {
			if seg, ok := m.currentSegment(); ok {
				if seg.FileSize > 0 {
					m.openRawAt(seg.Offset)
				} else {
					m.setStatus("segment has no file bytes", true)
				}
			}
			return m, nil
		}
		if sec, ok := m.currentSection(); ok {
			if sec.FileSize > 0 {
				m.openRawAt(sec.Offset)
			} else {
				m.setStatus("section has no file bytes (e.g. .bss)", true)
			}
		}
	case "s":
		m.sectionsSort = (m.sectionsSort + 1) % 4
		m.sectionsCur, m.sectionsTop = 0, 0
		m.recomputeSections()
		m.setStatus("sort: "+m.sectionsSort.String(), false)
	case "r":
		m.sectionsSortDesc = !m.sectionsSortDesc
		m.sectionsCur, m.sectionsTop = 0, 0
		m.recomputeSections()
		dir := "ascending"
		if m.sectionsSortDesc {
			dir = "descending"
		}
		m.setStatus("sort order: "+dir, false)
	case "w":
		m.toggleWrap()
	case "A":
		if m.showSegments {
			if seg, ok := m.currentSegment(); ok {
				m.copyToClipboard(fmt.Sprintf("0x%0*x", m.file.AddrHexWidth(), seg.Addr), "address")
			}
			return m, nil
		}
		if sec, ok := m.currentSection(); ok {
			m.copyToClipboard(fmt.Sprintf("0x%0*x", m.file.AddrHexWidth(), sec.Addr), "address")
		}
	case "S":
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

// currentSectionAddr returns the virtual address of the selected row (section or
// segment), for the h/m cross-view jumps.
func (m *Model) currentSectionAddr() (uint64, bool) {
	if m.showSegments {
		if seg, ok := m.currentSegment(); ok {
			return seg.Addr, true
		}
		return 0, false
	}
	if sec, ok := m.currentSection(); ok {
		return sec.Addr, true
	}
	return 0, false
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
		dir := "↑"
		if m.sectionsSortDesc {
			dir = "↓"
		}
		extra := ""
		if !m.showSegments {
			tf, ff := "all", "all"
			if m.sectionsTypeOn {
				tf = m.sectionsType
			}
			if m.sectionsFlagsOn {
				ff = m.sectionsFlags
			}
			extra = fmt.Sprintf("   %s type:%s   %s flags:%s", altKeys("t"), tf, altKeys("f"), ff)
		}
		filterRow = m.theme.footerStyle.Render(fmt.Sprintf("/ %s   %s (%d / %d)   t: toggle   s: sort:%s%s%s",
			m.sectionsFilter.Value(), kind, len(m.sectionsFiltered), total, m.sectionsSort.String(), dir, extra))
	}

	addrW := m.file.AddrHexWidth()
	addrCol := 2 + addrW
	phys := m.sectionsHavePhys()
	if m.showSegments {
		phys = m.segmentsHavePhys()
	}
	var hdr string
	idxLabel := sortHeaderLabel("#", 3, secSortIndex, m.sectionsSort, m.sectionsSortDesc)
	nameTitle := "Name"
	if m.showSegments {
		nameTitle = "Type"
	}
	nameW := 22
	if m.showSegments {
		nameW = 16
	}
	nameLabel := sortHeaderLabel(nameTitle, nameW, secSortName, m.sectionsSort, m.sectionsSortDesc)
	addrLabel := sortHeaderLabel("Addr", addrCol, secSortAddr, m.sectionsSort, m.sectionsSortDesc)
	sizeTitle := "Size"
	if m.showSegments {
		sizeTitle = "MemSize"
	}
	sizeLabel := sortHeaderLabel(sizeTitle, 12, secSortSize, m.sectionsSort, m.sectionsSortDesc)
	switch {
	case m.showSegments && phys:
		hdr = fmt.Sprintf(" %3s  %-16s %-5s %-*s %-*s %-12s %-12s  %s",
			idxLabel, nameLabel, "Perms", addrCol, addrLabel, addrCol, "LMA", sizeLabel, "FileSize", "Align")
	case m.showSegments:
		hdr = fmt.Sprintf(" %3s  %-16s %-5s %-*s %-12s %-12s  %s",
			idxLabel, nameLabel, "Perms", addrCol, addrLabel, sizeLabel, "FileSize", "Align")
	case phys:
		hdr = fmt.Sprintf(" %3s  %-22s %-14s %-*s %-*s %-12s  %s",
			idxLabel, nameLabel, "Type", addrCol, addrLabel, addrCol, "LMA", sizeLabel, "Flags")
	default:
		hdr = fmt.Sprintf(" %3s  %-22s %-14s %-*s %-12s  %s",
			idxLabel, nameLabel, "Type", addrCol, addrLabel, sizeLabel, "Flags")
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

	if len(m.sectionsFiltered) == 0 {
		msg := "no entries"
		if m.sectionsFilter.Value() != "" || m.sectionsTypeOn || m.sectionsFlagsOn {
			msg = "no matching entries  ·  Esc clears filters"
		}
		return m.emptyList(msg, filterRow, header)
	}
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
	return m.sectionHeightCache.get(rowCacheKey{i, m.width, addrW, m.wrap}, func() int {
		return len(renderLineRowsIndented(m.sectionRow(i, addrW), m.width, m.wrap, 6))
	})
}

func (m *Model) sectionRow(i, addrW int) string {
	return m.sectionRowCache.get(rowCacheKey{i, m.width, addrW, m.wrap}, func() string {
		if m.showSegments {
			return m.segmentRow(i, addrW)
		}
		return m.sectionRowText(i, addrW)
	})
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
