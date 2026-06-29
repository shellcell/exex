package ui

import (
	"strings"

	"charm.land/lipgloss/v2"
)

type sortableHeaderCol[T comparable] struct {
	start, end int
	sort       T
}

func sortHeaderLabel[T comparable](label string, width int, sort, active T, desc bool) string {
	if sort != active {
		return label
	}
	return activeSortHeaderLabel(label, width, desc)
}

func activeSortHeaderLabel(label string, width int, desc bool) string {
	triangle := sortTriangle(desc)
	labelW := lipgloss.Width(label)
	triangleW := lipgloss.Width(triangle)
	if width <= labelW+triangleW {
		return label + triangle
	}
	return label + strings.Repeat(" ", width-labelW-triangleW) + triangle
}

func trailingSortHeaderLabel[T comparable](label string, sort, active T, desc bool) string {
	if sort != active {
		return label
	}
	return activeSortHeaderLabel(label, lipgloss.Width(label)+3, desc)
}

func sortTriangle(desc bool) string {
	if desc {
		return "▽"
	}
	return "△"
}

func hitSortableHeader[T comparable](cols []sortableHeaderCol[T], x int) (T, bool) {
	for _, col := range cols {
		if x >= col.start && x < col.end {
			return col.sort, true
		}
	}
	var zero T
	return zero, false
}

// applySortHeaderClick mirrors htop-style header sorting: choosing a different
// column sorts it ascending; clicking the active column reverses the direction.
func applySortHeaderClick[T comparable](active *T, desc *bool, sort T) bool {
	if *active == sort {
		*desc = !*desc
		return false
	}
	*active = sort
	*desc = false
	return true
}

func sortDirectionLabel(desc bool) string {
	if desc {
		return "descending"
	}
	return "ascending"
}

func (m *Model) handleSortableHeaderClick(x, bodyRow int) bool {
	switch m.mode {
	case modeSections:
		return bodyRow == 1 && m.clickSectionsHeader(x)
	case modeSymbols:
		return bodyRow == 1 && m.clickSymbolsHeader(x)
	case modeStrings:
		return bodyRow == 1 && m.clickStringsHeader(x)
	case modeRelocs:
		return bodyRow == 1 && m.clickRelocsHeader(x)
	case modeLibs:
		return bodyRow == m.libsTitleRow() && m.clickLibsHeader(x)
	}
	return false
}

func (m *Model) isTableHeaderRow(bodyRow int) bool {
	switch m.mode {
	case modeSections, modeSymbols:
		return bodyRow == 1
	case modeStrings:
		m.ensureStrings()
		return len(m.stringsList) > 0 && bodyRow == 1
	case modeRelocs:
		return bodyRow == 1
	case modeLibs:
		return bodyRow == m.libsTitleRow()
	}
	return false
}

func (m *Model) clickSectionsHeader(x int) bool {
	addrW := m.file.AddrHexWidth()
	phys := m.sectionsHavePhys()
	if m.showSegments {
		phys = m.segmentsHavePhys()
	}
	sort, ok := hitSortableHeader(m.sectionHeaderCols(addrW, phys), x)
	if !ok {
		return false
	}
	fieldChanged := applySortHeaderClick(&m.sectionsSort, &m.sectionsSortDesc, sort)
	m.sectionsCur, m.sectionsTop = 0, 0
	m.recomputeSections()
	if fieldChanged {
		m.setStatus("sort: "+m.sectionsSort.String(), false)
	} else {
		m.setStatus("sort order: "+sortDirectionLabel(m.sectionsSortDesc), false)
	}
	return true
}

func (m *Model) sectionHeaderCols(addrW int, phys bool) []sortableHeaderCol[sectionSort] {
	addrCol := 2 + addrW
	nameStart, nameW, typeW := 6, 22, 14
	if m.showSegments {
		nameW, typeW = 16, 5
	}
	addrStart := nameStart + nameW + 1 + typeW + 1
	sizeStart := addrStart + addrCol + 1
	if phys {
		sizeStart += addrCol + 1
	}
	return []sortableHeaderCol[sectionSort]{
		{start: 1, end: 4, sort: secSortIndex},
		{start: nameStart, end: nameStart + nameW, sort: secSortName},
		{start: addrStart, end: addrStart + addrCol, sort: secSortAddr},
		{start: sizeStart, end: sizeStart + 12, sort: secSortSize},
	}
}

func (m *Model) clickSymbolsHeader(x int) bool {
	if m.symbolTreeActive() {
		return false
	}
	sort, ok := hitSortableHeader(m.symbolHeaderCols(m.file.AddrHexWidth()), x)
	if !ok {
		return false
	}
	fieldChanged := applySortHeaderClick(&m.symbolsSort, &m.symbolsSortDesc, sort)
	m.symbolsCur, m.symbolsTop = 0, 0
	m.recomputeSymbols()
	if fieldChanged {
		m.setStatus("sort: "+m.symbolsSort.String(), false)
	} else {
		m.setStatus("sort order: "+sortDirectionLabel(m.symbolsSortDesc), false)
	}
	return true
}

func (m *Model) symbolHeaderCols(addrW int) []sortableHeaderCol[symbolSort] {
	addrCol := 2 + addrW
	sizeStart := addrCol + 2
	nameStart := addrCol + 28
	return []sortableHeaderCol[symbolSort]{
		{start: 1, end: 1 + addrCol, sort: sortByAddr},
		{start: sizeStart, end: sizeStart + 9, sort: sortBySize},
		{start: nameStart, end: m.width, sort: sortByName},
	}
}

func (m *Model) clickStringsHeader(x int) bool {
	m.ensureStrings()
	if len(m.stringsList) == 0 {
		return false
	}
	sort, ok := hitSortableHeader(m.stringHeaderCols(m.file.AddrHexWidth()), x)
	if !ok {
		return false
	}
	fieldChanged := applySortHeaderClick(&m.stringsSort, &m.stringsSortDesc, sort)
	m.stringsCur, m.stringsTop = 0, 0
	m.recomputeStrings()
	if fieldChanged {
		m.setStatus("sort: "+m.stringsSort.String(), false)
	} else {
		m.setStatus("sort order: "+sortDirectionLabel(m.stringsSortDesc), false)
	}
	return true
}

func (m *Model) stringHeaderCols(addrW int) []sortableHeaderCol[stringSort] {
	addrCol := 2 + addrW
	addrStart := 12
	stringStart := addrW + 33
	return []sortableHeaderCol[stringSort]{
		{start: 1, end: 11, sort: strSortOffset},
		{start: addrStart, end: addrStart + addrCol, sort: strSortAddr},
		{start: stringStart, end: m.width, sort: strSortText},
	}
}

func (m *Model) clickRelocsHeader(x int) bool {
	sort, ok := hitSortableHeader(m.relocHeaderCols(m.file.AddrHexWidth()), x)
	if !ok {
		return false
	}
	fieldChanged := applySortHeaderClick(&m.relocSort, &m.relocSortDesc, sort)
	m.relocCur, m.relocTop = 0, 0
	m.recomputeRelocs()
	if fieldChanged {
		m.setStatus("sort: "+m.relocSort.String(), false)
	} else {
		m.setStatus("sort order: "+sortDirectionLabel(m.relocSortDesc), false)
	}
	return true
}

// relocHeaderCols maps the relocation table's header columns to their x ranges,
// matching the layout in renderRelocs / relocRow.
func (m *Model) relocHeaderCols(addrW int) []sortableHeaderCol[relocSortField] {
	offCol := 2 + addrW
	typeStart := 1 + offCol + 2
	secStart := typeStart + 24 + 1
	symStart := secStart + 12 + 1
	return []sortableHeaderCol[relocSortField]{
		{start: 1, end: 1 + offCol, sort: relocSortOffset},
		{start: typeStart, end: typeStart + 24, sort: relocSortType},
		{start: secStart, end: secStart + 12, sort: relocSortSection},
		{start: symStart, end: m.width, sort: relocSortSym},
	}
}

func (m *Model) clickLibsHeader(x int) bool {
	if m.file.Info == nil || len(m.file.Info.DynamicLibs) == 0 {
		return false
	}
	if x < 1 || x >= 1+m.libsTitleWidth() {
		return false
	}
	m.libsSortDesc = !m.libsSortDesc
	m.libsCur, m.libsTop = 0, 0
	m.buildLibRows()
	m.setStatus("sort order: "+sortDirectionLabel(m.libsSortDesc), false)
	return true
}
