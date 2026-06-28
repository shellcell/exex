package ui

// The Libraries view's third mode: the relocation table. Relocations are
// dynamic-linking data — the GOT/PLT slots and base fixups that the loader
// patches — so they live alongside the needed-libraries list, reached by the
// same `t` toggle (libraries-flat → libraries-tree → relocations). The list is
// filterable (by symbol / type / section) and Enter jumps to the patched
// address in the Hex view.

import (
	"fmt"
	"sort"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/rabarbra/exex/internal/binfile"
)

// relocSortField is the relocation table's sort key.
type relocSortField uint8

const (
	relocSortOffset relocSortField = iota // file/index order, by patched address
	relocSortType
	relocSortSection
	relocSortSym
)

// String returns the sort's filter-status label.
func (s relocSortField) String() string {
	switch s {
	case relocSortType:
		return "type"
	case relocSortSection:
		return "section"
	case relocSortSym:
		return "symbol"
	}
	return "offset"
}

// cycleLibsMode advances the Libraries view's `t` toggle through
// libraries-flat → libraries-tree → relocations → libraries-flat, returning a
// status label. Relocations are reachable even when there are no needed
// libraries (e.g. a static-PIE binary still has RELATIVE relocations).
func (m *Model) cycleLibsMode() string {
	switch {
	case m.libsRelocs:
		m.libsRelocs = false // → libraries (flat)
		m.libsTree = false
		m.libsFilter.SetValue("")
		m.libsFilter.Blur()
		m.libsCur, m.libsTop = 0, 0
		return "libs view: flat list"
	case m.libsTree:
		m.libsTree = false
		m.enterRelocs()
		return "showing relocations (t for libraries)"
	default:
		m.libsTree = true
		m.libsCur, m.libsTop = 0, 0
		m.buildLibRows()
		return "libs view: tree"
	}
}

// enterRelocs switches the view into relocation mode, building the facet lists
// and the filtered list.
func (m *Model) enterRelocs() {
	m.libsRelocs = true
	m.libsFilter.SetValue("")
	m.libsFilter.Blur()
	m.relocCur, m.relocTop = 0, 0
	m.buildRelocFacets()
	m.recomputeRelocs()
}

// recomputeRelocs rebuilds relocFiltered from the active facet filters (type /
// section) and the text filter (matching symbol, type or section).
func (m *Model) recomputeRelocs() {
	rels := m.file.Relocations()
	needle := strings.ToLower(m.libsFilter.Value())
	m.relocFiltered = m.relocFiltered[:0]
	for i := range rels {
		if m.relocTypeOn && rels[i].Type != m.relocType {
			continue
		}
		if m.relocSecOn && rels[i].Section != m.relocSec {
			continue
		}
		if needle == "" ||
			containsFold(rels[i].Sym, needle) ||
			containsFold(rels[i].Type, needle) ||
			containsFold(rels[i].Section, needle) {
			m.relocFiltered = append(m.relocFiltered, i)
		}
	}
	m.applyRelocSort(rels)
	if m.relocCur >= len(m.relocFiltered) {
		m.relocCur = max(0, len(m.relocFiltered)-1)
	}
}

// buildRelocFacets collects the distinct relocation types and section names, so
// the alt+t / alt+s facet filters can cycle through them. Built once per scan.
func (m *Model) buildRelocFacets() {
	rels := m.file.Relocations()
	seenT, seenS := map[string]bool{}, map[string]bool{}
	m.relocTypes = m.relocTypes[:0]
	m.relocSecs = m.relocSecs[:0]
	for i := range rels {
		if t := rels[i].Type; t != "" && !seenT[t] {
			seenT[t] = true
			m.relocTypes = append(m.relocTypes, t)
		}
		if s := rels[i].Section; s != "" && !seenS[s] {
			seenS[s] = true
			m.relocSecs = append(m.relocSecs, s)
		}
	}
	sort.Strings(m.relocTypes)
	sort.Strings(m.relocSecs)
}

// applyRelocSort orders relocFiltered by the active field. Offset order is the
// table's natural order, so it only needs reversing for descending.
func (m *Model) applyRelocSort(rels []binfile.Reloc) {
	if m.relocSort == relocSortOffset {
		sort.SliceStable(m.relocFiltered, func(a, b int) bool {
			less := rels[m.relocFiltered[a]].Offset < rels[m.relocFiltered[b]].Offset
			if m.relocSortDesc {
				return !less
			}
			return less
		})
		return
	}
	key := func(r binfile.Reloc) string {
		switch m.relocSort {
		case relocSortType:
			return r.Type
		case relocSortSection:
			return r.Section
		default: // relocSortSym
			return r.Sym
		}
	}
	sort.SliceStable(m.relocFiltered, func(a, b int) bool {
		ra, rb := rels[m.relocFiltered[a]], rels[m.relocFiltered[b]]
		ka, kb := key(ra), key(rb)
		less := ka < kb
		if ka == kb { // tie-break by patched address so equal keys read in order
			less = ra.Offset < rb.Offset
		}
		if m.relocSortDesc {
			return !less
		}
		return less
	})
}

// updateRelocs handles keys while the Libraries view is in relocation mode.
// A focused filter input is captured centrally (captureActiveFilter), so by the
// time a key reaches here it is navigation or an action.
func (m *Model) updateRelocs(key string) (tea.Model, tea.Cmd) {
	m.recomputeRelocs()
	if navKey(&m.relocCur, len(m.relocFiltered), m.listPage(), key) {
		return m, nil
	}
	switch key {
	case "t":
		m.setStatus(m.cycleLibsMode(), false)
	case "s":
		m.relocSort = (m.relocSort + 1) % 4
		m.relocCur, m.relocTop = 0, 0
		m.recomputeRelocs()
		m.setStatus("sort: "+m.relocSort.String(), false)
	case "r":
		m.relocSortDesc = !m.relocSortDesc
		m.relocCur, m.relocTop = 0, 0
		m.recomputeRelocs()
		dir := "ascending"
		if m.relocSortDesc {
			dir = "descending"
		}
		m.setStatus("sort order: "+dir, false)
	case "alt+t":
		cycleStringList(&m.relocTypeOn, &m.relocType, m.relocTypes)
		m.relocCur, m.relocTop = 0, 0
		m.recomputeRelocs()
		if m.relocTypeOn {
			m.setStatus("reloc type filter: "+m.relocType, false)
		} else {
			m.setStatus("reloc type filter: all", false)
		}
	case "alt+s":
		cycleStringList(&m.relocSecOn, &m.relocSec, m.relocSecs)
		m.relocCur, m.relocTop = 0, 0
		m.recomputeRelocs()
		if m.relocSecOn {
			m.setStatus("reloc section filter: "+m.relocSec, false)
		} else {
			m.setStatus("reloc section filter: all", false)
		}
	case "/":
		m.libsFilter.Focus()
	case "esc":
		dirty := m.libsFilter.Value() != "" || m.libsFilter.Focused() || m.relocTypeOn || m.relocSecOn
		if dirty {
			m.libsFilter.SetValue("")
			m.libsFilter.Blur()
			m.relocTypeOn, m.relocSecOn = false, false
			m.relocCur, m.relocTop = 0, 0
			m.recomputeRelocs()
			m.setStatus("filters cleared", false)
			return m, nil
		}
		m.libsRelocs = false
		m.setStatus("showing libraries", false)
	case "w":
		m.toggleWrap()
	case "enter", "h":
		if r, ok := m.currentReloc(); ok && r.Offset != 0 {
			m.jumpHexAtAddr(r.Offset)
		}
	case "S":
		if r, ok := m.currentReloc(); ok && r.Sym != "" {
			m.copyToClipboard(r.Sym, "symbol")
		}
	case "A":
		if r, ok := m.currentReloc(); ok {
			m.copyToClipboard(fmt.Sprintf("0x%0*x", m.file.AddrHexWidth(), r.Offset), "address")
		}
	}
	return m, nil
}

// currentReloc returns the relocation under the cursor, through the filter.
func (m *Model) currentReloc() (binfile.Reloc, bool) {
	if m.relocCur < 0 || m.relocCur >= len(m.relocFiltered) {
		return binfile.Reloc{}, false
	}
	return m.file.Relocations()[m.relocFiltered[m.relocCur]], true
}

func (m *Model) renderRelocs() string {
	bodyH := m.bodyHeight()
	if bodyH < 3 {
		bodyH = 3
	}
	m.recomputeRelocs()
	rels := m.file.Relocations()
	addrW := m.file.AddrHexWidth()

	var filterRow string
	if m.libsFilter.Focused() {
		filterRow = m.libsFilter.View()
	} else {
		note := ""
		if len(rels) == 0 {
			note = "   " + relocsEmptyHint(m.file.Format)
		}
		tf, sf := "all", "all"
		if m.relocTypeOn {
			tf = m.relocType
		}
		if m.relocSecOn {
			sf = m.relocSec
		}
		filterRow = m.theme.footerStyle.Render(fmt.Sprintf(
			"/ %s   relocations (%d / %d)   s: sort:%s   t: libraries   %s type:%s   %s sec:%s%s",
			m.libsFilter.Value(), len(m.relocFiltered), len(rels), m.relocSort.String(),
			altKeys("t"), tf, altKeys("s"), sf, note))
	}
	desc := m.relocSortDesc
	header := m.tableHeader(fmt.Sprintf(" %-*s  %-24s %-12s %s",
		addrW+2, sortHeaderLabel("Offset", addrW+2, relocSortOffset, m.relocSort, desc),
		sortHeaderLabel("Type", 24, relocSortType, m.relocSort, desc),
		sortHeaderLabel("Section", 12, relocSortSection, m.relocSort, desc),
		sortHeaderLabel("Symbol / Addend", 16, relocSortSym, m.relocSort, desc)))

	visible := bodyH - 2
	if visible < 1 {
		visible = 1
	}
	top := m.visualTopForView(m.relocCur, m.relocTop, len(m.relocFiltered), visible, func(int) int { return 1 })
	m.relocTop = top
	m.pageRows = pageStep(top, len(m.relocFiltered), visible, func(int) int { return 1 })

	rows := []string{filterRow, header}
	for i := top; i < len(m.relocFiltered); i++ {
		line := m.relocRow(rels[m.relocFiltered[i]], addrW)
		if i == m.relocCur {
			line = m.theme.tableSelStyle.Render(ansi.Strip(line))
		}
		if !appendRenderedRowsIndented(&rows, line, m.width, m.wrap, 6, bodyH) {
			break
		}
	}
	return padBodyRows(rows, m.width, bodyH)
}

// relocRow renders one relocation row: offset (address colour), type, section,
// and the target symbol with any addend.
func (m *Model) relocRow(r binfile.Reloc, addrW int) string {
	target := r.Sym
	if r.HasAddend {
		add := fmt.Sprintf("0x%x", uint64(r.Addend))
		if target != "" {
			target += " + " + add
		} else {
			target = add
		}
	}
	typ := r.Type
	sec := r.Section
	if !m.wrap {
		typ = truncateMiddle(typ, 24)
		sec = truncateMiddle(sec, 12)
		target = truncateMiddle(target, max(8, m.width-addrW-2-24-12-8))
	}
	return fmt.Sprintf(" %s  %s %s %s",
		m.theme.addrStyle.Render(fmt.Sprintf("0x%0*x", addrW, r.Offset)),
		m.theme.tableRowStyle.Render(padVisual(typ, 24)),
		m.theme.srcShadowStyle.Render(padVisual(sec, 12)),
		m.theme.symbolNameStyle.Render(target))
}

// relocsEmptyHint explains an empty relocation table for the current format.
func relocsEmptyHint(f binfile.Format) string {
	switch f {
	case binfile.FormatMachO:
		return "none decoded (dyld chained fixups)"
	case binfile.FormatPE:
		return "no base-relocation directory"
	}
	return "none"
}
