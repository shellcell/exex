package ui

// This file owns the symbols view: a filterable table of the merged symbol
// table (matching on both raw and demangled names), plus openSymbol, which
// routes a chosen symbol to the most useful view.

import (
	"fmt"
	"sort"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/rabarbra/exex/internal/binfile"
)

// clickSymbolFacet toggles the facet button at screen column x on the status row,
// returning whether a button was hit.
func (m *Model) clickSymbolFacet(x int) bool {
	for _, f := range m.symbolFacets {
		if x >= f.start && x < f.end {
			m.toggleSymbolFacet(f.kind)
			return true
		}
	}
	return false
}

// toggleSymbolFacet advances the clicked toggle, mirroring its keyboard binding.
func (m *Model) toggleSymbolFacet(k facetKind) {
	m.symbolsCur, m.symbolsTop = 0, 0
	switch k {
	case facetType:
		m.cycleSymbolKindFilter()
	case facetScope:
		m.symbolsScope = (m.symbolsScope + 1) % 3
		m.setStatus("symbol scope: "+m.symbolsScope.String(), false)
	case facetSort:
		m.symbolsSort = (m.symbolsSort + 1) % 3
		m.setStatus("sort: "+m.symbolsSort.String(), false)
	case facetSortDir:
		m.symbolsSortDesc = !m.symbolsSortDesc
	case facetBind:
		m.cycleSymbolBindFilter()
	case facetTree:
		m.symbolsTree = !m.symbolsTree
	}
	m.recomputeSymbols()
}

// treeIndent is the per-depth indentation of a tree row.
const treeIndent = 2

// splitStyledRows splits wrapped output into lines, dropping a trailing newline
// and never returning an empty slice.
func splitStyledRows(wrapped string) []string {
	parts := strings.Split(strings.TrimRight(wrapped, "\n"), "\n")
	if len(parts) == 0 {
		return []string{""}
	}
	return parts
}

// symbolSort is the display order of the (filtered) symbol table.
type symbolSort uint8

const (
	sortByName symbolSort = iota // f.Symbols' own order (already name-sorted)
	sortByAddr
	sortBySize
)

// String returns the sort's filter-status label.
func (s symbolSort) String() string {
	switch s {
	case sortByAddr:
		return "address"
	case sortBySize:
		return "size"
	}
	return "name"
}

// symbolScope filters the symbol table by where a symbol comes from.
type symbolScope uint8

const (
	scopeAll      symbolScope = iota // every symbol
	scopeInternal                    // defined in this binary (own functions/data)
	scopeImported                    // bound to a shared library (PLT/GOT/stubs)
)

// String returns the scope's filter-status label.
func (sc symbolScope) String() string {
	switch sc {
	case scopeInternal:
		return "internal"
	case scopeImported:
		return "imported"
	}
	return "all"
}

// includes reports whether s passes the scope filter. Internal means defined
// here (a real address, not bound to a library); imported means bound to a
// shared library (the synthesised PLT/GOT/stub symbols).
func (sc symbolScope) includes(s binfile.Symbol) bool {
	switch sc {
	case scopeInternal:
		return s.Library == "" && s.Addr != 0
	case scopeImported:
		return s.Library != ""
	}
	return true
}

// recomputeSymbols rebuilds the filtered set and the flattened visible rows from
// the current filter, sort, and (in tree mode) collapse state.
func (m *Model) recomputeSymbols() {
	m.clearSymbolCaches()
	needle := strings.ToLower(m.symbolsFilter.Value())
	lowerName, lowerDem := m.file.LowerNames()
	m.symbolsFiltered = m.symbolsFiltered[:0]
	scan := func(i int) {
		s := m.file.Symbols[i]
		if m.symbolsKindOn && s.Kind != m.symbolsKind {
			return
		}
		if m.symbolsBindOn && s.Bind != m.symbolsBind {
			return
		}
		if !m.symbolsScope.includes(s) {
			return
		}
		if m.symbolsLib != "" && s.Library != m.symbolsLib {
			return
		}
		if needle == "" ||
			strings.Contains(lowerName[i], needle) ||
			(lowerDem[i] != "" && strings.Contains(lowerDem[i], needle)) {
			m.symbolsFiltered = append(m.symbolsFiltered, i)
		}
	}
	// Scan in display order for a name sort, and always in tree mode: the tree's
	// grouping relies on name adjacency, so the tree is built from name order even
	// when the (irrelevant in tree mode) flat-list sort is by address or size.
	if m.symbolsSort == sortByName || m.symbolsTree {
		m.ensureSymbolDisplayOrder()
		for _, i := range m.symbolsByDisplay {
			scan(i)
		}
	} else {
		for i := range m.file.Symbols {
			scan(i)
		}
	}
	m.applySymbolSort()
	m.buildSymbolRows()
	if m.symbolsCur >= len(m.symbolsRows) {
		m.symbolsCur = max(0, len(m.symbolsRows)-1)
	}
}

// applySymbolSort orders symbolsFiltered by the active field, ascending by
// default and reversed when symbolsSortDesc is set. Name order is already
// established (ascending) by scanning in display order (see recomputeSymbols), so
// it only needs reversing for descending.
func (m *Model) applySymbolSort() {
	if m.symbolsTree {
		return // tree mode is always built from (ascending) name order
	}
	desc := m.symbolsSortDesc
	switch m.symbolsSort {
	case sortByName:
		if desc {
			reverseInts(m.symbolsFiltered)
		}
	case sortByAddr:
		sort.SliceStable(m.symbolsFiltered, func(i, j int) bool {
			a, b := m.file.Symbols[m.symbolsFiltered[i]].Addr, m.file.Symbols[m.symbolsFiltered[j]].Addr
			if desc {
				return a > b
			}
			return a < b
		})
	case sortBySize:
		sort.SliceStable(m.symbolsFiltered, func(i, j int) bool {
			a, b := m.file.Symbols[m.symbolsFiltered[i]].Size, m.file.Symbols[m.symbolsFiltered[j]].Size
			if desc {
				return a > b
			}
			return a < b
		})
	}
}

// reverseInts reverses s in place.
func reverseInts(s []int) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

// ensureSymbolDisplayOrder builds (once) the symbol indices sorted by their shown
// name. Invalidated (set nil) when demangling finishes, since Display() changes.
func (m *Model) ensureSymbolDisplayOrder() {
	if m.symbolsByDisplay != nil {
		return
	}
	idx := make([]int, len(m.file.Symbols))
	for i := range idx {
		idx[i] = i
	}
	sort.Slice(idx, func(a, b int) bool {
		return m.file.Symbols[idx[a]].Display() < m.file.Symbols[idx[b]].Display()
	})
	m.symbolsByDisplay = idx
}

// buildSymbolRows rebuilds the visible row slice from symbolsFiltered: in tree mode
// it (re)builds the namespace tree and flattens it; otherwise one leaf row per
// symbol. The built tree is cached in symbolsRoots so a later collapse/expand only
// re-flattens (flattenSymbolRows) instead of rebuilding from scratch — important on
// large symbol tables (hundreds of thousands of names).
func (m *Model) buildSymbolRows() {
	if m.symbolsTree {
		label := func(i int) string { return m.file.Symbols[i].Display() }
		m.symbolsRoots = buildScopedTree(m.symbolsFiltered, label)
		if !m.symbolsTreeInit {
			m.symbolsTreeInit = true
			if m.treeCollapseDefault {
				m.symbolsCollapsed = map[string]bool{}
				eachInternal(m.symbolsRoots, func(p string) { m.symbolsCollapsed[p] = true })
			}
		}
		m.flattenSymbolRows()
		return
	}
	m.symbolsRoots = nil
	nodes := make([]treeNode, len(m.symbolsFiltered))
	rows := m.symbolsRows[:0]
	for k, idx := range m.symbolsFiltered {
		nodes[k] = treeNode{label: m.file.Symbols[idx].Display(), leaf: idx, count: 1}
		rows = append(rows, treeRow{node: &nodes[k], depth: 0})
	}
	m.symbolsRows = rows
}

// flattenSymbolRows re-projects the cached tree (symbolsRoots) into visible rows
// using the current collapse state — the cheap path taken on every collapse/expand.
func (m *Model) flattenSymbolRows() {
	collapsed := m.symbolsCollapsed
	if m.symbolsFilter.Value() != "" {
		collapsed = nil // while filtering, keep every match visible
	}
	m.symbolsRows = flattenTree(m.symbolsRoots, collapsed, 0, m.symbolsRows[:0])
}

// symbolTreeActive reports whether the tree is currently shown. The tree is
// always built from name order, so it works under any flat-list sort field.
func (m *Model) symbolTreeActive() bool {
	return m.symbolsTree
}

// toggleSymbolNode collapses/expands the internal node at the current row.
func (m *Model) toggleSymbolNode() {
	if m.symbolsCur < 0 || m.symbolsCur >= len(m.symbolsRows) {
		return
	}
	n := m.symbolsRows[m.symbolsCur].node
	if n.leaf >= 0 {
		return
	}
	if m.symbolsCollapsed == nil {
		m.symbolsCollapsed = map[string]bool{}
	}
	m.symbolsCollapsed[n.path] = !m.symbolsCollapsed[n.path]
	m.rebuildSymbolRows()
}

func (m *Model) isSymbolCollapsed(path string) bool {
	return m.symbolsCollapsed != nil && m.symbolsCollapsed[path]
}

// setAllSymbolsCollapsed collapses or expands every internal node.
func (m *Model) setAllSymbolsCollapsed(collapsed bool) {
	if !m.symbolTreeActive() {
		return
	}
	if !collapsed {
		m.symbolsCollapsed = nil
	} else {
		m.symbolsCollapsed = map[string]bool{}
		eachInternal(m.symbolsRoots, func(p string) { m.symbolsCollapsed[p] = true })
	}
	m.rebuildSymbolRows()
}

func (m *Model) clampSymbolCursor() {
	if m.symbolsCur >= len(m.symbolsRows) {
		m.symbolsCur = max(0, len(m.symbolsRows)-1)
	}
	if m.symbolsCur < 0 {
		m.symbolsCur = 0
	}
}

func (m *Model) updateSymbols(key string) (tea.Model, tea.Cmd) {
	if navKey(&m.symbolsCur, len(m.symbolsRows), m.listPage(), key) {
		return m, nil
	}
	switch key {
	case "/":
		m.symbolsFilter.Focus()
		return m, nil
	case "esc":
		if m.symbolsLib != "" {
			m.symbolsLib = ""
			m.symbolsCur, m.symbolsTop = 0, 0
			m.recomputeSymbols()
			m.setStatus("library filter cleared", false)
		}
		return m, nil
	case "y":
		m.cycleSymbolKindFilter()
		m.symbolsCur, m.symbolsTop = 0, 0
		m.recomputeSymbols()
		return m, nil
	case "i":
		m.symbolsScope = (m.symbolsScope + 1) % 3
		m.symbolsCur, m.symbolsTop = 0, 0
		m.recomputeSymbols()
		m.setStatus("symbol scope: "+m.symbolsScope.String(), false)
		return m, nil
	case "b":
		m.cycleSymbolBindFilter()
		m.symbolsCur, m.symbolsTop = 0, 0
		m.recomputeSymbols()
		return m, nil
	case "o":
		m.symbolsSort = (m.symbolsSort + 1) % 3
		m.symbolsCur, m.symbolsTop = 0, 0
		m.recomputeSymbols()
		m.setStatus("sort: "+m.symbolsSort.String(), false)
		return m, nil
	case "r":
		m.symbolsSortDesc = !m.symbolsSortDesc
		m.symbolsCur, m.symbolsTop = 0, 0
		m.recomputeSymbols()
		dir := "ascending"
		if m.symbolsSortDesc {
			dir = "descending"
		}
		m.setStatus("sort order: "+dir, false)
		return m, nil
	case "t", "f":
		m.symbolsTree = !m.symbolsTree
		m.symbolsCur, m.symbolsTop = 0, 0
		m.recomputeSymbols()
		view := "flat table"
		if m.symbolsTree {
			view = "tree"
		}
		m.setStatus("symbols view: "+view, false)
		return m, nil
	case "-", "_":
		m.setAllSymbolsCollapsed(true)
		m.setStatus("collapsed all", false)
		return m, nil
	case "+", "=":
		m.setAllSymbolsCollapsed(false)
		m.setStatus("expanded all", false)
		return m, nil
	case "right", "l":
		if m.symbolTreeActive() {
			m.ensureSymbolsCollapsed()
			if treeExpandOne(m.symbolsRows, &m.symbolsCur, m.symbolsCollapsed) {
				m.rebuildSymbolRows()
			}
		}
		return m, nil
	case "left", "h":
		if m.symbolTreeActive() {
			m.ensureSymbolsCollapsed()
			if treeCollapseOne(m.symbolsRows, &m.symbolsCur, m.symbolsCollapsed) {
				m.rebuildSymbolRows()
			}
		}
		return m, nil
	case "w":
		m.toggleWrap()
		return m, nil
	case "enter", " ":
		m.activateSymbolRow()
	case "a":
		if sym, ok := m.currentSymbol(); ok {
			m.copyToClipboard(fmt.Sprintf("0x%0*x", m.file.AddrHexWidth(), sym.Addr), "address")
		}
	case "s":
		if sym, ok := m.currentSymbol(); ok {
			m.copyToClipboard(sym.Name, "symbol")
		}
	}
	return m, nil
}

// activateSymbolRow opens a leaf symbol, or expands/collapses the whole subtree
// under a group node (Enter switches "expand all below" ↔ "collapse all below").
func (m *Model) activateSymbolRow() {
	if m.symbolsCur < 0 || m.symbolsCur >= len(m.symbolsRows) {
		return
	}
	n := m.symbolsRows[m.symbolsCur].node
	if n.leaf < 0 {
		m.ensureSymbolsCollapsed()
		if treeToggleSubtree(m.symbolsRows, m.symbolsCur, m.symbolsCollapsed) {
			m.rebuildSymbolRows()
		}
		return
	}
	sym := m.file.Symbols[n.leaf]
	if sym.Addr == 0 {
		m.setStatus(fmt.Sprintf("symbol %s has no address", sym.Name), true)
		return
	}
	m.openSymbol(sym)
}

func (m *Model) ensureSymbolsCollapsed() {
	if m.symbolsCollapsed == nil {
		m.symbolsCollapsed = map[string]bool{}
	}
}

// rebuildSymbolRows re-projects the cached tree after a collapse-state change. It
// does not rebuild the tree itself (use recomputeSymbols/buildSymbolRows for that),
// so an arrow-key fold on a huge table is instant.
func (m *Model) rebuildSymbolRows() {
	m.clearSymbolCaches()
	m.flattenSymbolRows()
	m.clampSymbolCursor()
}

// currentSymbol returns the symbol under the cursor when the row is a leaf.
func (m *Model) currentSymbol() (binfile.Symbol, bool) {
	if m.symbolsCur < 0 || m.symbolsCur >= len(m.symbolsRows) {
		return binfile.Symbol{}, false
	}
	n := m.symbolsRows[m.symbolsCur].node
	if n.leaf < 0 {
		return binfile.Symbol{}, false
	}
	return m.file.Symbols[n.leaf], true
}

func (m *Model) cycleSymbolKindFilter() {
	order := []binfile.SymKind{binfile.SymFunc, binfile.SymObject, binfile.SymSection, binfile.SymFile, binfile.SymTLS, binfile.SymCommon, binfile.SymOther}
	if !m.symbolsKindOn {
		m.symbolsKindOn = true
		m.symbolsKind = order[0]
		m.setStatus("symbol type filter: "+kindString(m.symbolsKind), false)
		return
	}
	for i, k := range order {
		if k == m.symbolsKind {
			if i == len(order)-1 {
				m.symbolsKindOn = false
				m.setStatus("symbol type filter: all", false)
				return
			}
			m.symbolsKind = order[i+1]
			m.setStatus("symbol type filter: "+kindString(m.symbolsKind), false)
			return
		}
	}
	m.symbolsKindOn = false
}

// cycleSymbolBindFilter steps the bind filter off → global → weak → local → off
// (global is the usual "exported symbols" lens when combined with scope:internal).
func (m *Model) cycleSymbolBindFilter() {
	order := []binfile.SymBind{binfile.BindGlobal, binfile.BindWeak, binfile.BindLocal}
	if !m.symbolsBindOn {
		m.symbolsBindOn = true
		m.symbolsBind = order[0]
		m.setStatus("symbol bind filter: "+bindString(m.symbolsBind), false)
		return
	}
	for i, b := range order {
		if b == m.symbolsBind {
			if i == len(order)-1 {
				m.symbolsBindOn = false
				m.setStatus("symbol bind filter: all", false)
				return
			}
			m.symbolsBind = order[i+1]
			m.setStatus("symbol bind filter: "+bindString(m.symbolsBind), false)
			return
		}
	}
	m.symbolsBindOn = false
}

// canDisasmAt reports whether addr can actually be disassembled: there is a
// decoder for this architecture and the address lives in executable code. When
// false (an unsupported CPU, or an address outside any mapped exec section),
// callers should fall back to the hex view rather than the disasm view.
func (m *Model) canDisasmAt(addr uint64) bool {
	if m.dis == nil {
		return false
	}
	_, ok := m.file.ExecImage().PosForAddr(addr)
	return ok
}

// openSymbol opens a symbol in the most appropriate view. The hex and disasm
// views span the whole binary now, so this only chooses which view to land in
// and seeks the cursor onto the symbol's address:
//   - FUNC                  → disasm
//   - OBJECT/TLS/COMMON     → hex (virtual-address) view, cursor on the symbol
//   - SECTION               → exec ⇒ disasm; else hex/raw at the section
//   - NOTYPE                → exec section ⇒ disasm; else hex; else raw
//
// Anything that would land in disasm falls back to hex when disassembly isn't
// possible (no decoder for this CPU, or the address isn't in executable code).
func (m *Model) openSymbol(sym binfile.Symbol) {
	wantDisasm := false
	switch sym.Kind {
	case binfile.SymFunc:
		wantDisasm = true
	case binfile.SymObject, binfile.SymTLS, binfile.SymCommon:
		wantDisasm = false
	default:
		if sec := m.file.SectionAt(sym.Addr); sec != nil && binfile.IsExecSection(sec) {
			wantDisasm = true
		}
	}
	if wantDisasm && m.canDisasmAt(sym.Addr) {
		m.loadDisasmAt(sym.Addr)
	} else {
		m.openHexAt(sym.Addr)
	}
}

func (m *Model) renderSymbols() string {
	bodyH := m.bodyHeight()
	if bodyH < 3 {
		bodyH = 3
	}

	filterRow := m.symbolsFilter.View()
	m.symbolFacets = m.symbolFacets[:0]
	if !m.symbolsFilter.Focused() {
		kind := "all"
		if m.symbolsKindOn {
			kind = kindString(m.symbolsKind)
		}
		var b strings.Builder
		col := 0
		plain := func(s string) { b.WriteString(m.theme.footerStyle.Render(s)); col += lipgloss.Width(s) }
		// Each chip is a clickable toggle: the bound key in the accent colour (like
		// the footer hints) followed by the current value.
		button := func(key, label string, k facetKind) {
			start := col
			b.WriteString(m.theme.helpKeyStyle.Render(key))
			b.WriteString(m.theme.footerStyle.Render(" " + label))
			col += lipgloss.Width(key + " " + label)
			m.symbolFacets = append(m.symbolFacets, facetHit{start, col, k})
			plain("   ")
		}
		bind := "all"
		if m.symbolsBindOn {
			bind = bindString(m.symbolsBind)
		}
		treeLabel := "view:flat"
		if m.symbolTreeActive() {
			treeLabel = "view:tree"
		}
		plain("/ " + m.symbolsFilter.Value() + "   ")
		button("y", "type:"+kind, facetType)
		button("i", "scope:"+m.symbolsScope.String(), facetScope)
		button("b", "bind:"+bind, facetBind)
		button("o", "sort:"+m.symbolsSort.String(), facetSort)
		dir := "↑asc"
		if m.symbolsSortDesc {
			dir = "↓desc"
		}
		button("r", dir, facetSortDir)
		button("t", treeLabel, facetTree)
		if m.symbolsLib != "" {
			plain("lib:" + m.symbolsLib + " (Esc clears)   ")
		}
		plain(fmt.Sprintf("(%d / %d)", len(m.symbolsFiltered), len(m.file.Symbols)))
		filterRow = b.String()
	}

	addrW := m.file.AddrHexWidth()
	var header string
	if m.symbolTreeActive() {
		header = m.theme.footerStyle.Render(" tree · ←/→ fold · ↵ all below · +/− expand/collapse all · t flat")
	} else {
		addrCol := 2 + addrW
		header = m.tableHeader(fmt.Sprintf(" %-*s %9s %6s %7s  %s", addrCol, "Address", "Size", "Bind", "Type", "Name"))
	}

	visible := bodyH - 2 // filter row + header
	if visible < 1 {
		visible = 1
	}
	rowHeight := func(i int) int { return m.symbolRowHeight(i) }
	top := m.visualTopForView(m.symbolsCur, m.symbolsTop, len(m.symbolsRows), visible, rowHeight)
	m.symbolsTop = top
	m.renderedSymbolsTop = top
	m.pageRows = pageStep(top, len(m.symbolsRows), visible, rowHeight)

	rows := []string{filterRow, header}
	for i := top; i < len(m.symbolsRows); i++ {
		node := m.symbolsRows[i].node
		for _, row := range m.symbolRows(i, addrW) {
			if len(rows) >= bodyH {
				break
			}
			if i == m.symbolsCur {
				if node.leaf < 0 {
					// Group node: highlight the arrow only (no full-width white bar).
					row = m.treeNodeRow(m.symbolsRows[i].depth, node.label, node.count, m.isSymbolCollapsed(node.path), true, "", m.width)
				} else {
					row = m.theme.tableSelStyle.Render(ansi.Strip(row))
				}
			}
			rows = append(rows, row)
		}
		if len(rows) >= bodyH {
			break
		}
	}
	return padBodyRows(rows, m.width, bodyH)
}

func (m *Model) symbolRowHeight(i int) int {
	if i < 0 || i >= len(m.symbolsRows) {
		return 1
	}
	key := rowCacheKey{i, m.width, m.file.AddrHexWidth(), m.wrap}
	if m.symbolHeightCache != nil {
		if h, ok := m.symbolHeightCache[key]; ok {
			return h
		}
	}
	h := len(m.symbolRows(i, m.file.AddrHexWidth()))
	if m.symbolHeightCache == nil {
		m.symbolHeightCache = make(map[rowCacheKey]int)
	}
	m.symbolHeightCache[key] = h
	return h
}

// symbolRows renders one visible row — an internal tree node (arrow + underlined
// label + collapsed count) or a leaf symbol (address columns + indented name).
func (m *Model) symbolRows(i, addrW int) []string {
	key := rowCacheKey{i, m.width, addrW, m.wrap}
	if m.symbolRowCache != nil {
		if rows, ok := m.symbolRowCache[key]; ok {
			return rows
		}
	}
	const sep = " \t/.-_:$@<>"
	row := m.symbolsRows[i]
	n := row.node
	indentW := row.depth * treeIndent
	indent := strings.Repeat(" ", indentW)

	var rows []string
	if n.leaf < 0 {
		// Internal (group) node: arrow + highlighted, underlined segment.
		rows = []string{m.treeNodeRow(row.depth, n.label, n.count, m.isSymbolCollapsed(n.path), false, "", m.width)}
	} else {
		s := m.file.Symbols[n.leaf]
		rowStyle := m.theme.styleForSymbol(s.Kind, s.Bind)
		colsPlain := fmt.Sprintf("0x%0*x %9d %6s %7s  ", addrW, s.Addr, s.Size, bindString(s.Bind), kindString(s.Kind))
		cols := m.theme.addrStyle.Render(fmt.Sprintf("0x%0*x", addrW, s.Addr)) +
			rowStyle.Render(fmt.Sprintf(" %9d %6s %7s  ", s.Size, bindString(s.Bind), kindString(s.Kind)))
		nameW := m.width - indentW - len(colsPlain)
		if nameW < 1 {
			nameW = 1
		}
		var parts []string
		if m.wrap {
			parts = splitStyledRows(ansi.Wrap(n.label, nameW, sep))
			for k := range parts {
				parts[k] = rowStyle.Render(parts[k])
			}
		} else {
			parts = []string{rowStyle.Render(truncateMiddle(n.label, nameW))}
		}
		rows = make([]string, 0, len(parts))
		for j, part := range parts {
			if j == 0 {
				rows = append(rows, indent+cols+part)
			} else {
				rows = append(rows, strings.Repeat(" ", indentW+len(colsPlain))+part)
			}
		}
	}

	if m.symbolRowCache == nil {
		m.symbolRowCache = make(map[rowCacheKey][]string)
	}
	m.symbolRowCache[key] = rows
	return rows
}
