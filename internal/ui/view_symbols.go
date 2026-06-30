package ui

// This file owns the symbols view: a filterable table of the merged symbol
// table (matching on both raw and demangled names), plus openSymbol, which
// routes a chosen symbol to the most useful view.

import (
	"fmt"
	"sort"
	"strconv"
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
	if k == facetAbbrev {
		// Abbreviation is a pure render change: keep the cursor and skip the rebuild.
		m.toggleSymbolAbbrevAll()
		return
	}
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

// abbrevMinInner is the smallest "(…)"/"<…>" content (in bytes, brackets excluded)
// worth collapsing: only content longer than 5 bytes is replaced with "...". Short
// inner text (e.g. "<int>", "<A>", "<int16>", "(d)") is kept verbatim — it's
// readable as-is and "<...>" would barely shorten it.
const abbrevMinInner = 6

// abbrevBrackets replaces the contents of every top-level "(…)" and "<…>" group in
// s whose inner text is at least abbrevMinInner bytes with "..." — "f<Alloc, Traits>"
// becomes "f<...>" while "Foo<A>" and "find(x)" are left as-is. "[…]" is untouched.
// C++ "operator" names (operator<<, operator->, operator(), …) are passed through
// whole so their punctuation isn't mistaken for template/parameter brackets. If the
// "()"/"<>" nesting doesn't balance, s is returned unchanged so a pathological name
// is never truncated.
func abbrevBrackets(s string) string {
	if !bracketsBalanced(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if ol := operatorTokenLen(s, i); ol > 0 {
			b.WriteString(s[i : i+ol])
			i += ol
			continue
		}
		// The outer loop only ever runs at bracket depth 0 (groups are jumped over
		// whole), so any "("/"<" here opens a top-level group and any ">" is a "->"
		// arrow, never a close.
		if c := s[i]; c == '(' || c == '<' {
			j := matchClose(s, i)
			if j < 0 { // unreachable after bracketsBalanced; stay safe
				b.WriteByte(c)
				i++
				continue
			}
			if j-i-1 < abbrevMinInner {
				b.WriteString(s[i : j+1]) // short content: keep verbatim
			} else {
				b.WriteByte(c)
				b.WriteString("...")
				b.WriteByte(s[j])
			}
			i = j + 1
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// matchClose returns the index of the bracket that closes the "("/"<" at open,
// honouring nested groups, "operator" tokens and "->" arrows, or -1 if unbalanced.
func matchClose(s string, open int) int {
	depth := 0
	for k := open; k < len(s); {
		if ol := operatorTokenLen(s, k); ol > 0 {
			k += ol
			continue
		}
		switch s[k] {
		case '(', '<':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return k
			}
		case '>':
			if k > 0 && s[k-1] == '-' { // "->" arrow, not a close
				break
			}
			depth--
			if depth == 0 {
				return k
			}
		}
		k++
	}
	return -1
}

// bracketsBalanced reports whether s has at least one "("/"<" group and its
// "()"/"<>" nesting balances under a single depth counter, skipping "operator"
// punctuation. "[]" is ignored.
func bracketsBalanced(s string) bool {
	depth, seen := 0, false
	for i := 0; i < len(s); {
		if ol := operatorTokenLen(s, i); ol > 0 {
			i += ol
			continue
		}
		switch s[i] {
		case '(', '<':
			depth++
			seen = true
		case '>':
			if i > 0 && s[i-1] == '-' { // "->" arrow, not a close
				break
			}
			depth--
			if depth < 0 {
				return false
			}
		case ')':
			depth--
			if depth < 0 {
				return false
			}
		}
		i++
	}
	return depth == 0 && seen
}

// operatorTokenLen returns the byte length of a C++ "operator…" name starting at
// s[i] — the word "operator" plus its symbol form ("operator<<", "operator()",
// "operator->", "operator<=>") — or 0 when s[i] does not begin such a token. The
// operator's punctuation must be consumed wholesale so its "<"/">"/"(" are not read
// as template or parameter brackets. "operator" spelt out as part of a longer
// identifier, or followed by a word (conversion / new / delete), returns 0.
func operatorTokenLen(s string, i int) int {
	const kw = "operator"
	if i > 0 && isIdentByte(s[i-1]) {
		return 0
	}
	if !strings.HasPrefix(s[i:], kw) {
		return 0
	}
	j := i + len(kw)
	if j < len(s) && s[j] == ' ' { // tolerate "operator <"
		j++
	}
	// operator() and operator[] (and their array-new/delete cousins are handled by
	// the punctuation run below since "[]" isn't tracked anyway).
	if j+1 < len(s) && (s[j] == '(' && s[j+1] == ')' || s[j] == '[' && s[j+1] == ']') {
		return j + 2 - i
	}
	k := j
	for k < len(s) && isOpPunct(s[k]) {
		k++
	}
	if k == j {
		return 0 // "operator" + a name (conversion op, new, delete): nothing to skip
	}
	return k - i
}

// isOpPunct reports whether c is punctuation that can form an overloaded operator's
// name (excluding "()"/"[]", handled separately).
func isOpPunct(c byte) bool {
	switch c {
	case '<', '>', '=', '!', '+', '-', '*', '/', '%', '^', '&', '|', '~', ',':
		return true
	}
	return false
}

// isIdentByte reports whether c can appear inside a C identifier.
func isIdentByte(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// abbrevKey is the stable per-row key for a node's individual abbreviation
// override: the symbol index for a leaf, the (unique) path for a group node.
func abbrevKey(n *treeNode) string {
	if n.leaf >= 0 {
		return "s" + strconv.Itoa(n.leaf)
	}
	return "g" + n.path
}

// symbolAbbrevActive reports whether n's brackets should be abbreviated, combining
// the global setting with any per-row override (the override inverts the global).
func (m *Model) symbolAbbrevActive(n *treeNode) bool {
	on := m.symbolsAbbrev
	if m.symbolsAbbrevExcept[abbrevKey(n)] {
		on = !on
	}
	return on
}

// symbolLabel returns n's display label with bracket abbreviation applied when it
// is in effect for that row.
func (m *Model) symbolLabel(n *treeNode) string {
	if m.symbolAbbrevActive(n) {
		return abbrevBrackets(n.label)
	}
	return n.label
}

// displaySymbolName returns a symbol's display name with bracketed argument and
// template lists abbreviated (see abbrevBrackets) when the global Symbols-view
// "args" collapse is on, so a symbol reads the same in the disasm, hex/raw and
// pointer-follow annotations as it does in the Symbols list. The Symbols view's
// per-row overrides are list-specific and intentionally don't apply here.
func (m *Model) displaySymbolName(s binfile.Symbol) string {
	if m.symbolsAbbrev {
		return abbrevBrackets(s.Display())
	}
	return s.Display()
}

// toggleSymbolAbbrev flips bracket abbreviation for just the row under the cursor.
func (m *Model) toggleSymbolAbbrev() {
	if m.symbolsCur < 0 || m.symbolsCur >= len(m.symbolsRows) {
		return
	}
	n := m.symbolsRows[m.symbolsCur].node
	if m.symbolsAbbrevExcept == nil {
		m.symbolsAbbrevExcept = map[string]bool{}
	}
	k := abbrevKey(n)
	m.symbolsAbbrevExcept[k] = !m.symbolsAbbrevExcept[k]
	m.clearSymbolCaches()
	if m.symbolAbbrevActive(n) {
		m.setStatus("arguments collapsed (this row)", false)
	} else {
		m.setStatus("arguments expanded (this row)", false)
	}
}

// toggleSymbolAbbrevAll flips bracket abbreviation globally, clearing any per-row
// overrides so every row returns to the uniform state.
func (m *Model) toggleSymbolAbbrevAll() {
	m.symbolsAbbrev = !m.symbolsAbbrev
	m.symbolsAbbrevExcept = nil
	m.clearSymbolCaches()
	m.clearSymbolNameCaches() // the toggle also moves disasm/hex/source annotations
	if m.symbolsAbbrev {
		m.setStatus("arguments collapsed (all)", false)
	} else {
		m.setStatus("arguments expanded (all)", false)
	}
}

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
	m.symbolsReady = true
	m.clearSymbolCaches()
	needle := strings.ToLower(m.symbolsFilter.Value())
	// Entering a search auto-expands the tree so matches aren't hidden under
	// previously-collapsed groups; the pre-filter collapse state is saved and
	// restored when the search clears. In between, collapse/expand work normally on
	// the filtered tree (flattenSymbolRows honours symbolsCollapsed either way).
	if filtering := needle != ""; filtering != m.symbolsFiltering {
		if filtering {
			m.symbolsCollapsedAlt = m.symbolsCollapsed
			m.symbolsCollapsed = nil
		} else {
			m.symbolsCollapsed = m.symbolsCollapsedAlt
			m.symbolsCollapsedAlt = nil
		}
		m.symbolsFiltering = filtering
	}
	var lowerName, lowerDem []string
	if needle != "" {
		lowerName, lowerDem = m.file.LowerNames()
	}
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
		if needle == "" || strings.Contains(lowerName[i], needle) ||
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

func (m *Model) ensureSymbols() {
	if !m.symbolsReady {
		m.recomputeSymbols()
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
	// Always honour the collapse state — including while a search filter is active
	// (recomputeSymbols auto-expands on entering the filter so matches show, then
	// the user's collapse/expand take effect here).
	m.symbolsRows = flattenTree(m.symbolsRoots, m.symbolsCollapsed, 0, m.symbolsRows[:0])
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
		dirty := m.symbolsLib != "" || m.symbolsKindOn || m.symbolsBindOn ||
			m.symbolsScope != scopeAll || m.symbolsFilter.Value() != "" || m.symbolsFilter.Focused()
		m.symbolsFilter.SetValue("")
		m.symbolsFilter.Blur()
		m.symbolsLib = ""
		m.symbolsKindOn = false
		m.symbolsBindOn = false
		m.symbolsScope = scopeAll
		m.symbolsCur, m.symbolsTop = 0, 0
		m.recomputeSymbols()
		if dirty {
			m.setStatus("filters cleared", false)
		}
		return m, nil
	case "ctrl+t":
		m.cycleSymbolKindFilter()
		m.symbolsCur, m.symbolsTop = 0, 0
		m.recomputeSymbols()
		return m, nil
	case "ctrl+s":
		m.symbolsScope = (m.symbolsScope + 1) % 3
		m.symbolsCur, m.symbolsTop = 0, 0
		m.recomputeSymbols()
		m.setStatus("symbol scope: "+m.symbolsScope.String(), false)
		return m, nil
	case "ctrl+b":
		m.cycleSymbolBindFilter()
		m.symbolsCur, m.symbolsTop = 0, 0
		m.recomputeSymbols()
		return m, nil
	case "s":
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
	case "t":
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
	case "right":
		if m.symbolTreeActive() {
			m.ensureSymbolsCollapsed()
			if treeExpandOne(m.symbolsRows, &m.symbolsCur, m.symbolsCollapsed) {
				m.rebuildSymbolRows()
			}
		}
		return m, nil
	case "left":
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
	case "e":
		m.toggleSymbolAbbrevAll()
		return m, nil
	case ".":
		m.toggleSymbolAbbrev()
		return m, nil
	case "enter", " ":
		m.activateSymbolRow()
	case "d":
		if sym, ok := m.currentSymbol(); ok {
			m.jumpDisasmAtAddr(sym.Addr)
		}
	case "h":
		if sym, ok := m.currentSymbol(); ok {
			m.jumpHexAtAddr(sym.Addr)
		}
	case "m":
		if sym, ok := m.currentSymbol(); ok {
			m.jumpRawAtAddr(sym.Addr)
		}
	case "A":
		if sym, ok := m.currentSymbol(); ok {
			m.copyToClipboard(fmt.Sprintf("0x%0*x", m.file.AddrHexWidth(), sym.Addr), "address")
		}
	case "S":
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
	m.ensureSymbols()
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
		// footerStyle adds left/right padding, so count the *rendered* width — not
		// the raw string — or the clickable facet ranges drift right of the chips.
		plain := func(s string) {
			r := m.theme.footerStyle.Render(s)
			b.WriteString(r)
			col += lipgloss.Width(r)
		}
		// Each chip is a clickable toggle: the bound key in the accent colour (like
		// the footer hints) followed by the current value.
		button := func(key, label string, k facetKind) {
			start := col
			kr := m.theme.helpKeyStyle.Render(key)
			lr := m.theme.footerStyle.Render(" " + label)
			b.WriteString(kr)
			b.WriteString(lr)
			col += lipgloss.Width(kr) + lipgloss.Width(lr)
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
		button(ctrlKeys("t"), "type:"+kind, facetType)
		button(ctrlKeys("s"), "scope:"+m.symbolsScope.String(), facetScope)
		button(ctrlKeys("b"), "bind:"+bind, facetBind)
		button("s", "sort:"+m.symbolsSort.String(), facetSort)
		dir := "↑asc"
		if m.symbolsSortDesc {
			dir = "↓desc"
		}
		button("r", dir, facetSortDir)
		button("t", treeLabel, facetTree)
		argsLabel := "args:full"
		if m.symbolsAbbrev {
			argsLabel = "args:…"
		}
		button("e", argsLabel, facetAbbrev)
		if m.symbolsLib != "" {
			plain("lib:" + m.symbolsLib + " (Esc clears)   ")
		}
		plain(fmt.Sprintf("(%d / %d)", len(m.symbolsFiltered), len(m.file.Symbols)))
		filterRow = b.String()
	}

	addrW := m.file.AddrHexWidth()
	var header string
	if m.symbolTreeActive() {
		header = m.theme.footerStyle.Render(" tree · ←/→ fold · ↵ all below · +/− expand/collapse all · . args · t flat")
	} else {
		addrCol := 2 + addrW
		addrLabel := sortHeaderLabel("Address", addrCol, sortByAddr, m.symbolsSort, m.symbolsSortDesc)
		sizeLabel := sortHeaderLabel("Size", 9, sortBySize, m.symbolsSort, m.symbolsSortDesc)
		nameLabel := trailingSortHeaderLabel("Name", sortByName, m.symbolsSort, m.symbolsSortDesc)
		header = m.tableHeader(fmt.Sprintf(" %-*s %9s %6s %7s  %s", addrCol, addrLabel, sizeLabel, "Bind", "Type", nameLabel))
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

	if len(m.symbolsRows) == 0 {
		msg := "no symbols in this binary"
		if m.symbolsFilter.Value() != "" || m.symbolsKindOn || m.symbolsBindOn ||
			m.symbolsScope != scopeAll || m.symbolsLib != "" {
			msg = "no matching symbols  ·  Esc clears filters"
		}
		return m.emptyList(msg, filterRow, header)
	}
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
					row = m.treeNodeRow(m.symbolsRows[i].depth, m.symbolLabel(node), node.count, m.isSymbolCollapsed(node.path), true, "", m.width)
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
	return m.symbolHeightCache.get(rowCacheKey{i, m.width, m.file.AddrHexWidth(), m.wrap}, func() int {
		return len(m.symbolRows(i, m.file.AddrHexWidth()))
	})
}

// symbolRows renders one visible row — an internal tree node (arrow + underlined
// label + collapsed count) or a leaf symbol (address columns + indented name).
func (m *Model) symbolRows(i, addrW int) []string {
	return m.symbolRowCache.get(rowCacheKey{i, m.width, addrW, m.wrap}, func() []string {
		return m.symbolRowsText(i, addrW)
	})
}

func (m *Model) symbolRowsText(i, addrW int) []string {
	const sep = " \t/.-_:$@<>"
	row := m.symbolsRows[i]
	n := row.node
	indentW := row.depth * treeIndent
	indent := strings.Repeat(" ", indentW)

	label := m.symbolLabel(n)
	var rows []string
	if n.leaf < 0 {
		// Internal (group) node: arrow + highlighted, underlined segment.
		rows = []string{m.treeNodeRow(row.depth, label, n.count, m.isSymbolCollapsed(n.path), false, "", m.width)}
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
			parts = splitStyledRows(ansi.Wrap(label, nameW, sep))
			for k := range parts {
				parts[k] = rowStyle.Render(parts[k])
			}
		} else {
			parts = []string{rowStyle.Render(truncateMiddle(label, nameW))}
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

	return rows
}
