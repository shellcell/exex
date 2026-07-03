package symbols

import (
	"fmt"
	"sort"
	"strings"

	"charm.land/bubbles/v2/textinput"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/ui/layout"
	"github.com/rabarbra/exex/internal/ui/view"
)

// SortField is the display order of the (filtered) symbol table.
type SortField uint8

const (
	SortName SortField = iota // file.Symbols' own order (already name-sorted)
	SortAddr
	SortSize
)

// String returns the sort's filter-status label.
func (s SortField) String() string {
	switch s {
	case SortAddr:
		return "address"
	case SortSize:
		return "size"
	}
	return "name"
}

// Scope filters the symbol table by where a symbol comes from.
type Scope uint8

const (
	ScopeAll      Scope = iota // every symbol
	ScopeInternal              // defined in this binary (own functions/data)
	ScopeImported              // bound to a shared library (PLT/GOT/stubs)
)

// String returns the scope's filter-status label.
func (sc Scope) String() string {
	switch sc {
	case ScopeInternal:
		return "internal"
	case ScopeImported:
		return "imported"
	}
	return "all"
}

// includes reports whether s passes the scope filter. Internal means defined
// here (a real address, not bound to a library); imported means bound to a
// shared library (the synthesised PLT/GOT/stub symbols).
func (sc Scope) includes(s binfile.Symbol) bool {
	switch sc {
	case ScopeInternal:
		return s.Library == "" && s.Addr != 0
	case ScopeImported:
		return s.Library != ""
	}
	return true
}

// FacetKind identifies a clickable toggle button on the symbols status line.
type FacetKind int

const (
	FacetType FacetKind = iota
	FacetScope
	FacetSort
	FacetSortDir
	FacetBind
	FacetTree
	FacetAbbrev
)

// FacetHit is the screen-column span [Start,End) of one clickable toggle button.
type FacetHit struct {
	Start, End int
	Kind       FacetKind
}

// State stores list/filter/tree state for the Symbols view.
type State struct {
	Filter      textinput.Model
	Filtered    []int // indices into file.Symbols (sorted by name)
	Cur         int
	Top         int
	RenderedTop int // Top as of the last render, for mouse hit-testing
	Kind        binfile.SymKind
	KindOn      bool
	Bind        binfile.SymBind
	BindOn      bool
	Scope       Scope     // all / internal (defined here) / imported (from libs)
	Sort        SortField // view order: name / address / size
	SortDesc    bool      // reverse the active sort (descending)
	Lib         string    // when set, show only imports bound to this library
	Tree        bool      // group names into a collapsible namespace tree (name sort)
	Abbrev      bool      // global: render "(…)"/"<…>" contents as "..."
	Ready       bool      // rows/tree have been built at least once

	Rows   []layout.TreeRow // flattened visible rows (tree nodes + leaves), nav/render unit
	Facets []FacetHit       // clickable toggle buttons on the status line (x ranges)

	abbrevExcept map[string]bool    // per-row overrides inverting Abbrev
	collapsed    map[string]bool    // collapsed tree node paths (persist across rebuilds)
	collapsedAlt map[string]bool    // pre-filter collapse state, saved while a search filter is active
	filtering    bool               // whether a search filter is currently narrowing the tree
	roots        []*layout.TreeNode // built tree; cached so collapse toggles only re-flatten
	treeInit     bool               // collapse-default applied once
	byDisplay    []int              // all symbol indices sorted by Display(); built lazily
	rowCache     layout.RowMemo[view.RowCacheKey, []string]
	heightCache  layout.RowMemo[view.RowCacheKey, int]
}

// DropCaches drops cached symbol rows and heights.
func (st *State) DropCaches() {
	st.rowCache = nil
	st.heightCache = nil
}

// OnNamesChanged drops everything that bakes in symbol display names — the
// demangle pass finishing or being toggled changes both the display order and
// every tree path, so the pre-change tree (and any collapse-default) is stale.
func (st *State) OnNamesChanged(ctx view.Context) {
	st.byDisplay = nil
	st.treeInit = false
	st.collapsed = nil
	if st.Ready {
		st.Recompute(ctx)
	}
}

// SetAbbrevAll sets the global bracket-abbreviation state (the settings-modal
// path), clearing any per-row overrides.
func (st *State) SetAbbrevAll(on bool) {
	st.Abbrev = on
	st.abbrevExcept = nil
	st.DropCaches()
}

// FilterByLib narrows the view to symbols imported from lib (the Libs view's
// "show imports" jump), clearing the other filters that would hide them.
func (st *State) FilterByLib(ctx view.Context, lib string) {
	st.Filter.SetValue("")
	st.Lib = lib
	st.KindOn = false
	st.Cur, st.Top = 0, 0
	st.Recompute(ctx)
}

// FilterByName narrows the view to symbols matching name (the Relocs view's "go
// to the bound symbol" jump). Every narrowing facet is cleared first so the
// target can't be hidden by a stale scope/bind/type/lib filter.
func (st *State) FilterByName(ctx view.Context, name string) {
	st.Lib = ""
	st.KindOn = false
	st.BindOn = false
	st.Scope = ScopeAll
	st.Filter.SetValue(name)
	st.Cur, st.Top = 0, 0
	st.Recompute(ctx)
}

// CaretAddr returns the address of the symbol under the cursor, for the shell's
// cross-view "open caret in…" jump.
func (st *State) CaretAddr(ctx view.Context) (uint64, bool) {
	if s, ok := st.current(ctx); ok && s.Addr != 0 {
		return s.Addr, true
	}
	return 0, false
}

// ClickFacet toggles the facet button at screen column x on the status row,
// returning whether a button was hit.
func (st *State) ClickFacet(ctx view.Context, host view.Host, x int) bool {
	for _, f := range st.Facets {
		if x >= f.Start && x < f.End {
			st.toggleFacet(ctx, host, f.Kind)
			return true
		}
	}
	return false
}

// toggleFacet advances the clicked toggle, mirroring its keyboard binding.
func (st *State) toggleFacet(ctx view.Context, host view.Host, k FacetKind) {
	if k == FacetAbbrev {
		// Abbreviation is a pure render change: keep the cursor and skip the rebuild.
		st.ToggleAbbrevAll(host)
		return
	}
	st.Cur, st.Top = 0, 0
	switch k {
	case FacetType:
		st.cycleKindFilter(host)
	case FacetScope:
		st.Scope = (st.Scope + 1) % 3
		host.SetStatus("symbol scope: "+st.Scope.String(), false)
	case FacetSort:
		st.Sort = (st.Sort + 1) % 3
		host.SetStatus("sort: "+st.Sort.String(), false)
	case FacetSortDir:
		st.SortDesc = !st.SortDesc
	case FacetBind:
		st.cycleBindFilter(host)
	case FacetTree:
		st.Tree = !st.Tree
	}
	st.Recompute(ctx)
}

// abbrevActive reports whether n's brackets should be abbreviated, combining
// the global setting with any per-row override (the override inverts the global).
func (st *State) abbrevActive(n *layout.TreeNode) bool {
	on := st.Abbrev
	if st.abbrevExcept[abbrevKey(n)] {
		on = !on
	}
	return on
}

// label returns n's display label with bracket abbreviation applied when it is
// in effect for that row.
func (st *State) label(n *layout.TreeNode) string {
	if st.abbrevActive(n) {
		return AbbrevBrackets(n.Label)
	}
	return n.Label
}

// ToggleAbbrev flips bracket abbreviation for just the row under the cursor.
func (st *State) ToggleAbbrev(host view.Host) {
	if st.Cur < 0 || st.Cur >= len(st.Rows) {
		return
	}
	n := st.Rows[st.Cur].Node
	if st.abbrevExcept == nil {
		st.abbrevExcept = map[string]bool{}
	}
	k := abbrevKey(n)
	st.abbrevExcept[k] = !st.abbrevExcept[k]
	st.DropCaches()
	if st.abbrevActive(n) {
		host.SetStatus("arguments collapsed (this row)", false)
	} else {
		host.SetStatus("arguments expanded (this row)", false)
	}
}

// ToggleAbbrevAll flips bracket abbreviation globally, clearing any per-row
// overrides so every row returns to the uniform state.
func (st *State) ToggleAbbrevAll(host view.Host) {
	st.Abbrev = !st.Abbrev
	st.abbrevExcept = nil
	st.DropCaches()
	host.SymbolNamesChanged() // the toggle also moves disasm/hex/source annotations
	if st.Abbrev {
		host.SetStatus("arguments collapsed (all)", false)
	} else {
		host.SetStatus("arguments expanded (all)", false)
	}
}

// Recompute rebuilds the filtered set and the flattened visible rows from the
// current filter, sort, and (in tree mode) collapse state.
func (st *State) Recompute(ctx view.Context) {
	st.Ready = true
	st.DropCaches()
	needle := strings.ToLower(st.Filter.Value())
	// Entering a search auto-expands the tree so matches aren't hidden under
	// previously-collapsed groups; the pre-filter collapse state is saved and
	// restored when the search clears. In between, collapse/expand work normally on
	// the filtered tree (flattenRows honours the collapse set either way).
	if filtering := needle != ""; filtering != st.filtering {
		if filtering {
			st.collapsedAlt = st.collapsed
			st.collapsed = nil
		} else {
			st.collapsed = st.collapsedAlt
			st.collapsedAlt = nil
		}
		st.filtering = filtering
	}
	var lowerName, lowerDem []string
	if needle != "" {
		lowerName, lowerDem = ctx.File.LowerNames()
	}
	st.Filtered = st.Filtered[:0]
	scan := func(i int) {
		s := ctx.File.Symbols[i]
		if st.KindOn && s.Kind != st.Kind {
			return
		}
		if st.BindOn && s.Bind != st.Bind {
			return
		}
		if !st.Scope.includes(s) {
			return
		}
		if st.Lib != "" && s.Library != st.Lib {
			return
		}
		if needle == "" || strings.Contains(lowerName[i], needle) ||
			(lowerDem[i] != "" && strings.Contains(lowerDem[i], needle)) {
			st.Filtered = append(st.Filtered, i)
		}
	}
	// Scan in display order for a name sort, and always in tree mode: the tree's
	// grouping relies on name adjacency, so the tree is built from name order even
	// when the (irrelevant in tree mode) flat-list sort is by address or size.
	if st.Sort == SortName || st.Tree {
		st.ensureDisplayOrder(ctx)
		for _, i := range st.byDisplay {
			scan(i)
		}
	} else {
		for i := range ctx.File.Symbols {
			scan(i)
		}
	}
	st.applySort(ctx)
	st.buildRows(ctx)
	if st.Cur >= len(st.Rows) {
		st.Cur = max(0, len(st.Rows)-1)
	}
}

// Ensure builds the rows on first entry into the view.
func (st *State) Ensure(ctx view.Context) {
	if !st.Ready {
		st.Recompute(ctx)
	}
}

// applySort orders Filtered by the active field, ascending by default and
// reversed when SortDesc is set. Name order is already established (ascending)
// by scanning in display order (see Recompute), so it only needs reversing for
// descending.
func (st *State) applySort(ctx view.Context) {
	if st.Tree {
		return // tree mode is always built from (ascending) name order
	}
	desc := st.SortDesc
	switch st.Sort {
	case SortName:
		if desc {
			layout.ReverseInts(st.Filtered)
		}
	case SortAddr:
		sort.SliceStable(st.Filtered, func(i, j int) bool {
			a, b := ctx.File.Symbols[st.Filtered[i]].Addr, ctx.File.Symbols[st.Filtered[j]].Addr
			if desc {
				return a > b
			}
			return a < b
		})
	case SortSize:
		sort.SliceStable(st.Filtered, func(i, j int) bool {
			a, b := ctx.File.Symbols[st.Filtered[i]].Size, ctx.File.Symbols[st.Filtered[j]].Size
			if desc {
				return a > b
			}
			return a < b
		})
	}
}

// ensureDisplayOrder builds (once) the symbol indices sorted by their shown
// name. Invalidated (set nil) when demangling finishes, since Display() changes.
func (st *State) ensureDisplayOrder(ctx view.Context) {
	if st.byDisplay != nil {
		return
	}
	idx := make([]int, len(ctx.File.Symbols))
	for i := range idx {
		idx[i] = i
	}
	sort.Slice(idx, func(a, b int) bool {
		return ctx.File.Symbols[idx[a]].Display() < ctx.File.Symbols[idx[b]].Display()
	})
	st.byDisplay = idx
}

// buildRows rebuilds the visible row slice from Filtered: in tree mode it
// (re)builds the namespace tree and flattens it; otherwise one leaf row per
// symbol. The built tree is cached in roots so a later collapse/expand only
// re-flattens (flattenRows) instead of rebuilding from scratch — important on
// large symbol tables (hundreds of thousands of names).
func (st *State) buildRows(ctx view.Context) {
	if st.Tree {
		label := func(i int) string { return ctx.File.Symbols[i].Display() }
		st.roots = layout.BuildScopedTree(st.Filtered, label)
		if !st.treeInit {
			st.treeInit = true
			if ctx.TreeCollapseDefault {
				st.collapsed = map[string]bool{}
				layout.EachInternal(st.roots, func(p string) { st.collapsed[p] = true })
			}
		}
		st.flattenRows()
		return
	}
	st.roots = nil
	nodes := make([]layout.TreeNode, len(st.Filtered))
	rows := st.Rows[:0]
	for k, idx := range st.Filtered {
		nodes[k] = layout.TreeNode{Label: ctx.File.Symbols[idx].Display(), Leaf: idx, Count: 1}
		rows = append(rows, layout.TreeRow{Node: &nodes[k], Depth: 0})
	}
	st.Rows = rows
}

// flattenRows re-projects the cached tree (roots) into visible rows using the
// current collapse state — the cheap path taken on every collapse/expand.
func (st *State) flattenRows() {
	// Always honour the collapse state — including while a search filter is active
	// (Recompute auto-expands on entering the filter so matches show, then the
	// user's collapse/expand take effect here).
	st.Rows = layout.FlattenTree(st.roots, st.collapsed, 0, st.Rows[:0])
}

// TreeActive reports whether the tree is currently shown. The tree is always
// built from name order, so it works under any flat-list sort field.
func (st *State) TreeActive() bool {
	return st.Tree
}

func (st *State) IsCollapsed(path string) bool {
	return st.collapsed != nil && st.collapsed[path]
}

// SetAllCollapsed collapses or expands every internal node.
func (st *State) SetAllCollapsed(collapsed bool) {
	if !st.TreeActive() {
		return
	}
	if !collapsed {
		st.collapsed = nil
	} else {
		st.collapsed = map[string]bool{}
		layout.EachInternal(st.roots, func(p string) { st.collapsed[p] = true })
	}
	st.rebuildRows()
}

func (st *State) clampCursor() {
	if st.Cur >= len(st.Rows) {
		st.Cur = max(0, len(st.Rows)-1)
	}
	if st.Cur < 0 {
		st.Cur = 0
	}
}

// Update handles keys while the Symbols view is active. A focused filter input
// is captured centrally by the host, so by the time a key reaches here it is
// navigation or an action.
func (st *State) Update(ctx view.Context, host view.Host, key string) {
	if layout.NavKey(&st.Cur, len(st.Rows), host.ListPage(), key) {
		return
	}
	switch key {
	case "/":
		st.Filter.Focus()
	case "esc":
		dirty := st.Lib != "" || st.KindOn || st.BindOn ||
			st.Scope != ScopeAll || st.Filter.Value() != "" || st.Filter.Focused()
		st.Filter.SetValue("")
		st.Filter.Blur()
		st.Lib = ""
		st.KindOn = false
		st.BindOn = false
		st.Scope = ScopeAll
		st.Cur, st.Top = 0, 0
		st.Recompute(ctx)
		if dirty {
			host.SetStatus("filters cleared", false)
		}
	case "ctrl+t":
		st.cycleKindFilter(host)
		st.Cur, st.Top = 0, 0
		st.Recompute(ctx)
	case "ctrl+s":
		st.Scope = (st.Scope + 1) % 3
		st.Cur, st.Top = 0, 0
		st.Recompute(ctx)
		host.SetStatus("symbol scope: "+st.Scope.String(), false)
	case "ctrl+b":
		st.cycleBindFilter(host)
		st.Cur, st.Top = 0, 0
		st.Recompute(ctx)
	case "s":
		st.Sort = (st.Sort + 1) % 3
		st.Cur, st.Top = 0, 0
		st.Recompute(ctx)
		host.SetStatus("sort: "+st.Sort.String(), false)
	case "r":
		st.SortDesc = !st.SortDesc
		st.Cur, st.Top = 0, 0
		st.Recompute(ctx)
		dir := "ascending"
		if st.SortDesc {
			dir = "descending"
		}
		host.SetStatus("sort order: "+dir, false)
	case "t":
		st.Tree = !st.Tree
		st.Cur, st.Top = 0, 0
		st.Recompute(ctx)
		label := "flat table"
		if st.Tree {
			label = "tree"
		}
		host.SetStatus("symbols view: "+label, false)
	case "-", "_":
		st.SetAllCollapsed(true)
		host.SetStatus("collapsed all", false)
	case "+", "=":
		st.SetAllCollapsed(false)
		host.SetStatus("expanded all", false)
	case "right":
		if st.TreeActive() {
			st.ensureCollapsed()
			if layout.TreeExpandOne(st.Rows, &st.Cur, st.collapsed) {
				st.rebuildRows()
			}
		}
	case "left":
		if st.TreeActive() {
			st.ensureCollapsed()
			if layout.TreeCollapseOne(st.Rows, &st.Cur, st.collapsed) {
				st.rebuildRows()
			}
		}
	case "w":
		host.ToggleWrap()
	case "e":
		st.ToggleAbbrevAll(host)
	case ".":
		st.ToggleAbbrev(host)
	case "enter":
		st.activateRow(ctx, host)
	case "d":
		if sym, ok := st.current(ctx); ok {
			host.JumpDisasmAtAddr(sym.Addr)
		}
	case "h":
		if sym, ok := st.current(ctx); ok {
			host.JumpHexAtAddr(sym.Addr)
		}
	case "m":
		if sym, ok := st.current(ctx); ok {
			host.JumpRawAtAddr(sym.Addr)
		}
	case "A":
		if sym, ok := st.current(ctx); ok {
			host.CopyToClipboard(fmt.Sprintf("0x%0*x", ctx.File.AddrHexWidth(), sym.Addr), "address")
		}
	case "S":
		if sym, ok := st.current(ctx); ok {
			host.CopyToClipboard(sym.Name, "symbol")
		}
	}
}

// activateRow opens a leaf symbol, or expands/collapses the whole subtree under
// a group node (Enter switches "expand all below" ↔ "collapse all below").
func (st *State) activateRow(ctx view.Context, host view.Host) {
	if st.Cur < 0 || st.Cur >= len(st.Rows) {
		return
	}
	n := st.Rows[st.Cur].Node
	if n.Leaf < 0 {
		st.ensureCollapsed()
		if layout.TreeToggleSubtree(st.Rows, st.Cur, st.collapsed) {
			st.rebuildRows()
		}
		return
	}
	sym := ctx.File.Symbols[n.Leaf]
	if sym.Addr == 0 {
		host.SetStatus(fmt.Sprintf("symbol %s has no address", sym.Name), true)
		return
	}
	host.OpenSymbol(sym)
}

func (st *State) ensureCollapsed() {
	if st.collapsed == nil {
		st.collapsed = map[string]bool{}
	}
}

// ToggleNode collapses/expands the internal node at the current row (the
// mouse-click path; keyboard folding goes through Update).
func (st *State) ToggleNode() {
	if st.Cur < 0 || st.Cur >= len(st.Rows) {
		return
	}
	n := st.Rows[st.Cur].Node
	if n.Leaf >= 0 {
		return
	}
	st.ensureCollapsed()
	st.collapsed[n.Path] = !st.collapsed[n.Path]
	st.rebuildRows()
}

// rebuildRows re-projects the cached tree after a collapse-state change. It
// does not rebuild the tree itself (use Recompute/buildRows for that), so an
// arrow-key fold on a huge table is instant.
func (st *State) rebuildRows() {
	st.DropCaches()
	st.flattenRows()
	st.clampCursor()
}

// current returns the symbol under the cursor when the row is a leaf.
func (st *State) current(ctx view.Context) (binfile.Symbol, bool) {
	if st.Cur < 0 || st.Cur >= len(st.Rows) {
		return binfile.Symbol{}, false
	}
	n := st.Rows[st.Cur].Node
	if n.Leaf < 0 {
		return binfile.Symbol{}, false
	}
	return ctx.File.Symbols[n.Leaf], true
}

func (st *State) cycleKindFilter(host view.Host) {
	order := []binfile.SymKind{binfile.SymFunc, binfile.SymObject, binfile.SymSection, binfile.SymFile, binfile.SymTLS, binfile.SymCommon, binfile.SymOther}
	if !st.KindOn {
		st.KindOn = true
		st.Kind = order[0]
		host.SetStatus("symbol type filter: "+kindString(st.Kind), false)
		return
	}
	for i, k := range order {
		if k == st.Kind {
			if i == len(order)-1 {
				st.KindOn = false
				host.SetStatus("symbol type filter: all", false)
				return
			}
			st.Kind = order[i+1]
			host.SetStatus("symbol type filter: "+kindString(st.Kind), false)
			return
		}
	}
	st.KindOn = false
}

// cycleBindFilter steps the bind filter off → global → weak → local → off
// (global is the usual "exported symbols" lens when combined with scope:internal).
func (st *State) cycleBindFilter(host view.Host) {
	order := []binfile.SymBind{binfile.BindGlobal, binfile.BindWeak, binfile.BindLocal}
	if !st.BindOn {
		st.BindOn = true
		st.Bind = order[0]
		host.SetStatus("symbol bind filter: "+bindString(st.Bind), false)
		return
	}
	for i, b := range order {
		if b == st.Bind {
			if i == len(order)-1 {
				st.BindOn = false
				host.SetStatus("symbol bind filter: all", false)
				return
			}
			st.Bind = order[i+1]
			host.SetStatus("symbol bind filter: "+bindString(st.Bind), false)
			return
		}
	}
	st.BindOn = false
}

// ClickHeader handles a click on the flat table's sortable header row.
func (st *State) ClickHeader(ctx view.Context, host view.Host, x int) bool {
	if st.TreeActive() {
		return false
	}
	sort, ok := layout.HitSortableHeader(st.headerCols(ctx), x)
	if !ok {
		return false
	}
	fieldChanged := layout.ApplySortHeaderClick(&st.Sort, &st.SortDesc, sort)
	st.Cur, st.Top = 0, 0
	st.Recompute(ctx)
	if fieldChanged {
		host.SetStatus("sort: "+st.Sort.String(), false)
	} else {
		host.SetStatus("sort order: "+layout.SortDirectionLabel(st.SortDesc), false)
	}
	return true
}

// headerCols maps the flat table's header columns to their x ranges, matching
// the layout in Render / rowsText.
func (st *State) headerCols(ctx view.Context) []layout.SortableHeaderCol[SortField] {
	addrCol := 2 + ctx.File.AddrHexWidth()
	sizeStart := addrCol + 2
	nameStart := addrCol + 28
	return []layout.SortableHeaderCol[SortField]{
		{Start: 1, End: 1 + addrCol, Sort: SortAddr},
		{Start: sizeStart, End: sizeStart + 9, Sort: SortSize},
		{Start: nameStart, End: ctx.Width, Sort: SortName},
	}
}

// Render draws the view body.
func (st *State) Render(ctx view.Context, host view.Host) string {
	st.Ensure(ctx)
	bodyH := ctx.BodyH
	if bodyH < 3 {
		bodyH = 3
	}

	filterRow := st.Filter.View()
	st.Facets = st.Facets[:0]
	if !st.Filter.Focused() {
		kind := "all"
		if st.KindOn {
			kind = kindString(st.Kind)
		}
		var b strings.Builder
		col := 0
		// FooterStyle adds left/right padding, so count the *rendered* width — not
		// the raw string — or the clickable facet ranges drift right of the chips.
		plain := func(s string) {
			r := ctx.FooterStyle.Render(s)
			b.WriteString(r)
			col += lipgloss.Width(r)
		}
		// Each chip is a clickable toggle: the bound key in the accent colour (like
		// the footer hints) followed by the current value.
		button := func(key, label string, k FacetKind) {
			start := col
			kr := ctx.KeyStyle.Render(key)
			lr := ctx.FooterStyle.Render(" " + label)
			b.WriteString(kr)
			b.WriteString(lr)
			col += lipgloss.Width(kr) + lipgloss.Width(lr)
			st.Facets = append(st.Facets, FacetHit{start, col, k})
			plain("   ")
		}
		bind := "all"
		if st.BindOn {
			bind = bindString(st.Bind)
		}
		treeLabel := "view:flat"
		if st.TreeActive() {
			treeLabel = "view:tree"
		}
		plain("/ " + st.Filter.Value() + "   ")
		button(layout.CtrlKeys("t"), "type:"+kind, FacetType)
		button(layout.CtrlKeys("s"), "scope:"+st.Scope.String(), FacetScope)
		button(layout.CtrlKeys("b"), "bind:"+bind, FacetBind)
		button("s", "sort:"+st.Sort.String(), FacetSort)
		dir := "↑asc"
		if st.SortDesc {
			dir = "↓desc"
		}
		button("r", dir, FacetSortDir)
		button("t", treeLabel, FacetTree)
		argsLabel := "args:full"
		if st.Abbrev {
			argsLabel = "args:…"
		}
		button("e", argsLabel, FacetAbbrev)
		if st.Lib != "" {
			plain("lib:" + st.Lib + " (Esc clears)   ")
		}
		plain(fmt.Sprintf("(%d / %d)", len(st.Filtered), len(ctx.File.Symbols)))
		filterRow = b.String()
	}

	addrW := ctx.File.AddrHexWidth()
	var header string
	if st.TreeActive() {
		header = ctx.FooterStyle.Render(" tree · ←/→ fold · ↵ all below · +/− expand/collapse all · . args · t flat")
	} else {
		addrCol := 2 + addrW
		addrLabel := layout.SortHeaderLabel("Address", addrCol, SortAddr, st.Sort, st.SortDesc)
		sizeLabel := layout.SortHeaderLabel("Size", 9, SortSize, st.Sort, st.SortDesc)
		nameLabel := layout.TrailingSortHeaderLabel("Name", SortName, st.Sort, st.SortDesc)
		header = ctx.TableHeader(fmt.Sprintf(" %-*s %9s %6s %7s  %s", addrCol, addrLabel, sizeLabel, "Bind", "Type", nameLabel))
	}

	visible := bodyH - 2 // filter row + header
	if visible < 1 {
		visible = 1
	}
	rowHeight := st.RowHeightFn(ctx)
	top := ctx.VisualTop(st.Cur, st.Top, len(st.Rows), visible, rowHeight)
	st.Top = top
	st.RenderedTop = top
	host.SetPageRows(layout.PageStep(top, len(st.Rows), visible, rowHeight))

	if len(st.Rows) == 0 {
		msg := "no symbols in this binary"
		if st.Filter.Value() != "" || st.KindOn || st.BindOn ||
			st.Scope != ScopeAll || st.Lib != "" {
			msg = "no matching symbols  ·  Esc clears filters"
		}
		return ctx.EmptyList(msg, filterRow, header)
	}
	rows := []string{filterRow, header}
	for i := top; i < len(st.Rows); i++ {
		node := st.Rows[i].Node
		for _, row := range st.rowsFor(ctx, i, addrW) {
			if len(rows) >= bodyH {
				break
			}
			if i == st.Cur {
				if node.Leaf < 0 {
					// Group node: highlight the arrow only (no full-width white bar).
					row = ctx.TreeNodeRow(st.Rows[i].Depth, st.label(node), node.Count, st.IsCollapsed(node.Path), true, "")
				} else {
					row = ctx.SelStyle.Render(ansi.Strip(row))
				}
			}
			rows = append(rows, row)
		}
		if len(rows) >= bodyH {
			break
		}
	}
	return layout.PadBodyRows(rows, ctx.Width, bodyH)
}

// RowHeightFn returns the per-row rendered height, for the scroll geometry.
func (st *State) RowHeightFn(ctx view.Context) func(int) int {
	return func(i int) int {
		if i < 0 || i >= len(st.Rows) {
			return 1
		}
		addrW := ctx.File.AddrHexWidth()
		return st.heightCache.Get(view.RowCacheKey{I: i, Width: ctx.Width, AddrW: addrW, Wrap: ctx.Wrap}, func() int {
			return len(st.rowsFor(ctx, i, addrW))
		})
	}
}

// RowText returns the current row's rendered text, for the copy-line action.
func (st *State) RowText(ctx view.Context) string {
	if st.Cur < 0 || st.Cur >= len(st.Rows) {
		return ""
	}
	return strings.Join(st.RowLines(ctx, st.Cur), " ")
}

// RowLines returns the rendered lines of row i (a wrapped leaf renders as
// several lines).
func (st *State) RowLines(ctx view.Context, i int) []string {
	if i < 0 || i >= len(st.Rows) {
		return nil
	}
	return st.rowsFor(ctx, i, ctx.File.AddrHexWidth())
}

// rowsFor renders one visible row — an internal tree node (arrow + underlined
// label + collapsed count) or a leaf symbol (address columns + indented name) —
// memoised by the layout inputs.
func (st *State) rowsFor(ctx view.Context, i, addrW int) []string {
	return st.rowCache.Get(view.RowCacheKey{I: i, Width: ctx.Width, AddrW: addrW, Wrap: ctx.Wrap}, func() []string {
		return st.rowsText(ctx, i, addrW)
	})
}

func (st *State) rowsText(ctx view.Context, i, addrW int) []string {
	const sep = " \t/.-_:$@<>"
	row := st.Rows[i]
	n := row.Node
	indentW := row.Depth * layout.TreeIndent
	indent := strings.Repeat(" ", indentW)

	label := st.label(n)
	var rows []string
	if n.Leaf < 0 {
		// Internal (group) node: arrow + highlighted, underlined segment.
		rows = []string{ctx.TreeNodeRow(row.Depth, label, n.Count, st.IsCollapsed(n.Path), false, "")}
	} else {
		s := ctx.File.Symbols[n.Leaf]
		rowStyle := ctx.SymbolStyle(s.Kind, s.Bind)
		colsPlain := fmt.Sprintf("0x%0*x %9d %6s %7s  ", addrW, s.Addr, s.Size, bindString(s.Bind), kindString(s.Kind))
		cols := ctx.AddrStyle.Render(fmt.Sprintf("0x%0*x", addrW, s.Addr)) +
			rowStyle.Render(fmt.Sprintf(" %9d %6s %7s  ", s.Size, bindString(s.Bind), kindString(s.Kind)))
		nameW := ctx.Width - indentW - len(colsPlain)
		if nameW < 1 {
			nameW = 1
		}
		var parts []string
		if ctx.Wrap {
			parts = splitStyledRows(ansi.Wrap(label, nameW, sep))
			for k := range parts {
				parts[k] = rowStyle.Render(parts[k])
			}
		} else {
			parts = []string{rowStyle.Render(layout.TruncateMiddle(label, nameW))}
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
