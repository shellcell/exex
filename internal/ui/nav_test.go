package ui

import (
	"fmt"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/ui/layout"
	"github.com/rabarbra/exex/internal/ui/view"
	"github.com/rabarbra/exex/internal/ui/views/sources"
	"github.com/rabarbra/exex/internal/ui/views/symbols"
)

func TestSymbolsTreeGrouping(t *testing.T) {
	// Names chosen so the Discarding group must NOT nest under Allocating.
	names := []string{
		"Io.Writer.Allocating.drain",
		"Io.Writer.Allocating.ensureTotalCapacity",
		"Io.Writer.Allocating.vtable",
		"Io.Writer.Discarding.drain",
		"Io.Writer.alignBufferOptions",
	}
	var syms []binfile.Symbol
	for i, nm := range names {
		syms = append(syms, binfile.Symbol{Name: nm, Addr: uint64(0x1000 + i*8), Kind: binfile.SymFunc})
	}
	f := &binfile.File{Format: binfile.FormatELF, Symbols: syms}
	m, err := New(f)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m.width, m.height = 120, 30
	m.symbols.Tree = true
	m.setMode(modeSymbols)
	m.symbols.Recompute(m.viewContext())

	// Expect a compressed "Io.Writer." root whose children are the "Allocating."
	// group plus two leaves shown by their path from the root: "Discarding.drain"
	// (a single symbol → not its own group, and crucially NOT nested under
	// Allocating) and "alignBufferOptions".
	roots := layout.BuildScopedTree(m.symbols.Filtered, func(i int) string { return m.file.Symbols[i].Display() })
	if len(roots) != 1 || roots[0].Label != "Io.Writer." {
		t.Fatalf("root = %v, want single Io.Writer.", labelsOf(roots))
	}
	if got := labelsOf(roots[0].Children); strings.Join(got, "|") != "Allocating.|Discarding.drain|alignBufferOptions" {
		t.Fatalf("Io.Writer. children = %v", got)
	}
	// "Discarding.drain" must be a leaf, not an internal (collapsible) node.
	if roots[0].Children[1].Leaf < 0 {
		t.Fatalf("Discarding.drain should be a leaf, not a group")
	}

	// Collapsing everything hides all rows beneath the single Io.Writer. root.
	full := len(m.symbols.Rows)
	m.symbols.SetAllCollapsed(true)
	if len(m.symbols.Rows) != 1 {
		t.Fatalf("collapsed root: %d visible rows, want 1 (was %d)", len(m.symbols.Rows), full)
	}

	// Expand-all clears collapse; collapse-all leaves only the roots/internal heads.
	m.symbols.Cur = 0
	m.symbols.SetAllCollapsed(false)
	if len(m.symbols.Rows) != full {
		t.Fatalf("expand all: %d rows, want %d", len(m.symbols.Rows), full)
	}

	// t toggles back to the flat table: one row per symbol, full names.
	m.symbols.Update(m.viewContext(), m, "t")
	if len(m.symbols.Rows) != len(syms) {
		t.Fatalf("flat view: %d rows, want %d", len(m.symbols.Rows), len(syms))
	}
	if got := ansi.Strip(strings.TrimSpace(m.symbols.RowLines(m.viewContext(), 3)[0])); !strings.Contains(got, "Io.Writer.Discarding.drain") {
		t.Fatalf("flat row should show full name, got %q", got)
	}
}

func TestSymbolsTreeKeys(t *testing.T) {
	names := []string{
		"a.b.x", "a.b.y", "a.c.z", "top",
	}
	var syms []binfile.Symbol
	for i, nm := range names {
		syms = append(syms, binfile.Symbol{Name: nm, Addr: uint64(0x1000 + i*8), Kind: binfile.SymFunc})
	}
	f := &binfile.File{Format: binfile.FormatELF, Symbols: syms}
	m, err := New(f)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m.width, m.height = 120, 30
	m.symbols.Tree = true
	m.setMode(modeSymbols)
	m.symbols.Recompute(m.viewContext())

	rowLabel := func(i int) string {
		if i < 0 || i >= len(m.symbols.Rows) {
			return ""
		}
		return m.symbols.Rows[i].Node.Label
	}
	// Tree: ▾ a. → {▾ b. → x,y; c.z}; top. Row 0 is the "a." group.
	if rowLabel(0) != "a." {
		t.Fatalf("row 0 = %q, want a.", rowLabel(0))
	}
	full := len(m.symbols.Rows)

	// Enter on the (expanded) root recursively collapses everything below it.
	m.symbols.Cur = 0
	m.symbols.Update(m.viewContext(), m, "enter")
	if len(m.symbols.Rows) >= full || !m.symbols.IsCollapsed("a.") {
		t.Fatalf("enter on expanded root did not collapse subtree (%d rows)", len(m.symbols.Rows))
	}
	// Right expands the root one level.
	m.symbols.Update(m.viewContext(), m, "right")
	if m.symbols.IsCollapsed("a.") {
		t.Fatal("right should expand the a. group")
	}
	// Expand everything, then Left on a deep leaf folds its parent branch.
	m.symbols.SetAllCollapsed(false)
	full2 := len(m.symbols.Rows)
	leaf := -1
	for i, r := range m.symbols.Rows {
		if r.Node.Leaf >= 0 && r.Depth >= 2 {
			leaf = i
			break
		}
	}
	if leaf < 0 {
		t.Fatal("no deep leaf row found")
	}
	m.symbols.Cur = leaf
	m.symbols.Update(m.viewContext(), m, "left")
	if len(m.symbols.Rows) >= full2 {
		t.Fatalf("left on a leaf did not fold its parent branch (%d→%d)", full2, len(m.symbols.Rows))
	}
}

func TestSymbolsFacetClick(t *testing.T) {
	f := &binfile.File{Format: binfile.FormatELF, Symbols: []binfile.Symbol{
		{Name: "alpha", Addr: 0x1000, Kind: binfile.SymFunc},
		{Name: "beta", Addr: 0x1100, Kind: binfile.SymObject},
	}}
	m, err := New(f)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m.width, m.height = 120, 20
	m.setMode(modeSymbols)
	m.symbols.Recompute(m.viewContext())
	_ = m.symbols.Render(m.viewContext(), m) // populates m.symbols.Chips with x ranges

	// The chip carrying key k, clicked in its middle.
	hit := func(key string) (int, bool) {
		for _, c := range m.symbols.Chips {
			if c.Key == key {
				return (c.Start + c.End) / 2, true
			}
		}
		return 0, false
	}

	// Clicking the sort chip advances the sort, exactly as pressing `s` does.
	x, ok := hit("s")
	if !ok {
		t.Fatal("no sort chip rendered")
	}
	if m.symbols.Sort != symbols.SortName {
		t.Fatalf("precondition: sort = %v", m.symbols.Sort)
	}
	if !m.symbols.ClickStatus(m.viewContext(), m, x) {
		t.Fatal("click on the sort chip missed")
	}
	if m.symbols.Sort != symbols.SortAddr {
		t.Fatalf("sort after click = %v, want address", m.symbols.Sort)
	}

	// Clicking the view chip toggles the tree.
	_ = m.symbols.Render(m.viewContext(), m)
	x, ok = hit("t")
	if !ok {
		t.Fatal("no view chip rendered")
	}
	was := m.symbols.Tree
	if !m.symbols.ClickStatus(m.viewContext(), m, x) {
		t.Fatal("click on the view chip missed")
	}
	if m.symbols.Tree == was {
		t.Fatal("view chip click did not toggle tree mode")
	}
}

func TestSourcesTree(t *testing.T) {
	st := &sources.State{}
	st.Files = []string{
		"/home/u/proj/src/a.c",
		"/home/u/proj/src/b.c",
		"/home/u/proj/main.c",
	}
	st.Filtered = []int{0, 1, 2}
	st.Tree = true
	st.BuildRows(view.Context{})

	roots := layout.BuildTree(st.Filtered, func(i int) string { return st.Files[i] }, layout.SegPath)
	if len(roots) != 1 || roots[0].Label != "/home/u/proj/" {
		t.Fatalf("root = %v, want /home/u/proj/", labelsOf(roots))
	}
	if got := labelsOf(roots[0].Children); strings.Join(got, "|") != "src/|main.c" {
		t.Fatalf("children = %v, want src/, main.c", got)
	}
	if len(st.Rows) != 5 { // root + src/ + a.c + b.c + main.c
		t.Fatalf("visible rows = %d, want 5", len(st.Rows))
	}
	st.SetAllCollapsed(view.Context{}, true)
	if len(st.Rows) != 1 {
		t.Fatalf("collapse-all rows = %d, want 1", len(st.Rows))
	}
}

func labelsOf(nodes []*layout.TreeNode) []string {
	var out []string
	for _, n := range nodes {
		out = append(out, n.Label)
	}
	return out
}

func TestPageStep(t *testing.T) {
	const1 := func(int) int { return 1 }
	const2 := func(int) int { return 2 }
	const3 := func(int) int { return 3 }

	cases := []struct {
		name             string
		from, n, visible int
		rowHeight        func(int) int
		want             int
	}{
		{"single-line fills exactly", 0, 100, 10, const1, 10},
		{"two-line rows: half as many", 0, 100, 10, const2, 5},
		{"three-line rows leave a remainder", 0, 100, 10, const3, 3},
		{"fewer items than fit", 0, 3, 10, const1, 3},
		{"row taller than viewport still steps one", 0, 100, 5, func(int) int { return 10 }, 1},
		{"zero visible clamps to one line", 0, 100, 0, const1, 1},
		{"empty list still returns at least one", 5, 5, 10, const1, 1},
	}
	for _, tc := range cases {
		if got := layout.PageStep(tc.from, tc.n, tc.visible, tc.rowHeight); got != tc.want {
			t.Errorf("%s: layout.PageStep(%d,%d,%d) = %d, want %d", tc.name, tc.from, tc.n, tc.visible, got, tc.want)
		}
	}
}

// assertPageWithinViewport drives a list view's pgdown with wrap on and long
// (multi-line) rows, and checks the page neither overshoots the viewport nor
// loses its one-row context overlap, then that pgup round-trips back.
func assertPageWithinViewport(t *testing.T, m *Model, cur *int, rowHeight func(int) int, render func(), pgdn, pgup func()) {
	t.Helper()
	render()
	visible := m.bodyHeight() - 2
	if rowHeight(0) <= 1 {
		t.Skipf("rows not wrapping to multiple lines at this width (height %d)", rowHeight(0))
	}
	if m.pageRows < 1 || m.pageRows >= visible {
		t.Fatalf("pageRows = %d, want in [1,%d) when rows wrap", m.pageRows, visible)
	}

	start := *cur
	advance := m.listPage()
	pgdn()
	if got := *cur - start; got != advance {
		t.Fatalf("pgdown advanced %d items, want listPage()=%d", got, advance)
	}
	if m.pageRows > 1 {
		lines := 0
		for i := start; i < *cur; i++ {
			lines += rowHeight(i)
		}
		if lines > visible {
			t.Fatalf("pgdown skipped %d lines, want <= one viewport (%d)", lines, visible)
		}
		// One item of context should remain: a full screenful would be pageRows
		// items, and we advanced one fewer.
		if advance != m.pageRows-1 {
			t.Fatalf("advance = %d, want pageRows-1 = %d (one row of context)", advance, m.pageRows-1)
		}
	}
	pgup()
	if *cur != start {
		t.Fatalf("pgup after pgdown = %d, want %d", *cur, start)
	}
}

func TestPageDownWrapLongLinesSymbols(t *testing.T) {
	long := strings.Repeat("data_object_field_", 9) // ~160 chars, wraps at narrow width
	var syms []binfile.Symbol
	for i := 0; i < 300; i++ {
		syms = append(syms, binfile.Symbol{
			Name: fmt.Sprintf("%s%03d", long, i),
			Addr: uint64(0x1000 + i*8),
			Kind: binfile.SymObject,
		})
	}
	f := &binfile.File{Format: binfile.FormatELF, Symbols: syms}
	m, err := New(f)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m.width, m.height = 80, 30
	m.wrap = true
	m.setMode(modeSymbols)
	m.symbols.Recompute(m.viewContext())

	assertPageWithinViewport(t, m, &m.symbols.Cur,
		m.symbols.RowHeightFn(m.viewContext()),
		func() { _ = m.symbols.Render(m.viewContext(), m) },
		func() { m.symbols.Update(m.viewContext(), m, "pgdown") },
		func() { m.symbols.Update(m.viewContext(), m, "pgup") })
}

func TestPageDownWrapLongLinesStrings(t *testing.T) {
	long := strings.Repeat("a_long_printable_string_segment_", 6) // ~190 chars
	var list []binfile.StringEntry
	raw := make([]byte, 300*256)
	for i := 0; i < 300; i++ {
		txt := fmt.Sprintf("%s%03d", long, i)
		off := i * 256
		copy(raw[off:], txt)
		list = append(list, binfile.StringEntry{Offset: uint64(off), Len: uint32(len(txt))})
	}
	f := binfile.NewRawFile(raw)
	f.Format = binfile.FormatELF
	m, err := New(f)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m.width, m.height = 80, 30
	m.wrap = true
	m.setMode(modeStrings)
	// Seed the strings list directly so ensureStrings won't recompute it from the
	// (empty) synthetic file.
	m.strs.List = list
	m.strs.Recompute(m.viewContext())

	assertPageWithinViewport(t, m, &m.strs.Cur,
		m.strs.RowHeightFn(m.viewContext()),
		func() { _ = m.strs.Render(m.viewContext(), m) },
		func() { m.strs.Update(m.viewContext(), m, "pgdown") },
		func() { m.strs.Update(m.viewContext(), m, "pgup") })
}
