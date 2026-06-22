package ui

import (
	"fmt"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"

	"github.com/rabarbra/exex/internal/binfile"
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
	m.symbolsTree = true
	m.setMode(modeSymbols)
	m.recomputeSymbols()

	// Expect a compressed "Io.Writer." root whose children are the "Allocating."
	// group plus two leaves shown by their path from the root: "Discarding.drain"
	// (a single symbol → not its own group, and crucially NOT nested under
	// Allocating) and "alignBufferOptions".
	roots := buildScopedTree(m.symbolsFiltered, func(i int) string { return m.file.Symbols[i].Display() })
	if len(roots) != 1 || roots[0].label != "Io.Writer." {
		t.Fatalf("root = %v, want single Io.Writer.", labelsOf(roots))
	}
	if got := labelsOf(roots[0].children); strings.Join(got, "|") != "Allocating.|Discarding.drain|alignBufferOptions" {
		t.Fatalf("Io.Writer. children = %v", got)
	}
	// "Discarding.drain" must be a leaf, not an internal (collapsible) node.
	if roots[0].children[1].leaf < 0 {
		t.Fatalf("Discarding.drain should be a leaf, not a group")
	}

	// Collapsing the Io.Writer. root should hide everything beneath it.
	full := len(m.symbolsRows)
	m.symbolsCollapsed = map[string]bool{"Io.Writer.": true}
	m.buildSymbolRows()
	if len(m.symbolsRows) != 1 {
		t.Fatalf("collapsed root: %d visible rows, want 1 (was %d)", len(m.symbolsRows), full)
	}

	// Expand-all clears collapse; collapse-all leaves only the roots/internal heads.
	m.symbolsCur = 0
	m.setAllSymbolsCollapsed(false)
	if len(m.symbolsRows) != full {
		t.Fatalf("expand all: %d rows, want %d", len(m.symbolsRows), full)
	}

	// t toggles back to the flat table: one row per symbol, full names.
	m.updateSymbols("t")
	if len(m.symbolsRows) != len(syms) {
		t.Fatalf("flat view: %d rows, want %d", len(m.symbolsRows), len(syms))
	}
	if got := ansi.Strip(strings.TrimSpace(m.symbolRows(3, m.file.AddrHexWidth())[0])); !strings.Contains(got, "Io.Writer.Discarding.drain") {
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
	m.symbolsTree = true
	m.setMode(modeSymbols)
	m.recomputeSymbols()

	rowLabel := func(i int) string {
		if i < 0 || i >= len(m.symbolsRows) {
			return ""
		}
		return m.symbolsRows[i].node.label
	}
	// Tree: ▾ a. → {▾ b. → x,y; c.z}; top. Row 0 is the "a." group.
	if rowLabel(0) != "a." {
		t.Fatalf("row 0 = %q, want a.", rowLabel(0))
	}
	full := len(m.symbolsRows)

	// Enter on the (expanded) root recursively collapses everything below it.
	m.symbolsCur = 0
	m.updateSymbols("enter")
	if len(m.symbolsRows) >= full || !m.isSymbolCollapsed("a.") {
		t.Fatalf("enter on expanded root did not collapse subtree (%d rows)", len(m.symbolsRows))
	}
	// Right expands the root one level.
	m.updateSymbols("right")
	if m.isSymbolCollapsed("a.") {
		t.Fatal("right should expand the a. group")
	}
	// Expand everything, then Left on a deep leaf folds its parent branch.
	m.setAllSymbolsCollapsed(false)
	full2 := len(m.symbolsRows)
	leaf := -1
	for i, r := range m.symbolsRows {
		if r.node.leaf >= 0 && r.depth >= 2 {
			leaf = i
			break
		}
	}
	if leaf < 0 {
		t.Fatal("no deep leaf row found")
	}
	m.symbolsCur = leaf
	m.updateSymbols("left")
	if len(m.symbolsRows) >= full2 {
		t.Fatalf("left on a leaf did not fold its parent branch (%d→%d)", full2, len(m.symbolsRows))
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
	m.recomputeSymbols()
	_ = m.renderSymbols() // populates m.symbolFacets with x ranges

	hit := func(k facetKind) (int, bool) {
		for _, fc := range m.symbolFacets {
			if fc.kind == k {
				return (fc.start + fc.end) / 2, true
			}
		}
		return 0, false
	}

	// Clicking the sort button advances the sort.
	x, ok := hit(facetSort)
	if !ok {
		t.Fatal("no sort facet rendered")
	}
	if m.symbolsSort != sortByName {
		t.Fatalf("precondition: sort = %v", m.symbolsSort)
	}
	if !m.clickSymbolFacet(x) {
		t.Fatal("click on sort facet missed")
	}
	if m.symbolsSort != sortByAddr {
		t.Fatalf("sort after click = %v, want address", m.symbolsSort)
	}

	// Clicking the tree button toggles the tree.
	_ = m.renderSymbols()
	x, ok = hit(facetTree)
	if !ok {
		t.Fatal("no tree facet rendered")
	}
	was := m.symbolsTree
	if !m.clickSymbolFacet(x) {
		t.Fatal("click on tree facet missed")
	}
	if m.symbolsTree == was {
		t.Fatal("tree facet click did not toggle tree mode")
	}
}

func TestSourcesTree(t *testing.T) {
	m := &Model{}
	m.sourcesFiles = []string{
		"/home/u/proj/src/a.c",
		"/home/u/proj/src/b.c",
		"/home/u/proj/main.c",
	}
	m.sourcesFiltered = []int{0, 1, 2}
	m.sourcesTree = true
	m.buildSourceRows()

	roots := buildTree(m.sourcesFiltered, func(i int) string { return m.sourcesFiles[i] }, segPath)
	if len(roots) != 1 || roots[0].label != "/home/u/proj/" {
		t.Fatalf("root = %v, want /home/u/proj/", labelsOf(roots))
	}
	if got := labelsOf(roots[0].children); strings.Join(got, "|") != "src/|main.c" {
		t.Fatalf("children = %v, want src/, main.c", got)
	}
	if len(m.sourcesRows) != 5 { // root + src/ + a.c + b.c + main.c
		t.Fatalf("visible rows = %d, want 5", len(m.sourcesRows))
	}
	m.setAllSourcesCollapsed(true)
	if len(m.sourcesRows) != 1 {
		t.Fatalf("collapse-all rows = %d, want 1", len(m.sourcesRows))
	}
}

func labelsOf(nodes []*treeNode) []string {
	var out []string
	for _, n := range nodes {
		out = append(out, n.label)
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
		if got := pageStep(tc.from, tc.n, tc.visible, tc.rowHeight); got != tc.want {
			t.Errorf("%s: pageStep(%d,%d,%d) = %d, want %d", tc.name, tc.from, tc.n, tc.visible, got, tc.want)
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
	m.recomputeSymbols()

	assertPageWithinViewport(t, m, &m.symbolsCur,
		m.symbolRowHeight,
		func() { _ = m.renderSymbols() },
		func() { m.updateSymbols("pgdown") },
		func() { m.updateSymbols("pgup") })
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
	m.stringsList = list
	m.recomputeStrings()

	assertPageWithinViewport(t, m, &m.stringsCur,
		m.stringRowHeight,
		func() { _ = m.renderStrings() },
		func() { m.updateStrings("pgdown") },
		func() { m.updateStrings("pgup") })
}
