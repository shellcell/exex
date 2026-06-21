package ui

import (
	"fmt"
	"strings"
	"testing"

	"github.com/rabarbra/exex/internal/binfile"
)

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
func assertPageWithinViewport(t *testing.T, m *Model, cur, top *int, n int, rowHeight func(int) int, render func(), pgdn, pgup func()) {
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

	assertPageWithinViewport(t, m, &m.symbolsCur, &m.symbolsTop, len(m.symbolsFiltered),
		m.symbolRowHeight,
		func() { _ = m.renderSymbols() },
		func() { m.updateSymbols("pgdown") },
		func() { m.updateSymbols("pgup") })
}

func TestPageDownWrapLongLinesStrings(t *testing.T) {
	long := strings.Repeat("a_long_printable_string_segment_", 6) // ~190 chars
	var list []binfile.StringEntry
	for i := 0; i < 300; i++ {
		list = append(list, binfile.StringEntry{
			Offset: uint64(i * 256),
			Text:   fmt.Sprintf("%s%03d", long, i),
		})
	}
	f := &binfile.File{Format: binfile.FormatELF}
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

	assertPageWithinViewport(t, m, &m.stringsCur, &m.stringsTop, len(m.stringsFiltered),
		m.stringRowHeight,
		func() { _ = m.renderStrings() },
		func() { m.updateStrings("pgdown") },
		func() { m.updateStrings("pgup") })
}
