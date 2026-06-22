package ui

// Tests for the #27 keymap pass: the breaking re-bindings (copy → ⇧, filters →
// ⌥, sort-cycle on s) plus the new Sections sort and Strings section filter.

import (
	"testing"

	"github.com/rabarbra/exex/internal/binfile"
)

func newTestModel(t *testing.T, f *binfile.File) *Model {
	t.Helper()
	m, err := New(f)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m.width, m.height = 120, 30
	return m
}

func TestSectionsSortKeys(t *testing.T) {
	f := &binfile.File{Format: binfile.FormatELF, Sections: []binfile.Section{
		{Name: "zeta", Addr: 0x3000, Size: 10},
		{Name: "alpha", Addr: 0x1000, Size: 50},
		{Name: "mid", Addr: 0x2000, Size: 30},
	}}
	m := newTestModel(t, f)
	m.sections = f.Sections
	m.setMode(modeSections)
	m.recomputeSections()

	order := func() []string {
		var out []string
		for _, i := range m.sectionsFiltered {
			out = append(out, m.sections[i].Name)
		}
		return out
	}
	// Default is file/index order.
	if got := order(); got[0] != "zeta" || got[2] != "mid" {
		t.Fatalf("index order = %v", got)
	}
	// s: index → name.
	m.updateSections("s")
	if m.sectionsSort != secSortName {
		t.Fatalf("sort after s = %v, want name", m.sectionsSort)
	}
	if got := order(); got[0] != "alpha" || got[2] != "zeta" {
		t.Fatalf("name order = %v, want [alpha mid zeta]", got)
	}
	// s: name → address.
	m.updateSections("s")
	if got := order(); got[0] != "alpha" || got[2] != "zeta" { // addr 0x1000<0x2000<0x3000
		t.Fatalf("address order = %v", got)
	}
	// r: reverse the address sort.
	m.updateSections("r")
	if !m.sectionsSortDesc {
		t.Fatal("r did not set descending")
	}
	if got := order(); got[0] != "zeta" || got[2] != "alpha" {
		t.Fatalf("reversed address order = %v", got)
	}
	// s: address → size (still descending: 50,30,10 → alpha,mid,zeta).
	m.updateSections("s")
	if got := order(); got[0] != "alpha" || got[2] != "zeta" {
		t.Fatalf("size desc order = %v", got)
	}
}

func TestStringsSectionFilter(t *testing.T) {
	f := &binfile.File{Format: binfile.FormatELF}
	m := newTestModel(t, f)
	m.stringsList = []binfile.StringEntry{
		{Offset: 0x10, Len: 3, Section: ".rodata"},
		{Offset: 0x20, Len: 3, Section: ".data"},
		{Offset: 0x30, Len: 3, Section: ".rodata"},
	}
	m.buildStringSections()
	m.setMode(modeStrings)
	m.recomputeStrings()

	if len(m.stringsFiltered) != 3 {
		t.Fatalf("unfiltered = %d, want 3", len(m.stringsFiltered))
	}
	// alt+s turns the section filter on at the first section (.data, sorted).
	m.updateStrings("alt+s")
	if !m.stringsSecOn || m.stringsSec != ".data" {
		t.Fatalf("after alt+s: on=%v sec=%q", m.stringsSecOn, m.stringsSec)
	}
	if len(m.stringsFiltered) != 1 {
		t.Fatalf(".data filter = %d, want 1", len(m.stringsFiltered))
	}
	// alt+s again → .rodata (2 entries).
	m.updateStrings("alt+s")
	if m.stringsSec != ".rodata" || len(m.stringsFiltered) != 2 {
		t.Fatalf(".rodata filter: sec=%q n=%d", m.stringsSec, len(m.stringsFiltered))
	}
	// alt+s past the last section → off.
	m.updateStrings("alt+s")
	if m.stringsSecOn {
		t.Fatal("filter should be off after cycling past the last section")
	}
}

func TestSymbolsKeyMigration(t *testing.T) {
	f := &binfile.File{Format: binfile.FormatELF, Symbols: []binfile.Symbol{
		{Name: "alpha", Addr: 0x1000, Kind: binfile.SymFunc},
		{Name: "beta", Addr: 0x1100, Kind: binfile.SymObject},
	}}
	m := newTestModel(t, f)
	m.setMode(modeSymbols)
	m.recomputeSymbols()

	// s now cycles the sort field (was o); o is no longer a sort key.
	if m.symbolsSort != sortByName {
		t.Fatalf("precondition sort = %v", m.symbolsSort)
	}
	m.updateSymbols("o")
	if m.symbolsSort != sortByName {
		t.Fatal("o should no longer change the sort")
	}
	m.updateSymbols("s")
	if m.symbolsSort != sortByAddr {
		t.Fatalf("s did not advance sort, got %v", m.symbolsSort)
	}

	// ⌥t cycles the type filter (was y); y is no longer a filter key.
	m.updateSymbols("y")
	if m.symbolsKindOn {
		t.Fatal("y should no longer toggle the type filter")
	}
	m.updateSymbols("alt+t")
	if !m.symbolsKindOn {
		t.Fatal("alt+t did not enable the type filter")
	}

	// ⌥s cycles scope.
	if m.symbolsScope != scopeAll {
		t.Fatalf("precondition scope = %v", m.symbolsScope)
	}
	m.updateSymbols("alt+s")
	if m.symbolsScope == scopeAll {
		t.Fatal("alt+s did not advance the scope filter")
	}

	// Esc clears every filter.
	m.updateSymbols("esc")
	if m.symbolsKindOn || m.symbolsScope != scopeAll {
		t.Fatalf("esc did not clear filters: kind=%v scope=%v", m.symbolsKindOn, m.symbolsScope)
	}
}
