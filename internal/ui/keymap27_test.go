package ui

// Tests for the #27 keymap pass: the breaking re-bindings (copy → ⇧, filters →
// ⌥, sort-cycle on s) plus the new Sections sort and Strings section filter.

import (
	"testing"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/ui/views/sections"
	"github.com/rabarbra/exex/internal/ui/views/symbols"
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
	m.sections.Sections = f.Sections
	m.setMode(modeSections)
	m.sections.Recompute()

	order := func() []string {
		var out []string
		for _, i := range m.sections.Filtered {
			out = append(out, m.sections.Sections[i].Name)
		}
		return out
	}
	// Default is file/index order.
	if got := order(); got[0] != "zeta" || got[2] != "mid" {
		t.Fatalf("index order = %v", got)
	}
	// s: index → name.
	m.sections.Update(m.viewContext(), m, "s")
	if m.sections.Sort != sections.SortName {
		t.Fatalf("sort after s = %v, want name", m.sections.Sort)
	}
	if got := order(); got[0] != "alpha" || got[2] != "zeta" {
		t.Fatalf("name order = %v, want [alpha mid zeta]", got)
	}
	// s: name → address.
	m.sections.Update(m.viewContext(), m, "s")
	if got := order(); got[0] != "alpha" || got[2] != "zeta" { // addr 0x1000<0x2000<0x3000
		t.Fatalf("address order = %v", got)
	}
	// r: reverse the address sort.
	m.sections.Update(m.viewContext(), m, "r")
	if !m.sections.SortDesc {
		t.Fatal("r did not set descending")
	}
	if got := order(); got[0] != "zeta" || got[2] != "alpha" {
		t.Fatalf("reversed address order = %v", got)
	}
	// s: address → size (still descending: 50,30,10 → alpha,mid,zeta).
	m.sections.Update(m.viewContext(), m, "s")
	if got := order(); got[0] != "alpha" || got[2] != "zeta" {
		t.Fatalf("size desc order = %v", got)
	}
}

func TestStringsSectionFilter(t *testing.T) {
	f := &binfile.File{Format: binfile.FormatELF}
	m := newTestModel(t, f)
	m.strs.List = []binfile.StringEntry{
		{Offset: 0x10, Len: 3, Section: ".rodata"},
		{Offset: 0x20, Len: 3, Section: ".data"},
		{Offset: 0x30, Len: 3, Section: ".rodata"},
	}
	m.strs.BuildSections()
	m.setMode(modeStrings)
	m.strs.Recompute(m.viewContext())

	if len(m.strs.Filtered) != 3 {
		t.Fatalf("unfiltered = %d, want 3", len(m.strs.Filtered))
	}
	// ctrl+s turns the section filter on at the first section (.data, sorted).
	m.strs.Update(m.viewContext(), m, "ctrl+s")
	if !m.strs.SecOn || m.strs.Sec != ".data" {
		t.Fatalf("after ctrl+s: on=%v sec=%q", m.strs.SecOn, m.strs.Sec)
	}
	if len(m.strs.Filtered) != 1 {
		t.Fatalf(".data filter = %d, want 1", len(m.strs.Filtered))
	}
	// ctrl+s again → .rodata (2 entries).
	m.strs.Update(m.viewContext(), m, "ctrl+s")
	if m.strs.Sec != ".rodata" || len(m.strs.Filtered) != 2 {
		t.Fatalf(".rodata filter: sec=%q n=%d", m.strs.Sec, len(m.strs.Filtered))
	}
	// ctrl+s past the last section → off.
	m.strs.Update(m.viewContext(), m, "ctrl+s")
	if m.strs.SecOn {
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
	m.symbols.Recompute(m.viewContext())

	// s now cycles the sort field (was o); o is no longer a sort key.
	if m.symbols.Sort != symbols.SortName {
		t.Fatalf("precondition sort = %v", m.symbols.Sort)
	}
	m.symbols.Update(m.viewContext(), m, "o")
	if m.symbols.Sort != symbols.SortName {
		t.Fatal("o should no longer change the sort")
	}
	m.symbols.Update(m.viewContext(), m, "s")
	if m.symbols.Sort != symbols.SortAddr {
		t.Fatalf("s did not advance sort, got %v", m.symbols.Sort)
	}

	// ⌥t cycles the type filter (was y); y is no longer a filter key.
	m.symbols.Update(m.viewContext(), m, "y")
	if m.symbols.KindOn {
		t.Fatal("y should no longer toggle the type filter")
	}
	m.symbols.Update(m.viewContext(), m, "ctrl+t")
	if !m.symbols.KindOn {
		t.Fatal("ctrl+t did not enable the type filter")
	}

	// ⌥s cycles scope.
	if m.symbols.Scope != symbols.ScopeAll {
		t.Fatalf("precondition scope = %v", m.symbols.Scope)
	}
	m.symbols.Update(m.viewContext(), m, "ctrl+s")
	if m.symbols.Scope == symbols.ScopeAll {
		t.Fatal("ctrl+s did not advance the scope filter")
	}

	// Esc clears every filter.
	m.symbols.Update(m.viewContext(), m, "esc")
	if m.symbols.KindOn || m.symbols.Scope != symbols.ScopeAll {
		t.Fatalf("esc did not clear filters: kind=%v scope=%v", m.symbols.KindOn, m.symbols.Scope)
	}
}
