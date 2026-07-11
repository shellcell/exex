package ui

import (
	"testing"

	"github.com/rabarbra/exex/internal/binfile"
)

func TestDisplaySymbolNameUsesGlobalAbbrevOnly(t *testing.T) {
	m := &Model{file: &binfile.File{Symbols: []binfile.Symbol{
		{Name: "raw", Demangled: "foo<LongArgList>(int, char)", Addr: 0x1000},
	}}}
	m.symbols.Filter = newPromptInput("", "/ ")
	s := m.file.Symbols[0]

	// Off by default: the full demangled name (used by disasm/hex annotations).
	if got := m.displaySymbolName(s); got != "foo<LongArgList>(int, char)" {
		t.Fatalf("default = %q", got)
	}
	// Global toggle on: bracket lists collapse everywhere the helper is used.
	m.symbols.Abbrev = true
	if got := m.displaySymbolName(s); got != "foo<...>(...)" {
		t.Fatalf("global on = %q", got)
	}
	// Symbols-list per-row overrides are list-specific and must not leak here.
	m.symbols.Recompute(m.viewContext())
	m.symbols.Cur = 0
	m.symbols.ToggleAbbrev(m) // sets a per-row override on row 0
	if got := m.displaySymbolName(s); got != "foo<...>(...)" {
		t.Fatalf("per-row override leaked into shared helper = %q", got)
	}
}
