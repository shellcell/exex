package ui

import (
	"reflect"
	"testing"

	"github.com/rabarbra/exex/internal/binfile"
)

func TestSymbolScopeFilter(t *testing.T) {
	m := &Model{
		file: &binfile.File{Symbols: []binfile.Symbol{
			{Name: "my_func", Addr: 0x1000},                      // internal (defined here)
			{Name: "my_data", Addr: 0x2000},                      // internal
			{Name: "malloc", Addr: 0x3000, Library: "libc.so.6"}, // imported (PLT/GOT)
			{Name: "undef", Addr: 0},                             // undefined: neither internal nor imported
		}},
		symbolsState: symbolsState{},
	}
	m.symbolsFilter = newPromptInput("", "/ ")

	count := func(sc symbolScope) int {
		m.symbolsScope = sc
		m.recomputeSymbols()
		return len(m.symbolsFiltered)
	}

	if got := count(scopeAll); got != 4 {
		t.Fatalf("scope all = %d, want 4", got)
	}
	if got := count(scopeInternal); got != 2 {
		t.Fatalf("scope internal = %d, want 2 (defined here only)", got)
	}
	if got := count(scopeImported); got != 1 {
		t.Fatalf("scope imported = %d, want 1 (library-bound only)", got)
	}
}

func TestAbbrevBrackets(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain_name", "plain_name"},
		// Inner content of 5 bytes or fewer is kept verbatim; longer content collapses.
		{"Foo<A>", "Foo<A>"},
		{"Foo<int>", "Foo<int>"},
		{"Foo<int8>", "Foo<int8>"},   // inner "int8" = 4 bytes: kept
		{"Foo<int16>", "Foo<int16>"}, // inner "int16" = 5 bytes: kept
		{"Foo<uint16>", "Foo<...>"},  // inner "uint16" = 6 bytes: collapsed
		{"std::vector<int>::push_back", "std::vector<int>::push_back"},
		{"f<int, char>(a, b)", "f<...>(a, b)"}, // "<int, char>" collapses, "(a, b)" kept
		{"foo()", "foo()"},                     // empty parens unchanged
		{"std::map<K, V>::find()", "std::map<K, V>::find()"},
		{"a<b<c>>(d)", "a<b<c>>(d)"}, // both inners < 5
		{"vector<std::pair<int, long>>", "vector<...>"},
		{"x[1]", "x[1]"}, // square brackets untouched
		// C++ operator names: punctuation passed through, long groups still collapse.
		{"std::vector<int>::operator<<(std::ostream&)", "std::vector<int>::operator<<(...)"},
		{"Foo<Bar>::operator->()", "Foo<Bar>::operator->()"},
		{"std::map<K, V>::operator[](const K&)", "std::map<K, V>::operator[](...)"},
		// Trailing-return "->" arrows must not be read as a bracket close.
		{"f<A>(x: Int) -> Pair<A>", "f<A>(...) -> Pair<A>"},
		{"closure #1 <A>(B<A>) -> C<A> in foo.bar(baz: D<A>) -> E<A>",
			"closure #1 <A>(B<A>) -> C<A> in foo.bar(...) -> E<A>"},
	}
	for _, c := range cases {
		if got := abbrevBrackets(c.in); got != c.want {
			t.Errorf("abbrevBrackets(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSymbolAbbrevToggles(t *testing.T) {
	m := &Model{file: &binfile.File{Symbols: []binfile.Symbol{
		{Name: "alpha<Integer>", Addr: 0x1000},
		{Name: "beta<Character>", Addr: 0x2000},
	}}}
	m.symbolsFilter = newPromptInput("", "/ ")
	m.recomputeSymbols()

	label := func(row int) string { return m.symbolLabel(m.symbolsRows[row].node) }

	// Default: full names.
	if label(0) != "alpha<Integer>" {
		t.Fatalf("default label = %q, want alpha<Integer>", label(0))
	}
	// Global toggle abbreviates every row (both inners are > 5 bytes).
	m.toggleSymbolAbbrevAll()
	if label(0) != "alpha<...>" || label(1) != "beta<...>" {
		t.Fatalf("after toggle-all: %q, %q", label(0), label(1))
	}
	// Per-row override inverts just that row back to full.
	m.symbolsCur = 0
	m.toggleSymbolAbbrev()
	if label(0) != "alpha<Integer>" {
		t.Fatalf("per-row override label = %q, want alpha<Integer>", label(0))
	}
	if label(1) != "beta<...>" {
		t.Fatalf("sibling row changed: %q", label(1))
	}
	// A fresh global toggle clears per-row overrides (back to uniform, here expanded).
	m.toggleSymbolAbbrevAll()
	if label(0) != "alpha<Integer>" || label(1) != "beta<Character>" {
		t.Fatalf("after second toggle-all: %q, %q", label(0), label(1))
	}
}

func TestDisplaySymbolNameUsesGlobalAbbrevOnly(t *testing.T) {
	m := &Model{file: &binfile.File{Symbols: []binfile.Symbol{
		{Name: "raw", Demangled: "foo<LongArgList>(int, char)", Addr: 0x1000},
	}}}
	s := m.file.Symbols[0]

	// Off by default: the full demangled name (used by disasm/hex annotations).
	if got := m.displaySymbolName(s); got != "foo<LongArgList>(int, char)" {
		t.Fatalf("default = %q", got)
	}
	// Global toggle on: bracket lists collapse everywhere the helper is used.
	m.symbolsAbbrev = true
	if got := m.displaySymbolName(s); got != "foo<...>(...)" {
		t.Fatalf("global on = %q", got)
	}
	// Symbols-list per-row overrides are list-specific and must not leak here.
	m.symbolsAbbrevExcept = map[string]bool{"s0": true}
	if got := m.displaySymbolName(s); got != "foo<...>(...)" {
		t.Fatalf("per-row override leaked into shared helper = %q", got)
	}
}

func TestSymbolSortAndBind(t *testing.T) {
	m := &Model{file: &binfile.File{Symbols: []binfile.Symbol{
		{Name: "a", Addr: 0x1000, Size: 10, Bind: binfile.BindLocal},
		{Name: "b", Addr: 0x3000, Size: 50, Bind: binfile.BindGlobal},
		{Name: "c", Addr: 0x2000, Size: 30, Bind: binfile.BindGlobal},
	}}}
	m.symbolsFilter = newPromptInput("", "/ ")

	addrs := func() []uint64 {
		m.recomputeSymbols()
		out := make([]uint64, 0, len(m.symbolsFiltered))
		for _, idx := range m.symbolsFiltered {
			out = append(out, m.file.Symbols[idx].Addr)
		}
		return out
	}

	m.symbolsSort = sortByAddr
	if got := addrs(); !reflect.DeepEqual(got, []uint64{0x1000, 0x2000, 0x3000}) {
		t.Fatalf("sort by addr = %#x", got)
	}
	m.symbolsSort = sortBySize // ascending by size: a(10) c(30) b(50)
	if got := addrs(); !reflect.DeepEqual(got, []uint64{0x1000, 0x2000, 0x3000}) {
		t.Fatalf("sort by size = %#x", got)
	}
	m.symbolsSortDesc = true // reverse → largest first: b(50) c(30) a(10)
	if got := addrs(); !reflect.DeepEqual(got, []uint64{0x3000, 0x2000, 0x1000}) {
		t.Fatalf("sort by size desc = %#x", got)
	}
	m.symbolsSortDesc = false

	m.symbolsSort = sortByName
	m.symbolsBindOn = true
	m.symbolsBind = binfile.BindGlobal
	if got := len(addrs()); got != 2 {
		t.Fatalf("bind=global count = %d, want 2", got)
	}
}
