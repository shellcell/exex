package binfile

import "testing"

func TestFinalizeSymbolsInfersSizesOnCanonicalSymbols(t *testing.T) {
	f := &File{
		Sections: []Section{{Name: ".text", Addr: 0x1000, Size: 0x100, Alloc: true, Exec: true}},
		Symbols: []Symbol{
			{Name: "b", Addr: 0x1040, Kind: SymFunc},
			{Name: "a", Addr: 0x1000, Kind: SymFunc},
		},
	}

	f.finalizeSymbols()

	var a Symbol
	for _, sym := range f.Symbols {
		if sym.Name == "a" {
			a = sym
			break
		}
	}
	if a.Size != 0x40 {
		t.Fatalf("canonical symbol size = 0x%x, want 0x40", a.Size)
	}
	if sym, ok := f.SymbolAt(0x1010); !ok || sym.Name != "a" || sym.Size != a.Size {
		t.Fatalf("SymbolAt = %#v, %v; want canonical a with inferred size", sym, ok)
	}
}

func TestSymbolAtPrefersSizedSymbolOverSameAddressAlias(t *testing.T) {
	f := &File{
		Sections: []Section{{Name: ".text", Addr: 0x1000, Size: 0x100, Alloc: true, Exec: true}},
		Symbols: []Symbol{
			{Name: "alias", Addr: 0x1000, Kind: SymOther},
			{Name: "func", Addr: 0x1000, Size: 0x40, Kind: SymFunc},
			{Name: "next", Addr: 0x1080, Kind: SymFunc},
		},
	}

	f.finalizeSymbols()

	for _, sym := range f.Symbols {
		if sym.Name == "alias" && sym.Size != 0 {
			t.Fatalf("alias size = 0x%x, want exact-only alias", sym.Size)
		}
	}
	for _, addr := range []uint64{0x1000, 0x1010} {
		if sym, ok := f.SymbolAt(addr); !ok || sym.Name != "func" {
			t.Fatalf("SymbolAt(0x%x) = %#v, %v; want func", addr, sym, ok)
		}
	}
}

func TestSymbolDisplay(t *testing.T) {
	if got := (Symbol{Name: "_Z3foov", Demangled: "foo()"}).Display(); got != "foo()" {
		t.Fatalf("Display demangled = %q, want foo()", got)
	}
	if got := (Symbol{Name: "main"}).Display(); got != "main" {
		t.Fatalf("Display raw = %q, want main", got)
	}
}

func TestSymbolsInRangeHandlesBoundsAndOverlaps(t *testing.T) {
	f := &File{Symbols: []Symbol{
		{Name: "a", Addr: 0x1000, Size: 0x10},
		{Name: "b", Addr: 0x1020},
		{Name: "c", Addr: 0x1030, Size: 0x08},
	}}
	f.symByAddr = []int{0, 1, 2}

	tests := []struct {
		name string
		from uint64
		to   uint64
		want []string
	}{
		{name: "starts before first", from: 0x0, to: 0x1001, want: []string{"a"}},
		{name: "overlaps previous", from: 0x1008, to: 0x100c, want: []string{"a"}},
		{name: "zero sized at start", from: 0x1020, to: 0x1021, want: []string{"b"}},
		{name: "last symbol", from: 0x1030, to: 0x1040, want: []string{"c"}},
		{name: "after last", from: 0x1040, to: 0x1050},
		{name: "empty range", from: 0x1020, to: 0x1020},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := f.SymbolsInRange(tt.from, tt.to)
			if len(got) != len(tt.want) {
				t.Fatalf("SymbolsInRange length = %d, want %d (%#v)", len(got), len(tt.want), got)
			}
			for i, want := range tt.want {
				if got[i].Name != want {
					t.Fatalf("symbol %d = %q, want %q", i, got[i].Name, want)
				}
			}
			it := f.SymbolRangeIter(tt.from, tt.to)
			var iterGot []Symbol
			for {
				sym, ok := it.Next()
				if !ok {
					break
				}
				iterGot = append(iterGot, sym)
			}
			if len(iterGot) != len(got) {
				t.Fatalf("SymbolRangeIter length = %d, want %d (%#v)", len(iterGot), len(got), iterGot)
			}
			for i := range got {
				if iterGot[i] != got[i] {
					t.Fatalf("iterator symbol %d = %#v, want %#v", i, iterGot[i], got[i])
				}
			}
		})
	}
}

func TestNextPrevSymbol(t *testing.T) {
	f := &File{Symbols: []Symbol{
		{Name: "a", Addr: 0x1000, Kind: SymFunc},
		{Name: "b", Addr: 0x1010, Kind: SymObject},
		{Name: "c", Addr: 0x1020, Kind: SymFunc},
	}}
	f.symByAddr = []int{0, 1, 2}
	if got, ok := f.NextSymbol(0x1000, nil); !ok || got.Name != "b" {
		t.Fatalf("NextSymbol = %#v, %v; want b", got, ok)
	}
	if got, ok := f.NextSymbol(0x1000, func(s Symbol) bool { return s.Kind == SymFunc }); !ok || got.Name != "c" {
		t.Fatalf("NextSymbol func = %#v, %v; want c", got, ok)
	}
	if got, ok := f.PrevSymbol(0x1020, nil); !ok || got.Name != "b" {
		t.Fatalf("PrevSymbol = %#v, %v; want b", got, ok)
	}
	if _, ok := f.PrevSymbol(0x1000, nil); ok {
		t.Fatal("PrevSymbol before first succeeded, want false")
	}
}
