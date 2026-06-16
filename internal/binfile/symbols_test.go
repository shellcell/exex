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
