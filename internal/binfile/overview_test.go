package binfile

import "testing"

func TestComputeOverview(t *testing.T) {
	f := &File{
		raw: make([]byte, 100),
		Sections: []Section{
			{Name: "__text", Addr: 0x1000, Size: 0x200, Offset: 0, FileSize: 0x200, Alloc: true, Exec: true},
			{Name: "__data", Addr: 0x2000, Size: 0x100, Offset: 0x200, FileSize: 0x100, Alloc: true, Write: true},
			{Name: "__debug", Addr: 0, Size: 0x50, Alloc: false}, // unmapped, ignored
		},
		Symbols: []Symbol{
			{Name: "___stack_chk_fail"},
			{Name: "___memcpy_chk"},
			{Name: "main"},
		},
	}
	f.computeOverview()
	in := f.Info
	if in.FileSize != 100 {
		t.Errorf("FileSize = %d, want 100", in.FileSize)
	}
	if in.MappedLo != 0x1000 || in.MappedHi != 0x2100 {
		t.Errorf("mapped range = 0x%x–0x%x, want 0x1000–0x2100", in.MappedLo, in.MappedHi)
	}
	if in.CodeSize != 0x200 {
		t.Errorf("CodeSize = 0x%x, want 0x200", in.CodeSize)
	}
	if !in.Canary {
		t.Error("expected Canary=true from __stack_chk_fail")
	}
	if !in.Fortify {
		t.Error("expected Fortify=true from __memcpy_chk")
	}
}

func TestDwarfLangName(t *testing.T) {
	tests := map[int64]string{
		0x0005: "COBOL",
		0x000a: "Modula-2",
		0x0013: "D",
		0x0018: "Haskell",
		0x001f: "Julia",
		0x0022: "Fortran",
		0x0027: "Zig",
		0x002c: "C",
		0x0032: "C#",
		0x0033: "Mojo",
		0x003d: "Metal",
		0xdead: "",
	}
	for code, want := range tests {
		if got := dwarfLangName(code); got != want {
			t.Fatalf("dwarfLangName(0x%x) = %q, want %q", code, got, want)
		}
	}
}
