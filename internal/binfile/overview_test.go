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
