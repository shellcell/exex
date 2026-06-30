package binfile

import "testing"

// TestCompactAddrWidth checks the compact-address display: a 64-bit binary whose
// addresses all fit in 32 bits narrows to 8 hex digits when asked, a higher-half
// binary keeps the full 16, and the true pointer size never changes.
func TestCompactAddrWidth(t *testing.T) {
	// 64-bit, low addresses (everything under 4 GiB).
	low := &File{addrWidth: 16, entry: 0x1000, Sections: []Section{{Addr: 0x1000, Size: 0x4000}}}
	if got := low.AddrHexWidth(); got != 16 {
		t.Fatalf("default width = %d, want 16 (compact off)", got)
	}
	if got := low.PointerBytes(); got != 8 {
		t.Fatalf("PointerBytes = %d, want 8", got)
	}
	low.SetCompactAddr(true)
	if got := low.AddrHexWidth(); got != 8 {
		t.Fatalf("compact width = %d, want 8 (addresses fit in 32 bits)", got)
	}
	if got := low.PointerBytes(); got != 8 {
		t.Fatalf("PointerBytes after compact = %d, want 8 (word size unchanged)", got)
	}
	low.SetCompactAddr(false)
	if got := low.AddrHexWidth(); got != 16 {
		t.Fatalf("width after compact off = %d, want 16", got)
	}

	// 64-bit higher-half kernel: a symbol up in 0xffffffff… keeps the full width
	// even with compaction requested.
	high := &File{addrWidth: 16, Sections: []Section{{Addr: 0x100000, Size: 0x1000}},
		Symbols: []Symbol{{Addr: 0xffffffffc0101000}}}
	high.SetCompactAddr(true)
	if got := high.AddrHexWidth(); got != 16 {
		t.Fatalf("higher-half width = %d, want 16 (top half is non-zero)", got)
	}

	// 32-bit binary: already 8 digits, compaction is a no-op, pointers are 4 bytes.
	w32 := &File{addrWidth: 8, Sections: []Section{{Addr: 0x1000, Size: 0x100}}}
	w32.SetCompactAddr(true)
	if got := w32.AddrHexWidth(); got != 8 {
		t.Fatalf("32-bit width = %d, want 8", got)
	}
	if got := w32.PointerBytes(); got != 4 {
		t.Fatalf("32-bit PointerBytes = %d, want 4", got)
	}
}
