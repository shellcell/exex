package ui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"

	"github.com/shellcell/exex/internal/binfile"
	"github.com/shellcell/exex/internal/ui/views/hexraw"
)

func TestInspectorBannerDecodes(t *testing.T) {
	m := &Model{
		theme:       DefaultTheme(),
		file:        &binfile.File{Info: &binfile.Info{ByteOrder: "little-endian"}},
		layoutState: layoutState{width: 120, height: 10},
	}
	data := rawBytes([]byte{0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0})
	m.byteViews.RawData = []byte(data)
	m.byteViews.Inspect = true
	got := ansi.Strip(m.byteViews.Render(m.viewContextPtr(), hexraw.Raw))
	for _, want := range []string{"u8 0x78", "u16 0x5678", "u32 0x12345678", "u64 0x0000000012345678"} {
		if !strings.Contains(got, want) {
			t.Fatalf("inspector banner missing %q in %q", want, got)
		}
	}
}

func TestPointerWordStart(t *testing.T) {
	m := &Model{file: &binfile.File{}} // 64-bit default → 8-byte words
	if got := m.byteViews.PointerWordStart(m.viewContextPtr(), 0x1000, 0x40); got != 0x40 {
		t.Fatalf("aligned cursor = %d, want 0x40", got)
	}
	if got := m.byteViews.PointerWordStart(m.viewContextPtr(), 0x1003, 0x43); got != 0x40 {
		t.Fatalf("mid-word cursor = %d, want 0x40 (snapped to word start)", got)
	}
}

func TestReadPointerEndianness(t *testing.T) {
	le := &Model{file: &binfile.File{Info: &binfile.Info{ByteOrder: "little-endian"}}}
	be := &Model{file: &binfile.File{Info: &binfile.Info{ByteOrder: "big-endian"}}}
	data := rawBytes([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
	if v, ok := le.byteViews.ReadPointer(le.viewContextPtr(), data, 0); !ok || v != 0x0807060504030201 {
		t.Fatalf("little-endian pointer = %#x (ok=%v)", v, ok)
	}
	if v, ok := be.byteViews.ReadPointer(be.viewContextPtr(), data, 0); !ok || v != 0x0102030405060708 {
		t.Fatalf("big-endian pointer = %#x (ok=%v)", v, ok)
	}
	if _, ok := le.byteViews.ReadPointer(le.viewContextPtr(), data, 4); ok {
		t.Fatal("readPointer should fail when the word doesn't fit")
	}
}
