package binfile

import "testing"

func TestExtractStrings(t *testing.T) {
	// "ab" is below minString and must be dropped; the two long runs must be
	// found with their correct offsets.
	raw := []byte("\x00\x00Hello, world!\x00\x01ab\x00MoreText")
	f := &File{raw: raw}
	got := f.extractStrings()

	want := map[string]uint64{
		"Hello, world!": 2,
		"MoreText":      uint64(len(raw) - len("MoreText")),
	}
	found := map[string]uint64{}
	for _, s := range got {
		found[s.Text] = s.Offset
		if s.HasAddr {
			t.Errorf("string %q reported an address with no sections loaded", s.Text)
		}
	}
	for text, off := range want {
		if got, ok := found[text]; !ok {
			t.Errorf("missing string %q", text)
		} else if got != off {
			t.Errorf("string %q offset = %d, want %d", text, got, off)
		}
	}
	if _, ok := found["ab"]; ok {
		t.Error(`short run "ab" should not be reported`)
	}
}

func TestExtractStringsMapsAddress(t *testing.T) {
	// A section whose file bytes cover the string maps it to a virtual address.
	raw := make([]byte, 64)
	copy(raw[16:], "mapped!")
	f := &File{
		raw: raw,
		Sections: []Section{{
			Name:     "__cstring",
			Addr:     0x4000,
			Size:     48,
			Offset:   16,
			FileSize: 48,
			Alloc:    true,
		}},
	}
	for _, s := range f.extractStrings() {
		if s.Text == "mapped!" {
			if !s.HasAddr || s.Addr != 0x4000 || s.Section != "__cstring" {
				t.Fatalf("bad mapping: %+v", s)
			}
			return
		}
	}
	t.Fatal(`"mapped!" not found`)
}
