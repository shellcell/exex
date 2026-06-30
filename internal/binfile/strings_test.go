package binfile

import (
	"io"
	"testing"
)

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
		found[f.StringText(s)] = s.Offset
		if s.HasAddr {
			t.Errorf("string %q reported an address with no sections loaded", f.StringText(s))
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

func TestStringsCachesExtraction(t *testing.T) {
	f := &File{raw: []byte("hello\x00world")}
	first := f.Strings()
	second := f.Strings()
	if len(first) != len(second) || first[0] != second[0] {
		t.Fatalf("Strings cache changed: first=%#v second=%#v", first, second)
	}
}

func TestScanStringsDoesNotPopulateCache(t *testing.T) {
	f := &File{raw: []byte("hello\x00world\x00tiny")}
	var got []string
	if err := f.ScanStrings(func(e StringEntry) error {
		got = append(got, f.StringText(e))
		return nil
	}); err != nil {
		t.Fatalf("ScanStrings: %v", err)
	}
	if len(got) != 3 || got[0] != "hello" || got[1] != "world" || got[2] != "tiny" {
		t.Fatalf("ScanStrings = %#v, want hello/world/tiny", got)
	}
	if f.strings != nil {
		t.Fatalf("ScanStrings populated cache: %#v", f.strings)
	}
}

func TestScanStringsParallelOrderedAndNoCache(t *testing.T) {
	raw := make([]byte, parallelStringScanChunk*3+128)
	copy(raw[10:], "first")
	copy(raw[parallelStringScanChunk-2:], "boundary")
	copy(raw[parallelStringScanChunk+20:], "second")
	f := &File{raw: raw}
	var got []string
	if err := f.scanStringsParallel(raw, nil, 2, func(e StringEntry) error {
		got = append(got, f.StringText(e))
		return nil
	}); err != nil {
		t.Fatalf("scanStringsParallel: %v", err)
	}
	want := []string{"first", "boundary", "second"}
	if len(got) != len(want) {
		t.Fatalf("strings = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("strings = %#v, want %#v", got, want)
		}
	}
	if f.strings != nil {
		t.Fatalf("parallel scan populated cache: %#v", f.strings)
	}
}

func TestScanStringsParallelClosedPipe(t *testing.T) {
	raw := make([]byte, parallelStringScanChunk*2+128)
	copy(raw[0:], "first")
	copy(raw[parallelStringScanChunk+10:], "second")
	f := &File{raw: raw}
	n := 0
	if err := f.scanStringsParallel(raw, nil, 2, func(StringEntry) error {
		n++
		return io.ErrClosedPipe
	}); err != nil {
		t.Fatalf("closed pipe should be clean, got %v", err)
	}
	if n != 1 {
		t.Fatalf("emitted %d entries before closed pipe, want 1", n)
	}
	if f.strings != nil {
		t.Fatalf("parallel closed-pipe scan populated cache: %#v", f.strings)
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
		if f.StringText(s) == "mapped!" {
			if !s.HasAddr || s.Addr != 0x4000 || s.Section != "__cstring" {
				t.Fatalf("bad mapping: %+v", s)
			}
			return
		}
	}
	t.Fatal(`"mapped!" not found`)
}
