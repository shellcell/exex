package bytesearch

import (
	"bytes"
	"testing"
)

func TestParsePatternAuto(t *testing.T) {
	cases := []struct {
		in   string
		want []byte
	}{
		{"de ad be ef", []byte{0xde, 0xad, 0xbe, 0xef}},
		{"0xcafe", []byte{0xca, 0xfe}},
		{`"hi"`, []byte("hi")},
		{"hello", []byte("hello")}, // not all hex -> text
		{"abc", []byte("abc")},     // odd length -> text
		{"DEAD", []byte{0xde, 0xad}},
		{" hi ", []byte(" hi ")},
		{"de ad ", []byte("de ad ")},
	}
	for _, c := range cases {
		if got := ParsePattern(c.in, ModeAuto); !bytes.Equal(got, c.want) {
			t.Errorf("ParsePattern(%q, ModeAuto) = % x, want % x", c.in, got, c.want)
		}
	}
}

func TestParsePatternModes(t *testing.T) {
	if got := ParsePattern("DEAD", ModeText); !bytes.Equal(got, []byte("DEAD")) {
		t.Fatalf("text mode = % x, want literal text", got)
	}
	if got := ParsePattern("de ad", ModeHex); !bytes.Equal(got, []byte{0xde, 0xad}) {
		t.Fatalf("hex mode = % x, want de ad", got)
	}
	if got := ParsePattern("abc", ModeHex); got != nil {
		t.Fatalf("invalid hex = % x, want nil", got)
	}
	if got := ParsePattern("0XCA\tFE", ModeHex); !bytes.Equal(got, []byte{0xca, 0xfe}) {
		t.Fatalf("uppercase prefix/tab hex = % x, want ca fe", got)
	}
}

func TestModeStringAndNextMode(t *testing.T) {
	if got := ModeAuto.String(); got != "auto" {
		t.Fatalf("ModeAuto.String = %q", got)
	}
	if got := ModeText.String(); got != "text" {
		t.Fatalf("ModeText.String = %q", got)
	}
	if got := ModeHex.String(); got != "hex" {
		t.Fatalf("ModeHex.String = %q", got)
	}
	if got := NextMode(ModeAuto); got != ModeText {
		t.Fatalf("NextMode(auto) = %v, want text", got)
	}
	if got := NextMode(ModeText); got != ModeHex {
		t.Fatalf("NextMode(text) = %v, want hex", got)
	}
	if got := NextMode(ModeHex); got != ModeAuto {
		t.Fatalf("NextMode(hex) = %v, want auto", got)
	}
}

func TestFindBytes(t *testing.T) {
	data := []byte("abcXYabcXY")
	pat := []byte("abc")

	if got := FindBytes(data, pat, 0, true); got != 0 {
		t.Errorf("forward from 0 = %d, want 0", got)
	}
	if got := FindBytes(data, pat, 1, true); got != 5 {
		t.Errorf("forward from 1 = %d, want 5", got)
	}
	if got := FindBytes(data, pat, len(data)-1, false); got != 5 {
		t.Errorf("backward from end = %d, want 5", got)
	}
	if got := FindBytes(data, pat, 4, false); got != 0 {
		t.Errorf("backward from 4 = %d, want 0", got)
	}
	if got := FindBytes(data, []byte("zzz"), 0, true); got != -1 {
		t.Errorf("missing pattern = %d, want -1", got)
	}
	if got := FindBytes(data, pat, 8, true); got != -1 {
		t.Errorf("forward past last match = %d, want -1", got)
	}
	if got := FindBytes(data, pat, -100, true); got != 0 {
		t.Errorf("forward negative start = %d, want 0", got)
	}
	if got := FindBytes(data, pat, 100, false); got != 5 {
		t.Errorf("backward oversized start = %d, want 5", got)
	}
	if got := FindBytes(data, nil, 0, true); got != -1 {
		t.Errorf("empty pattern = %d, want -1", got)
	}
}

func TestFindBytesFold(t *testing.T) {
	data := []byte("The Quick Brown FOX")
	// insensitive finds regardless of case
	if i := FindBytesFold(data, []byte("quick"), 0, true, true); i != 4 {
		t.Errorf("fold forward: got %d, want 4", i)
	}
	if i := FindBytesFold(data, []byte("fox"), 0, true, true); i != 16 {
		t.Errorf("fold fox: got %d, want 16", i)
	}
	// sensitive (fold=false) is exact
	if i := FindBytesFold(data, []byte("quick"), 0, true, false); i != -1 {
		t.Errorf("no-fold should not match lowercase: got %d, want -1", i)
	}
	if i := FindBytesFold(data, []byte("Quick"), 0, true, false); i != 4 {
		t.Errorf("no-fold exact: got %d, want 4", i)
	}
	// backward
	if i := FindBytesFold(data, []byte("BROWN"), 0x20, false, true); i != 10 {
		t.Errorf("fold backward: got %d, want 10", i)
	}
}

func TestIsTextPattern(t *testing.T) {
	if !IsTextPattern("hello", ModeAuto) {
		t.Error("plain word should be text")
	}
	if IsTextPattern("deadbeef", ModeAuto) {
		t.Error("bare hex should be a byte pattern, not text")
	}
	if !IsTextPattern("deadbeef", ModeText) {
		t.Error("explicit text mode is always text")
	}
	if IsTextPattern("de ad be ef", ModeHex) {
		t.Error("hex mode is never text")
	}
}
