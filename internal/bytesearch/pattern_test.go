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
}
