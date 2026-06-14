package ui

import (
	"bytes"
	"testing"
)

func TestSearchPattern(t *testing.T) {
	cases := []struct {
		in   string
		want []byte
	}{
		{"de ad be ef", []byte{0xde, 0xad, 0xbe, 0xef}},
		{"0xcafe", []byte{0xca, 0xfe}},
		{`"hi"`, []byte("hi")},
		{"hello", []byte("hello")}, // not all hex → text
		{"abc", []byte("abc")},     // odd length → text
		{"DEAD", []byte{0xde, 0xad}},
	}
	for _, c := range cases {
		if got := searchPattern(c.in); !bytes.Equal(got, c.want) {
			t.Errorf("searchPattern(%q) = % x, want % x", c.in, got, c.want)
		}
	}
}

func TestFindBytes(t *testing.T) {
	data := []byte("abcXYabcXY")
	pat := []byte("abc")

	if got := findBytes(data, pat, 0, true); got != 0 {
		t.Errorf("forward from 0 = %d, want 0", got)
	}
	if got := findBytes(data, pat, 1, true); got != 5 {
		t.Errorf("forward from 1 = %d, want 5", got)
	}
	if got := findBytes(data, pat, len(data)-1, false); got != 5 {
		t.Errorf("backward from end = %d, want 5", got)
	}
	if got := findBytes(data, pat, 4, false); got != 0 {
		t.Errorf("backward from 4 = %d, want 0", got)
	}
	if got := findBytes(data, []byte("zzz"), 0, true); got != -1 {
		t.Errorf("missing pattern = %d, want -1", got)
	}
	if got := findBytes(data, pat, 8, true); got != -1 {
		t.Errorf("forward past last match = %d, want -1", got)
	}
}
