package syntax

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

func TestHighlightLines(t *testing.T) {
	old := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	defer lipgloss.SetColorProfile(old)

	src := []string{
		"#include <stdio.h>",
		"int main(void) {",
		"    printf(\"hi\\n\");",
		"    return 0;",
		"}",
	}
	hl := HighlightLines("main.c", src, defaultTheme)
	if hl == nil {
		t.Fatal("no lexer matched main.c")
	}
	if len(hl) != len(src) {
		t.Fatalf("highlighted line count = %d, want %d", len(hl), len(src))
	}
	for i := range src {
		if got := stripANSI(hl[i]); got != src[i] {
			t.Fatalf("line %d plain text = %q, want %q", i, got, src[i])
		}
	}
	if !strings.Contains(strings.Join(hl, ""), "\x1b[") {
		t.Fatal("expected ANSI colour codes in highlighted output")
	}
}

func TestHighlightUnknownExtension(t *testing.T) {
	hl := HighlightLines("data.unknownext", []string{"\x00\x01\x02"}, defaultTheme)
	for _, line := range hl {
		_ = line
	}
}

func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && (s[j] < 0x40 || s[j] > 0x7e) {
				j++
			}
			if j < len(s) {
				j++
			}
			i = j - 1
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
