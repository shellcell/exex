package ui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

func TestHighlightLines(t *testing.T) {
	// Force a colour profile so Render emits ANSI even though the test's stdout
	// isn't a TTY (otherwise lipgloss falls back to plain output).
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
	hl := highlightLines("main.c", src)
	if hl == nil {
		t.Fatal("no lexer matched main.c")
	}
	if len(hl) != len(src) {
		t.Fatalf("highlighted line count = %d, want %d", len(hl), len(src))
	}
	// Stripping the ANSI must recover the original text on every line.
	for i := range src {
		if got := stripANSI(hl[i]); got != src[i] {
			t.Fatalf("line %d plain text = %q, want %q", i, got, src[i])
		}
	}
	// And at least some colour must have been applied.
	if !strings.Contains(strings.Join(hl, ""), "\x1b[") {
		t.Fatal("expected ANSI colour codes in highlighted output")
	}
}

func TestHighlightUnknownExtension(t *testing.T) {
	// An unknown, content-free extension should simply yield no highlighting
	// rather than panicking, so the caller can fall back to plain text.
	hl := highlightLines("data.unknownext", []string{"\x00\x01\x02"})
	for _, line := range hl {
		_ = line // nil or best-effort; just must not panic
	}
}
