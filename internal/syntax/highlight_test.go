//go:build !lite

package syntax

import (
	"reflect"
	"strings"
	"testing"

	"charm.land/lipgloss/v2"
	"github.com/alecthomas/chroma/v2"

	"github.com/rabarbra/exex/internal/chromastyles"
)

func TestHighlightLines(t *testing.T) {

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

// TestAssemblySourceUsesGAS guards the .s/.S lexer choice: ArmAsm, GAS and R all
// register that extension at the same priority, so a plain lexers.Match can pick
// R and highlight assembly as the R language. lexerFor must force GAS.
func TestAssemblySourceUsesGAS(t *testing.T) {
	src := "	.globl main\nmain:\n	ret"
	for _, name := range []string{"foo.s", "foo.S", "crt0.S"} {
		l := lexerFor(name, src)
		if l == nil {
			t.Fatalf("%s: no lexer", name)
		}
		if got := l.Config().Name; got != "GAS" {
			t.Fatalf("%s: lexer = %q, want GAS", name, got)
		}
	}
}

func TestGoSourceUsesCuratedLexer(t *testing.T) {
	l := lexerFor("main.go", "package main\nfunc main() {}")
	if l == nil {
		t.Fatal("main.go: no lexer")
	}
	if got := l.Config().Name; got != "Go" {
		t.Fatalf("main.go: lexer = %q, want Go", got)
	}
}

func TestUnsupportedLanguageFallsBackToMinimal(t *testing.T) {
	src := []string{`defmodule Demo do`}
	if l := lexerFor("main.exs", strings.Join(src, "\n")); l != nil {
		t.Fatalf("main.exs: lexer = %q, want nil", l.Config().Name)
	}
	hl := HighlightLines("main.exs", src, defaultTheme)
	if len(hl) != len(src) {
		t.Fatalf("highlighted line count = %d, want %d", len(hl), len(src))
	}
	if got := stripANSI(hl[0]); got != src[0] {
		t.Fatalf("plain text = %q, want %q", got, src[0])
	}
	if !strings.Contains(hl[0], "\x1b[") {
		t.Fatal("expected minimal highlighter ANSI colour codes")
	}
}

func TestUnsupportedChromaStyleFallsBackToMinimal(t *testing.T) {
	// A name Chroma will never register, so curating more styles into
	// internal/chromasubset/styles.txt can't quietly invalidate this test.
	const style = "definitely-not-a-style"
	if _, ok := chromastyles.Lookup(style); ok {
		t.Fatalf("%s is bundled; pick an unbundled style for this test", style)
	}
	src := []string{"package main", "func main() {}"}
	got := HighlightLines("main.go", src, style)
	want := minimalHighlight("main.go", src, style)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unsupported style did not use minimal fallback\ngot:  %q\nwant: %q", got, want)
	}
}

func TestHighlightUnknownExtension(t *testing.T) {
	hl := HighlightLines("data.unknownext", []string{"\x00\x01\x02"}, defaultTheme)
	for _, line := range hl {
		_ = line
	}
}

func TestHighlighterNilReceiverAndInvalidTheme(t *testing.T) {
	src := []string{"package main", "func main() {}"}
	var h *Highlighter
	if got := h.Highlight("main.go", src); len(got) != len(src) {
		t.Fatalf("nil highlighter line count = %d, want %d", len(got), len(src))
	}
	got := HighlightLines("main.go", src, "definitely-not-a-theme")
	if len(got) != len(src) {
		t.Fatalf("invalid theme line count = %d, want %d", len(got), len(src))
	}
	for i := range src {
		if plain := stripANSI(got[i]); plain != src[i] {
			t.Fatalf("line %d plain text = %q, want %q", i, plain, src[i])
		}
	}
}

func TestHighlighterCachesByFilename(t *testing.T) {
	h := NewHighlighter("")
	first := h.Highlight("main.go", []string{"package main"})
	second := h.Highlight("main.go", []string{"package changed"})
	if len(first) != len(second) || stripANSI(second[0]) != "package main" {
		t.Fatalf("cached highlight = %q, want first source", second)
	}
}

// TestChromaDefaultTokenUsesThemeForeground covers the converter shared by the
// source pane and the disassembly pane (internal/ui/disasm_syntax.go).
func TestChromaDefaultTokenUsesThemeForeground(t *testing.T) {
	got := StyleEntryToLipgloss(chroma.StyleEntry{}, "#586e75").Render("x")
	want := lipgloss.NewStyle().Foreground(lipgloss.Color("#586e75")).Render("x")
	if got != want {
		t.Fatalf("default token style = %q, want %q", got, want)
	}
}

func TestChromaStyledTokenAttributes(t *testing.T) {
	e := chroma.StyleEntry{Bold: chroma.Yes, Italic: chroma.Yes, Underline: chroma.Yes}
	got := StyleEntryToLipgloss(e, "#586e75").Render("x")
	want := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#586e75")).
		Bold(true).Italic(true).Underline(true).
		Render("x")
	if got != want {
		t.Fatalf("styled token = %q, want %q", got, want)
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
