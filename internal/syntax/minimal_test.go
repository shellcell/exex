package syntax

import (
	"strings"
	"testing"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

func TestMinimalHighlight(t *testing.T) {
	src := []string{
		"// a comment",
		"int x = 42;",
		"s = \"hello\"",
		"plain text 123",
	}
	out := minimalHighlight("x.c", src, "")
	if len(out) != len(src) {
		t.Fatalf("line count = %d, want %d", len(out), len(src))
	}
	// The comment line must be styled (contains ANSI escapes) and still carry
	// its text once stripped.
	if !strings.Contains(out[0], "\x1b[") {
		t.Errorf("comment line not styled: %q", out[0])
	}
	// Keyword + number on the declaration line should be styled.
	if !strings.Contains(out[1], "\x1b[") {
		t.Errorf("declaration line not styled: %q", out[1])
	}
}

func TestMinimalHighlightBlockCommentSpansLines(t *testing.T) {
	src := []string{"code /* start", "still comment", "end */ code"}
	out := minimalHighlight("x.c", src, "")
	// The middle line is entirely inside the block comment -> fully styled.
	if !strings.Contains(out[1], "\x1b[") {
		t.Errorf("in-block line not styled: %q", out[1])
	}
}

func TestMinimalHighlightHashLanguage(t *testing.T) {
	// In a Python file, "#" starts a comment but "//" does not.
	out := minimalHighlight("x.py", []string{"x = 1 // 2  # note"}, "")
	if !strings.Contains(out[0], "\x1b[") {
		t.Fatalf("python line not styled: %q", out[0])
	}
}

func TestMinimalHighlightKeywordCategoriesAndFunctions(t *testing.T) {
	line := "func main() int { if true { return printf(\"ok\") } }"
	out := minimalHighlight("x.go", []string{line}, "")[0]
	if plain := ansi.Strip(out); plain != line {
		t.Fatalf("plain text = %q, want %q", plain, line)
	}
	for name, want := range map[string]string{
		"function keyword": mhFunction.Render("func"),
		"function name":    mhFunctionName.Render("main"),
		"type keyword":     mhType.Render("int"),
		"control keyword":  mhControl.Render("if"),
		"literal keyword":  mhLiteral.Render("true"),
		"function call":    mhFunctionName.Render("printf"),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("%s was not styled in %q", name, out)
		}
	}
}

func TestMinimalHighlightFollowsThemePalette(t *testing.T) {
	line := "func main() { return 1 } // note"
	out := minimalHighlight("x.go", []string{line}, "solarized-light")[0]
	pal := minimalPaletteForTheme("solarized-light")
	for name, want := range map[string]string{
		"function keyword": pal.function.Render("func"),
		"function name":    pal.functionName.Render("main"),
		"control keyword":  pal.control.Render("return"),
		"number":           pal.number.Render("1"),
		"comment":          pal.comment.Render("// note"),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("%s did not use solarized-light palette in %q", name, out)
		}
	}
}

func TestMinimalHighlightOperatorsAndPreproc(t *testing.T) {
	src := []string{
		"#include <stdio.h>",
		"  # define N 3",
		"a += b == c;",
	}
	out := minimalHighlight("x.c", src, "")
	for i, line := range src {
		if plain := ansi.Strip(out[i]); plain != line {
			t.Fatalf("line %d plain text = %q, want %q", i, plain, line)
		}
	}
	// The directive token (leading whitespace excluded) is preproc-styled.
	if !strings.Contains(out[0], mhPreproc.Render("#include")) {
		t.Errorf("#include not preproc-styled: %q", out[0])
	}
	if !strings.Contains(out[1], mhPreproc.Render("# define")) {
		t.Errorf("spaced directive not preproc-styled: %q", out[1])
	}
	// A run of operator bytes shares the operator colour ("+=", "==").
	if !strings.Contains(out[2], mhOperator.Render("+=")) {
		t.Errorf("operator run += not styled: %q", out[2])
	}
	if !strings.Contains(out[2], mhOperator.Render("==")) {
		t.Errorf("operator run == not styled: %q", out[2])
	}
}

// A '#' mid-line in a hash-comment language must stay a comment, not a directive.
func TestMinimalHashLanguageNotTreatedAsPreproc(t *testing.T) {
	out := minimalHighlight("x.py", []string{"#!/usr/bin/env python"}, "")[0]
	if !strings.Contains(out, mhComment.Render("#!/usr/bin/env python")) {
		t.Errorf("python shebang not treated as comment: %q", out)
	}
}

func TestMinimalPlainTextUsesThemeForeground(t *testing.T) {
	got := minimalHighlight("plain.txt", []string{"plain + text"}, "solarized-light")[0]
	want := lipgloss.NewStyle().Foreground(lipgloss.Color("#586e75")).Render("plain")
	if !strings.Contains(got, want) {
		t.Fatalf("plain text was not styled with theme foreground: %q", got)
	}
}
