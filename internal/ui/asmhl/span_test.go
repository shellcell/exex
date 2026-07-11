package asmhl

import (
	"strings"
	"testing"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/rabarbra/exex/internal/disasm"
)

// These run under both build tags: whichever highlighter is compiled in must
// honour the link spans, because that is the one behaviour the shell depends on.

func spanStyles() (Styles, lipgloss.Style) {
	link := lipgloss.NewStyle().Underline(true)
	st := Styles{
		Class:    func(disasm.InstClass) lipgloss.Style { return lipgloss.NewStyle().Bold(true) },
		Plain:    lipgloss.NewStyle(),
		Register: lipgloss.NewStyle(),
		Number:   lipgloss.NewStyle(),
	}
	return st, link
}

// TestSpanIsDrawnInItsLinkStyle: a followable address literal keeps its link
// colour, whatever the token colours around it are.
func TestSpanIsDrawnInItsLinkStyle(t *testing.T) {
	st, link := spanStyles()
	h := New("nord", "#d8dee9", disasm.ArchAMD64, st)

	const text = "call 0x401020"
	start := strings.Index(text, "0x401020")
	got := h.Render(text, disasm.Classify(text), []Span{{Start: start, End: len(text), Style: link}})

	if plain := ansi.Strip(got); plain != text {
		t.Fatalf("plain text = %q, want %q", plain, text)
	}
	if !strings.Contains(got, link.Render("0x401020")) {
		t.Errorf("the address span was not drawn in its link style:\n%q", got)
	}
}

// TestSpanInsideAToken: Chroma may tokenise "[0x1000]" as one token, so a span
// covering part of it has to split that token.
func TestSpanInsideAToken(t *testing.T) {
	st, link := spanStyles()
	h := New("nord", "#d8dee9", disasm.ArchAMD64, st)

	const text = "mov [0x401020],%rax"
	start := strings.Index(text, "0x401020")
	got := h.Render(text, disasm.Classify(text), []Span{{Start: start, End: start + len("0x401020"), Style: link}})

	if plain := ansi.Strip(got); plain != text {
		t.Fatalf("plain text = %q, want %q", plain, text)
	}
	if !strings.Contains(got, link.Render("0x401020")) {
		t.Errorf("a span inside a token was not honoured:\n%q", got)
	}
}

// TestNoSpansLeavesTextIntact guards the common case.
func TestNoSpansLeavesTextIntact(t *testing.T) {
	st, _ := spanStyles()
	h := New("nord", "#d8dee9", disasm.ArchAMD64, st)
	const text = "nop"
	if plain := ansi.Strip(h.Render(text, disasm.Classify(text), nil)); plain != text {
		t.Errorf("plain text = %q, want %q", plain, text)
	}
}

func TestSpanAt(t *testing.T) {
	spans := []Span{{Start: 2, End: 5}, {Start: 8, End: 10}}
	for _, tc := range []struct {
		i    int
		want bool
	}{{0, false}, {2, true}, {4, true}, {5, false}, {8, true}, {9, true}, {10, false}, {99, false}} {
		if _, ok := spanAt(spans, tc.i); ok != tc.want {
			t.Errorf("spanAt(%d) = %v, want %v", tc.i, ok, tc.want)
		}
	}
}
