package ui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/muesli/termenv"
)

// TestOverlayPreservesBackground guards the popup-overlay bug: the background
// to the left/right of a modal must keep its colour and must not shift width
// (the disasm source-pane border was moving right before the fix).
func TestOverlayPreservesBackground(t *testing.T) {
	old := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	defer lipgloss.SetColorProfile(old)

	red := lipgloss.NewStyle().Foreground(lipgloss.Color("#ff0000"))
	const w = 30
	bgLine := red.Render(strings.Repeat("X", w)) // fully coloured, width 30
	bg := strings.Join([]string{bgLine, bgLine, bgLine}, "\n")

	modal := "ABCDE\nFGHIJ" // 2 lines, width 5, no styling
	out := overlay(bg, modal, 10, 1)
	lines := strings.Split(out, "\n")

	// Row 0 is untouched.
	if lines[0] != bgLine {
		t.Errorf("row above modal changed:\n got %q\nwant %q", lines[0], bgLine)
	}
	// Rows 1 and 2 carry the modal text...
	if !strings.Contains(lines[1], "ABCDE") || !strings.Contains(lines[2], "FGHIJ") {
		t.Fatalf("modal text missing: %q / %q", lines[1], lines[2])
	}
	for i := 1; i <= 2; i++ {
		// ...keep the exact visible width (no rightward shift)...
		if got := ansi.StringWidth(lines[i]); got != w {
			t.Errorf("row %d visible width = %d, want %d", i, got, w)
		}
		// ...and still contain background colour around the modal.
		if !strings.Contains(lines[i], "\x1b[") {
			t.Errorf("row %d lost background colour", i)
		}
	}
}
