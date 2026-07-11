package layout

import (
	"testing"

	"charm.land/lipgloss/v2"
)

// TestPainterTextMatchesLipgloss pins Painter.Text to the bytes lipgloss itself
// produces. Text exists to skip the render, so it is only correct while it is
// indistinguishable from one — including the exact spelling of the closing
// reset, which the disasm selection bar rewrites by substitution. A lipgloss
// upgrade that changed it would otherwise surface as an unexplained golden diff.
func TestPainterTextMatchesLipgloss(t *testing.T) {
	styles := map[string]lipgloss.Style{
		"foreground":      lipgloss.NewStyle().Foreground(lipgloss.Color("#79808f")),
		"background":      lipgloss.NewStyle().Background(lipgloss.Color("#5e81ac")),
		"bold foreground": lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#d8dee9")),
		"fg + bg":         lipgloss.NewStyle().Foreground(lipgloss.Color("#eceff4")).Background(lipgloss.Color("#3b4252")),
		"underline":       lipgloss.NewStyle().Underline(true).Foreground(lipgloss.Color("#88c0d0")),
		"no styling":      lipgloss.NewStyle(),
	}
	for name, st := range styles {
		t.Run(name, func(t *testing.T) {
			p := NewPainter(st)
			for _, s := range []string{"0x0000000000401000", "main", "x"} {
				if got, want := p.Text(s), st.Render(s); got != want {
					t.Errorf("Text(%q)\n  got  %q\n  want %q (lipgloss)", s, got, want)
				}
			}
		})
	}
}

// TestPainterTextLeavesEmptyAlone: lipgloss renders "" as "", with no escape
// codes; Text must not emit a bare colour sequence for it.
func TestPainterTextLeavesEmptyAlone(t *testing.T) {
	p := NewPainter(lipgloss.NewStyle().Foreground(lipgloss.Color("#79808f")))
	if got := p.Text(""); got != "" {
		t.Errorf("Text(\"\") = %q, want the empty string", got)
	}
}
