//go:build !lite

package syntax

import (
	"charm.land/lipgloss/v2"
	"github.com/alecthomas/chroma/v2"
)

// StyleEntryToLipgloss converts the subset of Chroma style attributes exex
// renders. Tokens a style leaves uncoloured take fallbackFG (see
// theme.ForegroundFor), so a style that only highlights keywords still draws its
// body text in the right colour instead of the terminal default.
//
// Both the source pane (this package) and the disassembly pane (internal/ui)
// need it, and each had its own byte-identical copy.
func StyleEntryToLipgloss(e chroma.StyleEntry, fallbackFG string) lipgloss.Style {
	s := lipgloss.NewStyle()
	if e.Colour.IsSet() {
		s = s.Foreground(lipgloss.Color(e.Colour.String()))
	} else if fallbackFG != "" {
		s = s.Foreground(lipgloss.Color(fallbackFG))
	}
	if e.Bold == chroma.Yes {
		s = s.Bold(true)
	}
	if e.Italic == chroma.Yes {
		s = s.Italic(true)
	}
	if e.Underline == chroma.Yes {
		s = s.Underline(true)
	}
	return s
}
