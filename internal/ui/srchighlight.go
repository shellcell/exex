package ui

// Shared highlight policy for the split source/disasm panes.
//
// Both layouts — source-first (source left, disasm right) and disasm-first
// (disasm left, source right) — must colour code lines and instruction
// addresses identically. Rather than duplicate that decision in each renderer,
// it lives here as one small policy layer that every pane renderer consumes:
//
//   - srcGutter      decides the colour of a source line's number gutter.
//   - addrMapStyle   decides the colour of an instruction's address column.
//
// The renderers above this layer only lay out text; they never decide colours.

import (
	"fmt"

	"charm.land/lipgloss/v2"
)

// srcGutter renders the line-number gutter for a source line. Only the number
// is coloured — never the whole line: the current (caret) line is highlighted,
// lines that have machine code mapped to them are white, and unmapped lines are
// dimmed. digits is the field width of the number; the returned string is
// digits+3 columns wide ("<num> <marker> ").
func (m *Model) srcGutter(ln, curLine int, mapped map[int]bool, digits int) string {
	switch {
	case ln == curLine:
		return m.theme.srcCurLineStyle.Render(fmt.Sprintf("%*d ▸ ", digits, ln))
	case mapped[ln]:
		return m.theme.whiteStyle.Render(fmt.Sprintf("%*d · ", digits, ln))
	default:
		return m.theme.srcShadowStyle.Render(fmt.Sprintf("%*d   ", digits, ln))
	}
}

// addrMapStyle classifies an instruction address against the current source
// location and returns the style its address column should use: dimmed when the
// address maps to no source line, the per-column colour when it maps to the
// current line (so it correlates with the source carets), and white when it
// maps to some other line.
func (m *Model) addrMapStyle(addr uint64, curFile string, curLine int) lipgloss.Style {
	f, l, c := m.file.LookupAddrCol(addr)
	switch {
	case f == "" || l == 0:
		return m.theme.srcShadowStyle
	case curFile != "" && f == curFile && l == curLine:
		if st, ok := m.theme.columnStyle(m.dasm.SourceLineColumns(m.viewContextPtr(), curFile, curLine), c); ok {
			return st.Bold(true)
		}
		return m.theme.srcMappedStyle
	default:
		return m.theme.whiteStyle
	}
}

// rightPaneActive reports whether the disasm view is currently showing a second
// (follower) pane that the independent-scroll controls apply to.
func (m *Model) rightPaneActive() bool {
	return m.mode == modeDisasm && m.dasm.ShowSource && m.file.HasDWARF()
}

// scrollRightPane nudges the follower pane's independent scroll offset; the
// renderers clamp it to the pane bounds.
func (m *Model) scrollRightPane(delta int) {
	m.dasm.RightScroll += delta
}
