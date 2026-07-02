package layout

import (
	"strings"

	"github.com/charmbracelet/x/ansi"
)

// Overlay places fg over bg at column x, row y. Both are pre-rendered strings.
// It is ANSI- and width-aware: the background to the left and right of the
// modal keeps its colours and lines up correctly even when those lines contain
// styled or multi-byte content (e.g. the disasm source-pane border).
func Overlay(bg, fg string, x, y int) string {
	if x < 0 {
		x = 0
	}
	if y < 0 {
		y = 0
	}
	bgLines := strings.Split(bg, "\n")
	fgLines := strings.Split(fg, "\n")
	for i, fl := range fgLines {
		row := y + i
		if row >= len(bgLines) {
			break
		}
		bgLine := bgLines[row]
		fw := ansi.StringWidth(fl)

		// Left slice: the first x cells of the background, padded if short.
		left := ansi.Truncate(bgLine, x, "")
		if w := ansi.StringWidth(left); w < x {
			left += strings.Repeat(" ", x-w)
		}
		// Right slice: the background beyond the modal, with its style preserved.
		right := ansi.TruncateLeft(bgLine, x+fw, "")

		bgLines[row] = left + "\x1b[0m" + fl + "\x1b[0m" + right
	}
	return strings.Join(bgLines, "\n")
}
