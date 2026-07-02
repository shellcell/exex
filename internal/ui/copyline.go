package ui

// shift+l (received as "L") copies the full current row — every column as shown —
// to the clipboard, across the list, byte and code views. It reuses each view's
// own row renderer and strips styling so the clipboard gets clean text.

import (
	"strings"

	"github.com/charmbracelet/x/ansi"
)

// copyCurrentLine copies the row under the cursor in the active view. It reports
// whether the key was handled (true for every view that has rows; false in views
// without a row concept, so the caller can let other handling proceed).
func (m *Model) copyCurrentLine() bool {
	line, ok := m.currentLineText()
	if !ok {
		return false
	}
	if line == "" {
		m.setStatus("nothing to copy on this line", true)
		return true
	}
	m.copyToClipboard(line, "line")
	return true
}

// currentLineText returns the plain text of the current row in the active view.
func (m *Model) currentLineText() (string, bool) {
	return m.current().lineText()
}

// cleanCopyLine strips styling and squeezes column padding so a table row copies
// as a single readable, space-separated line.
func cleanCopyLine(s string) string {
	return strings.TrimSpace(collapseSpaces(ansi.Strip(s)))
}

// byteRowText renders the hex/raw row containing the cursor and strips styling.
func (m *Model) byteRowText(md mode, data byteSource, cur int, addrAt func(int) uint64) string {
	if data.Len() == 0 {
		return ""
	}
	start := m.hexRowTop(md, cur, addrAt)
	span := m.hexRowSpan(md, data, start, addrAt)
	return ansi.Strip(m.renderHexRow(md, data, cur, span, m.file.AddrHexWidth(), addrAt))
}

// collapseSpaces squeezes runs of spaces to one, so a wide table row copies as a
// single readable, space-separated line rather than column-padded text.
func collapseSpaces(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	space := false
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' {
			space = true
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteByte(s[i])
	}
	return b.String()
}
