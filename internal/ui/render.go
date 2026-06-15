package ui

// Presentation primitives shared by every view: width-aware padding and
// truncation, line wrapping with hanging indent, the scroll-window math that
// keeps a cursor visible across variable-height rows, hex byte rendering, path
// colouring, and the modal overlay compositor. These are pure string helpers
// with no dependency on Model, kept separate from the model/dispatch in app.go.

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

// bytesHex renders up to maxN bytes as space-separated, per-byte-coloured hex.
// The output is padded with plain spaces to a fixed visible width so columns
// line up regardless of how many bytes the instruction occupied. Uses the
// precomputed byteHex table to avoid re-rendering ANSI codes on every byte.
func bytesHex(b []byte, maxN int) string {
	if len(b) > maxN {
		b = b[:maxN]
	}
	var sb strings.Builder
	for i, x := range b {
		if i > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(byteHex[x])
	}
	visible := len(b)*3 - 1
	if len(b) == 0 {
		visible = 0
	}
	want := maxN*3 - 1
	if visible < want {
		sb.WriteString(strings.Repeat(" ", want-visible))
	}
	return sb.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

func truncateMiddle(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if lipgloss.Width(stripANSI(s)) <= n {
		return s
	}
	if n <= 3 {
		return truncateANSI(s, n)
	}
	plain := stripANSI(s)
	left := (n - 1) / 2
	right := n - 1 - left
	if len(plain) <= n {
		return plain
	}
	return plain[:left] + "…" + plain[len(plain)-right:]
}

func wrapStatus(on bool) string {
	if on {
		return "wrap: on"
	}
	return "wrap: off"
}

// colorPathByPrefix renders display in a single colour chosen from keyPath's
// directory prefix, so paths sharing a directory share a colour. keyPath is the
// full path (used only for the colour key); display is what's drawn — which may
// be a middle-truncated form of the same path.
func colorPathByPrefix(keyPath, display string) string {
	if display == "" {
		return display
	}
	key := keyPath
	if i := strings.LastIndexByte(keyPath, '/'); i > 0 {
		key = keyPath[:i] // the directory
	}
	return pathPrefixStyle(key).Render(display)
}

func pathPrefixStyle(prefix string) lipgloss.Style {
	colors := []lipgloss.Color{"75", "114", "141", "173", "214", "213", "84", "39"}
	h := 0
	for i := 0; i < len(prefix); i++ {
		h = h*33 + int(prefix[i])
	}
	if h < 0 {
		h = -h
	}
	return lipgloss.NewStyle().Foreground(colors[h%len(colors)])
}

// padRight pads s to exactly w visible columns, truncating when it's longer so
// an over-wide line (e.g. a long demangled symbol) can't wrap and shove the
// layout down behind the status line.
func padRight(s string, w int) string {
	pw := lipgloss.Width(stripANSI(s))
	switch {
	case pw == w:
		return s
	case pw > w:
		// Truncate (width-aware) and pad any remainder — a wide rune straddling
		// the boundary can leave the result a cell short.
		s = truncateANSI(s, w)
		if d := w - lipgloss.Width(stripANSI(s)); d > 0 {
			s += strings.Repeat(" ", d)
		}
		return s
	default:
		return s + strings.Repeat(" ", w-pw)
	}
}

func padBody(s string, w, h int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > h {
		lines = lines[:h]
	}
	// Clamp every line to exactly w columns so nothing wraps and shoves the
	// layout (and the status line) down.
	for i, l := range lines {
		if lipgloss.Width(stripANSI(l)) != w {
			lines[i] = padRight(l, w)
		}
	}
	for len(lines) < h {
		lines = append(lines, strings.Repeat(" ", w))
	}
	return strings.Join(lines, "\n")
}

func padBodyRows(lines []string, w, h int) string {
	if len(lines) > h {
		lines = lines[:h]
	}
	for i, l := range lines {
		lines[i] = padRight(l, w)
	}
	for len(lines) < h {
		lines = append(lines, strings.Repeat(" ", w))
	}
	return strings.Join(lines, "\n")
}

func renderLineRows(line string, w int, wrap bool) []string {
	return renderLineRowsIndented(line, w, wrap, 0)
}

func renderLineRowsIndented(line string, w int, wrap bool, indent int) []string {
	if !wrap {
		return []string{padRight(line, w)}
	}
	if indent < 0 {
		indent = 0
	}
	if indent >= w {
		indent = max(0, w-1)
	}
	wrapped := ansi.Wrap(line, w, " \t/.-_:")
	rows := strings.Split(strings.TrimRight(wrapped, "\n"), "\n")
	if len(rows) == 0 {
		return []string{strings.Repeat(" ", w)}
	}
	for i := 0; i < len(rows); i++ {
		if lipgloss.Width(stripANSI(rows[i])) <= w {
			continue
		}
		hard := ansi.Wrap(rows[i], w, "")
		parts := strings.Split(strings.TrimRight(hard, "\n"), "\n")
		rows = append(rows[:i], append(parts, rows[i+1:]...)...)
		i += len(parts) - 1
	}
	if indent > 0 {
		prefix := strings.Repeat(" ", indent)
		contW := max(1, w-indent)
		indented := rows[:1]
		for _, row := range rows[1:] {
			cont := strings.TrimLeft(row, " ")
			if lipgloss.Width(stripANSI(cont)) > contW {
				cont = ansi.Wrap(cont, contW, " \t/.-_:")
			}
			parts := strings.Split(strings.TrimRight(cont, "\n"), "\n")
			if len(parts) == 0 {
				parts = []string{""}
			}
			for _, part := range parts {
				indented = append(indented, prefix+part)
			}
		}
		rows = indented
	}
	for i, row := range rows {
		rows[i] = padRight(row, w)
	}
	return rows
}

func appendRenderedRows(lines *[]string, line string, w int, wrap bool, limit int) bool {
	return appendRenderedRowsIndented(lines, line, w, wrap, 0, limit)
}

func appendRenderedRowsIndented(lines *[]string, line string, w int, wrap bool, indent int, limit int) bool {
	for _, row := range renderLineRowsIndented(line, w, wrap, indent) {
		if len(*lines) >= limit {
			return false
		}
		*lines = append(*lines, row)
	}
	return len(*lines) < limit
}

func ensureVisualTop(cur int, top *int, n, visible int, rowHeight func(int) int) {
	if n <= 0 {
		*top = 0
		return
	}
	if cur < 0 {
		cur = 0
	}
	if cur >= n {
		cur = n - 1
	}
	if *top < 0 || cur < *top {
		*top = cur
	}
	if *top >= n {
		*top = n - 1
	}
	for *top < cur && visualRowsBetween(*top, cur, rowHeight)+rowHeight(cur) > visible {
		*top++
	}
}

func visualRowsBetween(start, end int, rowHeight func(int) int) int {
	rows := 0
	for i := start; i < end; i++ {
		rows += max(1, rowHeight(i))
	}
	return rows
}

func visualItemAtRow(top, n, row int, rowHeight func(int) int) (int, bool) {
	if row < 0 {
		return 0, false
	}
	pos := 0
	for i := top; i < n; i++ {
		h := max(1, rowHeight(i))
		if row >= pos && row < pos+h {
			return i, true
		}
		pos += h
	}
	return 0, false
}

// overlay places fg over bg at column x, row y. Both are pre-rendered strings.
// It is ANSI- and width-aware: the background to the left and right of the
// modal keeps its colours and lines up correctly even when those lines contain
// styled or multi-byte content (e.g. the disasm source-pane border).
func overlay(bg, fg string, x, y int) string {
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

// stripANSI removes ANSI escape sequences for width math. Cheap and good enough
// for our render strings, which only carry simple SGR codes from lipgloss.
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

// fitANSIWidth keeps a styled string intact when it fits within w visible
// columns, and falls back to a plain truncation when it doesn't — so a single
// over-long source line can't break the side-by-side layout while normal-width
// lines retain their syntax colours.
func fitANSIWidth(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if lipgloss.Width(stripANSI(s)) <= w {
		return s
	}
	return truncateANSI(s, w)
}

// truncateANSI naively truncates while keeping the trailing SGR reset.
func truncateANSI(s string, w int) string {
	if w <= 0 {
		return ""
	}
	// ansi.Truncate is width- and escape-aware (and never splits a multi-byte
	// rune, unlike a naive byte slice), so it's safe for styled / Unicode text.
	return ansi.Truncate(s, w, "")
}
