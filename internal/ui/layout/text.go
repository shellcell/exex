package layout

// Width-aware text geometry shared by every view: padding and truncation that
// count terminal cells (not bytes), line wrapping with a hanging indent, and the
// SGR-carry that keeps colour across wrapped rows. All ANSI- and Unicode-aware,
// and free of any Model/Theme dependency, so the fiddly cell math is unit-tested
// in isolation instead of through a rendered view.

import (
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

// Clamp constrains v to the inclusive range [lo, hi].
func Clamp(v, lo, hi int) int {
	return min(max(v, lo), hi)
}

// TruncateMiddle keeps both ends of a string visible within n columns.
func TruncateMiddle(s string, n int) string {
	if n <= 0 {
		return ""
	}
	plain := ansi.Strip(s)
	if lipgloss.Width(plain) <= n {
		return plain
	}
	if n <= 3 {
		return TruncateANSI(plain, n)
	}
	leftW := (n - 1) / 2
	rightW := n - 1 - leftW
	totalW := lipgloss.Width(plain)
	left := ansi.Truncate(plain, leftW, "")
	right := ansi.TruncateLeft(plain, max(0, totalW-rightW), "")
	return left + "…" + right
}

// TruncateANSI naively truncates while keeping the trailing SGR reset.
func TruncateANSI(s string, w int) string {
	if w <= 0 {
		return ""
	}
	// ansi.Truncate is width- and escape-aware (and never splits a multi-byte
	// rune, unlike a naive byte slice), so it's safe for styled / Unicode text.
	return ansi.Truncate(s, w, "")
}

// FitANSIWidth keeps a styled string intact when it fits within w visible
// columns, and falls back to a plain truncation when it doesn't — so a single
// over-long source line can't break the side-by-side layout while normal-width
// lines retain their syntax colours.
func FitANSIWidth(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= w {
		return s
	}
	return TruncateANSI(s, w)
}

// PadVisual right-pads s to a minimum display width of w columns (ANSI- and
// width-aware), leaving a string that's already wider untouched. This is the
// cell-accurate equivalent of fmt's "%-*s", which counts runes/bytes rather
// than terminal cells and so misaligns columns containing wide or styled text.
func PadVisual(s string, w int) string {
	if d := w - lipgloss.Width(s); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s
}

// PadRight pads s to exactly w visible columns, truncating when it's longer so
// an over-wide line (e.g. a long demangled symbol) can't wrap and shove the
// layout down behind the status line.
func PadRight(s string, w int) string {
	pw := lipgloss.Width(s)
	switch {
	case pw == w:
		return s
	case pw > w:
		// Truncate (width-aware) and pad any remainder — a wide rune straddling
		// the boundary can leave the result a cell short.
		s = TruncateANSI(s, w)
		if d := w - lipgloss.Width(s); d > 0 {
			s += strings.Repeat(" ", d)
		}
		return s
	default:
		return s + strings.Repeat(" ", w-pw)
	}
}

// PadBody clamps and pads a rendered body to exactly w by h cells.
func PadBody(s string, w, h int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > h {
		lines = lines[:h]
	}
	// Clamp every line to exactly w columns so nothing wraps and shoves the
	// layout (and the status line) down.
	for i, l := range lines {
		if lipgloss.Width(l) != w {
			lines[i] = PadRight(l, w)
		}
	}
	for len(lines) < h {
		lines = append(lines, strings.Repeat(" ", w))
	}
	return strings.Join(lines, "\n")
}

// PadBodyRows clamps and pads pre-split rows to exactly w by h cells.
func PadBodyRows(lines []string, w, h int) string {
	if len(lines) > h {
		lines = lines[:h]
	}
	for i, l := range lines {
		lines[i] = PadRight(l, w)
	}
	for len(lines) < h {
		lines = append(lines, strings.Repeat(" ", w))
	}
	return strings.Join(lines, "\n")
}

// WrapRows splits s into width-limited rows using ansi.Wrap.
func WrapRows(s string, w int, cutset string) []string {
	wrapped := ansi.Wrap(s, w, cutset)
	rows := strings.Split(strings.TrimRight(wrapped, "\n"), "\n")
	if len(rows) == 0 {
		return []string{""}
	}
	return rows
}

// HardWrapLongRows splits any row still wider than w columns.
func HardWrapLongRows(rows []string, w int) []string {
	out := make([]string, 0, len(rows))

	for _, row := range rows {
		if lipgloss.Width(row) <= w {
			out = append(out, row)
			continue
		}

		out = append(out, WrapRows(row, w, "")...)
	}

	return out
}

// IndentContinuationRows applies a hanging indent after the first row.
func IndentContinuationRows(rows []string, w int, indent int) []string {
	if len(rows) <= 1 {
		return rows
	}

	prefix := strings.Repeat(" ", indent)
	contW := max(1, w-indent)

	out := make([]string, 0, len(rows))
	out = append(out, rows[0])

	for _, row := range rows[1:] {
		cont := strings.TrimLeft(row, " ")

		for _, part := range WrapRows(cont, contW, " \t/.-_:") {
			out = append(out, prefix+part)
		}
	}

	return out
}

// RenderLineRowsIndented renders a logical line with optional hanging indent.
func RenderLineRowsIndented(line string, w int, wrap bool, indent int) []string {
	if !wrap {
		return []string{PadRight(line, w)}
	}

	indent = Clamp(indent, 0, max(0, w-1))

	rows := WrapRows(line, w, " \t/.-_:")
	rows = HardWrapLongRows(rows, w)

	if indent > 0 {
		rows = IndentContinuationRows(rows, w, indent)
	}

	CarryWrapStyle(rows)

	for i := range rows {
		rows[i] = PadRight(rows[i], w)
	}
	return rows
}

// CarryWrapStyle makes each wrapped row self-contained. A styled span (e.g. a
// coloured symbol or pointer annotation) split across a line break otherwise
// loses its colour: the cell renderer resets the pen at every line, so a
// continuation row that begins mid-span renders with the default colour. This
// re-emits the SGR active at each break — after any leading indent, so the
// hanging indent stays unstyled — and closes every row that ends mid-span.
func CarryWrapStyle(rows []string) {
	open := ""
	for i, row := range rows {
		if open != "" {
			j := 0
			for j < len(row) && row[j] == ' ' {
				j++
			}
			row = row[:j] + open + row[j:]
		}
		open = LastOpenSGR(open, row)
		if open != "" {
			row += "\x1b[0m"
		}
		rows[i] = row
	}
}

// LastOpenSGR returns the SGR sequence still in effect at the end of row, given
// the sequence already open when the row began. A reset ("\x1b[0m" / "\x1b[m")
// clears it; any other SGR replaces it. Styles in this UI are emitted as one
// complete SGR per span (lipgloss does this), so tracking the last sequence is
// sufficient.
func LastOpenSGR(open, row string) string {
	for i := 0; i+1 < len(row); i++ {
		if row[i] != 0x1b || row[i+1] != '[' {
			continue
		}
		j := i + 2
		for j < len(row) && (row[j] < 0x40 || row[j] > 0x7e) {
			j++
		}
		if j >= len(row) {
			break
		}
		if row[j] == 'm' {
			if seq := row[i : j+1]; seq == "\x1b[0m" || seq == "\x1b[m" {
				open = ""
			} else {
				open = seq
			}
		}
		i = j
	}
	return open
}

// AppendRenderedRows appends rendered rows until limit is reached.
func AppendRenderedRows(lines *[]string, line string, w int, wrap bool, limit int) bool {
	return AppendRenderedRowsIndented(lines, line, w, wrap, 0, limit)
}

// AppendRenderedRowsIndented appends indented rendered rows until limit is reached.
func AppendRenderedRowsIndented(lines *[]string, line string, w int, wrap bool, indent int, limit int) bool {
	for _, row := range RenderLineRowsIndented(line, w, wrap, indent) {
		if len(*lines) >= limit {
			return false
		}
		*lines = append(*lines, row)
	}
	return len(*lines) < limit
}
