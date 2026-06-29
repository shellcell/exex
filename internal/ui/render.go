package ui

// Presentation primitives shared by every view: width-aware padding and
// truncation, line wrapping with hanging indent, the scroll-window math that
// keeps a cursor visible across variable-height rows, hex byte rendering, path
// colouring, and the modal overlay compositor. These are pure string helpers
// with no dependency on Model, kept separate from the model/dispatch in app.go.

import (
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

// bytesHex renders up to maxN bytes as compact, per-byte-coloured hex.
// The output is padded with plain spaces to a fixed visible width so columns
// line up regardless of how many bytes the instruction occupied. Uses the
// precomputed byteHex table to avoid re-rendering ANSI codes on every byte.
func bytesHex(b []byte, maxN int) string {
	if len(b) > maxN {
		b = b[:maxN]
	}
	var sb strings.Builder
	for _, x := range b {
		sb.WriteString(byteHex[x])
	}
	visible := len(b) * 2
	want := maxN * 2
	if visible < want {
		sb.WriteString(strings.Repeat(" ", want-visible))
	}
	return sb.String()
}

// bytesHexSpaced is bytesHex with a space between bytes ("01 00 00 14"), padded
// to the maxN-byte column width (maxN*3-1). Used when behavior.spaced_disasm_bytes
// is on, matching the `-o disasm` dump.
func bytesHexSpaced(b []byte, maxN int) string {
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
	want := max(0, maxN*3-1)
	if visible := max(0, len(b)*3-1); visible < want {
		sb.WriteString(strings.Repeat(" ", want-visible))
	}
	return sb.String()
}

// placeCentred renders msg as a dim, centred block within w_view × h, wrapping the
// text to the window width (capped for readability) so it stays inside narrow or
// short terminals instead of overflowing.
func (m *Model) placeCentred(msg string, h int) string {
	w := clamp(m.width-4, 1, 60)
	styled := m.theme.srcShadowStyle.Width(w).Align(lipgloss.Center).Render(msg)
	return lipgloss.Place(m.width, max(1, h), lipgloss.Center, lipgloss.Center, styled)
}

// emptyBody centres a dim message in the whole body area, for a view that has no
// entries at all (no filter/header rows to keep).
func (m *Model) emptyBody(msg string) string {
	return m.placeCentred(msg, m.bodyHeight())
}

// emptyList renders a list view's empty state: the leading rows (filter / column
// header) are kept and a dim message is centred in the body below them, so an
// empty (or fully-filtered) table reads clearly instead of as a blank area.
func (m *Model) emptyList(msg string, leading ...string) string {
	bodyH := m.bodyHeight()
	rows := append(leading, strings.Split(m.placeCentred(msg, bodyH-len(leading)), "\n")...)
	return padBodyRows(rows, m.width, bodyH)
}

// truncateMiddle keeps both ends of a string visible within n columns.
func truncateMiddle(s string, n int) string {
	if n <= 0 {
		return ""
	}
	plain := ansi.Strip(s)
	if lipgloss.Width(plain) <= n {
		return plain
	}
	if n <= 3 {
		return truncateANSI(plain, n)
	}
	leftW := (n - 1) / 2
	rightW := n - 1 - leftW
	totalW := lipgloss.Width(plain)
	left := ansi.Truncate(plain, leftW, "")
	right := ansi.TruncateLeft(plain, max(0, totalW-rightW), "")
	return left + "…" + right
}

// wrapStatus returns the footer label for the current wrap setting.
func wrapStatus(on bool) string {
	if on {
		return "wrap: on"
	}
	return "wrap: off"
}

// colorPathByPrefix renders display in a single colour chosen from keyPath's
// directory prefix, so paths sharing a directory share a colour. keyPath is the
// full path (used only for the colour key); display is what's drawn — which may
// be a middle-truncated form of the same path. The palette comes from the theme,
// so path colouring follows the active preset.
func (t *Theme) colorPathByPrefix(keyPath, display string) string {
	if display == "" {
		return display
	}
	return t.pathPrefixStyle(pathColorKey(keyPath)).Render(display)
}

// pathColorKey reduces a path to a coarse grouping key: at most its first two
// directory components. This keeps whole subtrees (e.g. everything under
// /usr/lib) one colour instead of giving every leaf directory its own.
func pathColorKey(p string) string {
	segs := strings.Split(strings.Trim(p, "/"), "/")
	// Drop the filename (last segment) so siblings group together — bare names
	// with no directory then all share one colour — and keep up to the first two
	// directory components.
	if len(segs) > 0 {
		segs = segs[:len(segs)-1]
	}
	if len(segs) > 2 {
		segs = segs[:2]
	}
	return strings.Join(segs, "/")
}

// pathPrefixStyle deterministically maps a path prefix to one of the theme's
// path-palette styles.
func (t *Theme) pathPrefixStyle(prefix string) lipgloss.Style {
	if len(t.pathPalette) == 0 {
		return lipgloss.NewStyle()
	}
	h := 0
	for i := 0; i < len(prefix); i++ {
		h = h*33 + int(prefix[i])
	}
	if h < 0 {
		h = -h
	}
	return t.pathPalette[h%len(t.pathPalette)]
}

// padVisual right-pads s to a minimum display width of w columns (ANSI- and
// width-aware), leaving a string that's already wider untouched. This is the
// cell-accurate equivalent of fmt's "%-*s", which counts runes/bytes rather
// than terminal cells and so misaligns columns containing wide or styled text.
func padVisual(s string, w int) string {
	if d := w - lipgloss.Width(s); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s
}

// padRight pads s to exactly w visible columns, truncating when it's longer so
// an over-wide line (e.g. a long demangled symbol) can't wrap and shove the
// layout down behind the status line.
func padRight(s string, w int) string {
	pw := lipgloss.Width(s)
	switch {
	case pw == w:
		return s
	case pw > w:
		// Truncate (width-aware) and pad any remainder — a wide rune straddling
		// the boundary can leave the result a cell short.
		s = truncateANSI(s, w)
		if d := w - lipgloss.Width(s); d > 0 {
			s += strings.Repeat(" ", d)
		}
		return s
	default:
		return s + strings.Repeat(" ", w-pw)
	}
}

// padBody clamps and pads a rendered body to exactly w by h cells.
func padBody(s string, w, h int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > h {
		lines = lines[:h]
	}
	// Clamp every line to exactly w columns so nothing wraps and shoves the
	// layout (and the status line) down.
	for i, l := range lines {
		if lipgloss.Width(l) != w {
			lines[i] = padRight(l, w)
		}
	}
	for len(lines) < h {
		lines = append(lines, strings.Repeat(" ", w))
	}
	return strings.Join(lines, "\n")
}

// padBodyRows clamps and pads pre-split rows to exactly w by h cells.
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

func (t Theme) renderViewBackground(s string, w int) string {
	return renderBackground(s, w, t.viewStyle)
}

func renderBackground(s string, w int, st lipgloss.Style) string {
	return renderStyle(s, w, st)
}

func renderStyle(s string, w int, st lipgloss.Style) string {
	prefix := stylePrefix(st)
	if prefix == "" {
		return s
	}
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if w > 0 && lipgloss.Width(line) != w {
			line = padRight(line, w)
		}
		line = strings.ReplaceAll(line, "\x1b[0m", "\x1b[0m"+prefix)
		line = strings.ReplaceAll(line, "\x1b[m", "\x1b[m"+prefix)
		lines[i] = prefix + line + "\x1b[0m"
	}
	return strings.Join(lines, "\n")
}

func (t Theme) viewTitleLine(s string, w int) string {
	return renderBackground(padRight(fitANSIWidth(s, w), w), w, t.tableHeaderStyle)
}

func (t Theme) stickyTitleLine(s string, w int) string {
	return renderBackground(padRight(fitANSIWidth(s, w), w), w, t.stickySymStyle)
}

func stylePrefix(st lipgloss.Style) string {
	sample := st.Render("x")
	i := strings.IndexByte(sample, 'x')
	if i <= 0 {
		return ""
	}
	return sample[:i]
}

// tableHeader renders a full-width table header line.
func (m *Model) tableHeader(s string) string {
	return m.theme.viewTitleLine(truncateMiddle(s, m.width), m.width)
}

// wrapRows splits s into width-limited rows using ansi.Wrap.
func wrapRows(s string, w int, cutset string) []string {
	wrapped := ansi.Wrap(s, w, cutset)
	rows := strings.Split(strings.TrimRight(wrapped, "\n"), "\n")
	if len(rows) == 0 {
		return []string{""}
	}
	return rows
}

// hardWrapLongRows splits any row still wider than w columns.
func hardWrapLongRows(rows []string, w int) []string {
	out := make([]string, 0, len(rows))

	for _, row := range rows {
		if lipgloss.Width(row) <= w {
			out = append(out, row)
			continue
		}

		out = append(out, wrapRows(row, w, "")...)
	}

	return out
}

// indentContinuationRows applies a hanging indent after the first row.
func indentContinuationRows(rows []string, w int, indent int) []string {
	if len(rows) <= 1 {
		return rows
	}

	prefix := strings.Repeat(" ", indent)
	contW := max(1, w-indent)

	out := make([]string, 0, len(rows))
	out = append(out, rows[0])

	for _, row := range rows[1:] {
		cont := strings.TrimLeft(row, " ")

		for _, part := range wrapRows(cont, contW, " \t/.-_:") {
			out = append(out, prefix+part)
		}
	}

	return out
}

// clamp constrains v to the inclusive range [lo, hi].
func clamp(v, lo, hi int) int {
	return min(max(v, lo), hi)
}

// renderLineRowsIndented renders a logical line with optional hanging indent.
func renderLineRowsIndented(line string, w int, wrap bool, indent int) []string {
	if !wrap {
		return []string{padRight(line, w)}
	}

	indent = clamp(indent, 0, max(0, w-1))

	rows := wrapRows(line, w, " \t/.-_:")
	rows = hardWrapLongRows(rows, w)

	if indent > 0 {
		rows = indentContinuationRows(rows, w, indent)
	}

	carryWrapStyle(rows)

	for i := range rows {
		rows[i] = padRight(rows[i], w)
	}
	return rows
}

// carryWrapStyle makes each wrapped row self-contained. A styled span (e.g. a
// coloured symbol or pointer annotation) split across a line break otherwise
// loses its colour: the cell renderer resets the pen at every line, so a
// continuation row that begins mid-span renders with the default colour. This
// re-emits the SGR active at each break — after any leading indent, so the
// hanging indent stays unstyled — and closes every row that ends mid-span.
func carryWrapStyle(rows []string) {
	open := ""
	for i, row := range rows {
		if open != "" {
			j := 0
			for j < len(row) && row[j] == ' ' {
				j++
			}
			row = row[:j] + open + row[j:]
		}
		open = lastOpenSGR(open, row)
		if open != "" {
			row += "\x1b[0m"
		}
		rows[i] = row
	}
}

// lastOpenSGR returns the SGR sequence still in effect at the end of row, given
// the sequence already open when the row began. A reset ("\x1b[0m" / "\x1b[m")
// clears it; any other SGR replaces it. Styles in this UI are emitted as one
// complete SGR per span (lipgloss does this), so tracking the last sequence is
// sufficient.
func lastOpenSGR(open, row string) string {
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

// appendRenderedRows appends rendered rows until limit is reached.
func appendRenderedRows(lines *[]string, line string, w int, wrap bool, limit int) bool {
	return appendRenderedRowsIndented(lines, line, w, wrap, 0, limit)
}

// appendRenderedRowsIndented appends indented rendered rows until limit is reached.
func appendRenderedRowsIndented(lines *[]string, line string, w int, wrap bool, indent int, limit int) bool {
	for _, row := range renderLineRowsIndented(line, w, wrap, indent) {
		if len(*lines) >= limit {
			return false
		}
		*lines = append(*lines, row)
	}
	return len(*lines) < limit
}

// visualTopForView respects detached viewport state when computing list top.
func (m *Model) visualTopForView(cur, top, n, visible int, rowHeight func(int) int) int {
	if m.viewportDetached {
		return viewportTop(top, n, visible, rowHeight)
	}
	return visualTop(cur, top, n, visible, rowHeight)
}

// viewportTop clamps a detached viewport top for variable-height rows.
func viewportTop(top, n, visible int, rowHeight func(int) int) int {
	if n <= 0 {
		return 0
	}
	if visible < 1 {
		visible = 1
	}
	if top < 0 {
		top = 0
	}
	if top >= n {
		top = n - 1
	}
	maxTop := maxViewportTop(n, visible, rowHeight)
	if top > maxTop {
		return maxTop
	}
	return top
}

// maxViewportTop returns the latest top row that can fill the viewport.
func maxViewportTop(n, visible int, rowHeight func(int) int) int {
	if n <= 0 {
		return 0
	}
	if visible < 1 {
		visible = 1
	}
	rows := 0
	top := n
	for top > 0 {
		h := max(1, rowHeight(top-1))
		if rows+h > visible {
			break
		}
		rows += h
		top--
	}
	if top == n {
		return n - 1
	}
	return top
}

// visualTop returns the nearest top that keeps cur visible.
func visualTop(cur, top, n, visible int, rowHeight func(int) int) int {
	if n <= 0 {
		return 0
	}
	if visible < 1 {
		visible = 1
	}
	if cur < 0 {
		cur = 0
	}
	if cur >= n {
		cur = n - 1
	}
	if top < 0 || cur < top {
		top = cur
	}
	if top >= n {
		top = n - 1
	}
	if maxTop := maxViewportTop(n, visible, rowHeight); top > maxTop {
		top = maxTop
	}
	if top > cur {
		top = cur
	}

	// Find the earliest row that can still keep cur visible by walking backward
	// only as far as the viewport can fit. This preserves the old top while it's
	// valid, but avoids the O(n²) forward scan when the cursor jumps far away
	// (End / Ctrl+E on huge symbol or string tables).
	minTop := cur
	rows := max(1, rowHeight(cur))
	for minTop > 0 {
		h := max(1, rowHeight(minTop-1))
		if rows+h > visible {
			break
		}
		rows += h
		minTop--
	}
	if top < minTop {
		top = minTop
	}
	return top
}

// visualItemAtRow maps a visual row offset to a logical item index.
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

// fitANSIWidth keeps a styled string intact when it fits within w visible
// columns, and falls back to a plain truncation when it doesn't — so a single
// over-long source line can't break the side-by-side layout while normal-width
// lines retain their syntax colours.
func fitANSIWidth(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= w {
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
