package ui

// The strings view lists printable runs found in the file (à la strings(1)),
// each annotated with its file offset and — when the bytes are mapped — the
// virtual address and owning section. Enter jumps a mapped string into the hex
// view; copy keys grab the address/offset or the string text.

import (
	"fmt"
	"sort"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/rabarbra/exex/internal/binfile"
)

// stringSort is the display order of the (filtered) strings list.
type stringSort uint8

const (
	strSortOffset stringSort = iota // file order (the natural extraction order)
	strSortAddr
	strSortText
)

// String returns the sort's filter-status label.
func (s stringSort) String() string {
	switch s {
	case strSortAddr:
		return "address"
	case strSortText:
		return "string"
	}
	return "offset"
}

// applyStringSort orders stringsFiltered by the active field. The natural order
// is offset-ascending (strings are extracted in offset order), so that case only
// needs reversing for descending.
func (m *Model) applyStringSort() {
	desc := m.stringsSortDesc
	if m.stringsSort == strSortOffset {
		if desc {
			reverseInts(m.stringsFiltered)
		}
		return
	}
	sort.SliceStable(m.stringsFiltered, func(a, b int) bool {
		sa, sb := m.stringsList[m.stringsFiltered[a]], m.stringsList[m.stringsFiltered[b]]
		var less bool
		switch m.stringsSort {
		case strSortAddr:
			less = sa.Addr < sb.Addr
		case strSortText:
			less = string(m.file.StringBytes(sa)) < string(m.file.StringBytes(sb))
		}
		if desc {
			return !less
		}
		return less
	})
}

// ensureStrings extracts the file's printable strings lazily and builds the
// (initially unfiltered) view list.
func (m *Model) ensureStrings() {
	if m.stringsList == nil {
		m.stringsList = m.file.Strings()
		m.buildStringSections()
		m.recomputeStrings()
	}
}

// buildStringSections collects the distinct owning-section names (sorted) so the
// alt+s filter can cycle through them.
func (m *Model) buildStringSections() {
	seen := map[string]bool{}
	m.stringsSections = m.stringsSections[:0]
	for _, s := range m.stringsList {
		if s.Section != "" && !seen[s.Section] {
			seen[s.Section] = true
			m.stringsSections = append(m.stringsSections, s.Section)
		}
	}
	sort.Strings(m.stringsSections)
}

// cycleStringSectionFilter steps the section filter off → first → … → last → off.
func (m *Model) cycleStringSectionFilter() {
	if len(m.stringsSections) == 0 {
		m.setStatus("no section info for strings", false)
		return
	}
	if !m.stringsSecOn {
		m.stringsSecOn = true
		m.stringsSec = m.stringsSections[0]
		m.setStatus("string section filter: "+m.stringsSec, false)
		return
	}
	for i, sec := range m.stringsSections {
		if sec == m.stringsSec {
			if i == len(m.stringsSections)-1 {
				m.stringsSecOn = false
				m.setStatus("string section filter: all", false)
				return
			}
			m.stringsSec = m.stringsSections[i+1]
			m.setStatus("string section filter: "+m.stringsSec, false)
			return
		}
	}
	m.stringsSecOn = false
}

// recomputeStrings rebuilds stringsFiltered from the current filter text,
// matching on the string text and its owning section.
// looksLikePath reports whether a string is a plausible filesystem path or URL.
// It is deliberately *precise* rather than inclusive: a bare separator is not
// enough (that admits "text/html", "application/json", "%s/%s", "and/or"). A
// string qualifies only if it is a URL (scheme://…), is anchored as a path
// (leading "/", "./", "../", "~/", "@rpath/…", a Windows drive or UNC), or has
// real path structure (≥2 separators or a file extension) using only path-like
// bytes and no whitespace/control.
func looksLikePath(b []byte) bool {
	if len(b) < 2 || len(b) > 4096 {
		return false
	}
	for _, c := range b {
		if c <= ' ' || c == 0x7f {
			return false // whitespace/control → not a clean path
		}
	}
	if schemeEnd(b) > 0 { // URL: scheme://rest — query chars allowed, skip the strict scan
		return true
	}

	anchored := false
	switch {
	case b[0] == '/' || b[0] == '~' || b[0] == '@':
		anchored = true // /abs, ~/home, @rpath/@executable_path
	case b[0] == '.' && (b[1] == '/' || (b[1] == '.' && len(b) >= 3 && b[2] == '/')):
		anchored = true // ./rel or ../rel
	case b[0] == '\\' && b[1] == '\\': // UNC \\host\share
		anchored = true
	case len(b) >= 3 && isAlpha(b[0]) && b[1] == ':' && (b[2] == '\\' || b[2] == '/'):
		anchored = true // C:\ or C:/
	}

	seps, lastSeg, hasAlnum, hasAlpha := 0, 0, false, false
	for i, c := range b {
		switch {
		case c == '/' || c == '\\':
			seps++
			lastSeg = i + 1
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
			hasAlnum, hasAlpha = true, true
		case c >= '0' && c <= '9':
			hasAlnum = true
		case c == '.' || c == '_' || c == '-' || c == '+' || c == '~' || c == '@' || c == '%' || c == ':' || c == '$':
			// allowed path-component punctuation
		default:
			return false // unusual punctuation → not a clean path
		}
	}
	if seps == 0 || !hasAlnum {
		return false
	}
	if anchored {
		return true
	}
	// Unanchored relative path: demand real structure (≥2 separators or a file
	// extension) and at least one letter, so single-separator tokens ("text/html",
	// "%s/%s") and all-digit runs ("2024/01/02") don't slip through.
	if !hasAlpha {
		return false
	}
	hasExt := false
	for j := lastSeg + 1; j+1 < len(b); j++ {
		if b[j] == '.' {
			hasExt = true
			break
		}
	}
	return seps >= 2 || hasExt
}

// isAlpha reports whether b is an ASCII letter.
func isAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// schemeEnd returns the index of the ':' in a leading URL scheme ("http://…") or
// 0 if b doesn't start with a scheme followed by "://".
func schemeEnd(b []byte) int {
	if len(b) < 4 || !isAlpha(b[0]) {
		return 0
	}
	i := 1
	for i < len(b) {
		c := b[i]
		if isAlpha(c) || (c >= '0' && c <= '9') || c == '+' || c == '.' || c == '-' {
			i++
			continue
		}
		break
	}
	if i+2 < len(b) && b[i] == ':' && b[i+1] == '/' && b[i+2] == '/' {
		return i
	}
	return 0
}

func (m *Model) recomputeStrings() {
	m.clearStringCaches()
	needle := strings.ToLower(m.stringsFilter.Value())
	m.stringsFiltered = m.stringsFiltered[:0]
	for i, s := range m.stringsList {
		if m.stringsSecOn && s.Section != m.stringsSec {
			continue
		}
		// Filter on the raw bytes (zero-copy) so scanning millions of strings on
		// each keystroke doesn't allocate a copy per entry.
		b := m.file.StringBytes(s)
		if m.stringsPathsOnly && !looksLikePath(b) {
			continue
		}
		if needle == "" || containsFoldBytes(b, needle) || containsFold(s.Section, needle) {
			m.stringsFiltered = append(m.stringsFiltered, i)
		}
	}
	m.applyStringSort()
	if m.stringsCur >= len(m.stringsFiltered) {
		m.stringsCur = max(0, len(m.stringsFiltered)-1)
	}
}

// openStringSearch implements the -s CLI flag: it filters the printable strings
// by s and either jumps to the single match (Hex if mapped, else Raw) or opens
// the Strings view with the filter applied when several match.
func (m *Model) openStringSearch(s string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return
	}
	m.ensureStrings()
	m.stringsFilter.SetValue(s)
	m.recomputeStrings()
	m.stringsCur, m.stringsTop = 0, 0
	switch len(m.stringsFiltered) {
	case 0:
		m.setMode(modeStrings)
		m.setStatus(fmt.Sprintf("no strings match %q", s), true)
	case 1:
		e := m.stringsList[m.stringsFiltered[0]]
		if e.HasAddr {
			m.openHexAt(e.Addr)
		} else {
			m.openRawAt(e.Offset)
		}
		m.setStatus(fmt.Sprintf("string %q", s), false)
	default:
		m.setMode(modeStrings)
		m.setStatus(fmt.Sprintf("%d strings match %q", len(m.stringsFiltered), s), false)
	}
}

// currentString returns the selected string through the active filter.
func (m *Model) currentString() (binfile.StringEntry, bool) {
	if m.stringsCur < 0 || m.stringsCur >= len(m.stringsFiltered) {
		return binfile.StringEntry{}, false
	}
	return m.stringsList[m.stringsFiltered[m.stringsCur]], true
}

func (m *Model) updateStrings(key string) (tea.Model, tea.Cmd) {
	m.ensureStrings()
	// In the compact flow the strings tile a 2-D grid: ←/→ step one string along
	// the flow, ↑/↓ move a visual line keeping roughly the same column (so a long
	// scan reads like text, not a single ribbon).
	if m.stringsCompact {
		switch key {
		case "left":
			m.stringsCur = max(0, m.stringsCur-1)
			return m, nil
		case "right":
			m.stringsCur = min(len(m.stringsFiltered)-1, m.stringsCur+1)
			return m, nil
		case "up":
			m.flowMoveLine(-1)
			return m, nil
		case "down":
			m.flowMoveLine(1)
			return m, nil
		case "pgup", "[": // also ⌥↑ / ctrl+↑ (normalised to pgup)
			for p := max(1, m.listPage()); p > 0; p-- {
				m.flowMoveLine(-1)
			}
			return m, nil
		case "pgdown", "]": // also ⌥↓ / ctrl+↓
			for p := max(1, m.listPage()); p > 0; p-- {
				m.flowMoveLine(1)
			}
			return m, nil
		case "home": // also cmd+↑
			m.stringsCur = 0
			return m, nil
		case "end", "G": // also cmd+↓
			m.stringsCur = max(0, len(m.stringsFiltered)-1)
			return m, nil
		}
	}
	if navKey(&m.stringsCur, len(m.stringsFiltered), m.listPage(), key) {
		return m, nil
	}
	switch key {
	case "t":
		m.stringsCompact = !m.stringsCompact
		mode := "table"
		if m.stringsCompact {
			mode = "compact"
		}
		m.setStatus("strings: "+mode, false)
	case "/":
		m.stringsFilter.Focus()
	case "esc":
		dirty := m.stringsSecOn || m.stringsPathsOnly || m.stringsFilter.Value() != "" || m.stringsFilter.Focused()
		m.stringsSecOn = false
		m.stringsPathsOnly = false
		m.stringsFilter.SetValue("")
		m.stringsFilter.Blur()
		m.stringsCur, m.stringsTop = 0, 0
		m.recomputeStrings()
		if dirty {
			m.setStatus("filters cleared", false)
		}
	case "alt+s":
		m.cycleStringSectionFilter()
		m.stringsCur, m.stringsTop = 0, 0
		m.recomputeStrings()
	case "alt+p":
		m.stringsPathsOnly = !m.stringsPathsOnly
		m.stringsCur, m.stringsTop = 0, 0
		m.recomputeStrings()
		state := "off"
		if m.stringsPathsOnly {
			state = "on"
		}
		m.setStatus("paths only: "+state, false)
	case "s":
		m.stringsSort = (m.stringsSort + 1) % 3
		m.stringsCur, m.stringsTop = 0, 0
		m.recomputeStrings()
		m.setStatus("sort: "+m.stringsSort.String(), false)
	case "r":
		m.stringsSortDesc = !m.stringsSortDesc
		m.stringsCur, m.stringsTop = 0, 0
		m.recomputeStrings()
		dir := "ascending"
		if m.stringsSortDesc {
			dir = "descending"
		}
		m.setStatus("sort order: "+dir, false)
	case "w":
		m.toggleWrap()
	case "d":
		if s, ok := m.currentString(); ok && s.HasAddr {
			m.jumpDisasmAtAddr(s.Addr)
		} else {
			m.setStatus("string has no mapped address", true)
		}
	case "h":
		if s, ok := m.currentString(); ok && s.HasAddr {
			m.jumpHexAtAddr(s.Addr)
		} else {
			m.setStatus("string has no mapped address", true)
		}
	case "m":
		if s, ok := m.currentString(); ok {
			m.openRawAt(s.Offset)
		}
	case "enter":
		if s, ok := m.currentString(); ok {
			if s.HasAddr {
				m.openHexAt(s.Addr)
			} else {
				m.openRawAt(s.Offset)
			}
		}
	case "A":
		if s, ok := m.currentString(); ok {
			if s.HasAddr {
				m.copyToClipboard(fmt.Sprintf("0x%0*x", m.file.AddrHexWidth(), s.Addr), "address")
			} else {
				m.copyToClipboard(fmt.Sprintf("0x%x", s.Offset), "offset")
			}
		}
	case "S":
		if s, ok := m.currentString(); ok {
			m.copyToClipboard(m.file.StringText(s), "string")
		}
	}
	return m, nil
}

func (m *Model) renderStrings() string {
	bodyH := m.bodyHeight()
	if bodyH < 2 {
		bodyH = 2
	}
	m.ensureStrings()
	if len(m.stringsList) == 0 {
		return m.emptyBody("no printable strings found")
	}

	filterRow := m.stringsFilter.View()
	if !m.stringsFilter.Focused() {
		secLabel := "all"
		if m.stringsSecOn {
			secLabel = m.stringsSec
		}
		dir := "↑"
		if m.stringsSortDesc {
			dir = "↓"
		}
		pathsLabel := "off"
		if m.stringsPathsOnly {
			pathsLabel = "on"
		}
		filterRow = m.theme.footerStyle.Render(fmt.Sprintf("/ %s   (%d / %d)   ", m.stringsFilter.Value(), len(m.stringsFiltered), len(m.stringsList))) +
			m.theme.helpKeyStyle.Render(altKeys("s")) + m.theme.footerStyle.Render(" section:"+secLabel) +
			m.theme.footerStyle.Render("   ") + m.theme.helpKeyStyle.Render(altKeys("p")) + m.theme.footerStyle.Render(" paths:"+pathsLabel) +
			m.theme.footerStyle.Render("   ") + m.theme.helpKeyStyle.Render("s") + m.theme.footerStyle.Render(" sort:"+m.stringsSort.String()+dir)
	}

	if m.stringsCompact {
		return m.renderStringsFlow(bodyH, filterRow)
	}

	addrW := m.file.AddrHexWidth()
	addrCol := 2 + addrW
	offsetLabel := sortHeaderLabel("Offset", 10, strSortOffset, m.stringsSort, m.stringsSortDesc)
	addrLabel := sortHeaderLabel("Address", addrCol, strSortAddr, m.stringsSort, m.stringsSortDesc)
	stringLabel := trailingSortHeaderLabel("String", strSortText, m.stringsSort, m.stringsSortDesc)
	hdr := fmt.Sprintf(" %-10s %-*s %-16s  %s", offsetLabel, 2+addrW, addrLabel, "Section", stringLabel)
	header := m.tableHeader(hdr)

	visible := bodyH - 2 // filter row + header
	if visible < 1 {
		visible = 1
	}
	rowHeight := func(i int) int {
		return m.stringRowHeight(i)
	}
	top := m.visualTopForView(m.stringsCur, m.stringsTop, len(m.stringsFiltered), visible, rowHeight)
	m.stringsTop = top
	m.renderedStringsTop = top
	m.pageRows = pageStep(top, len(m.stringsFiltered), visible, rowHeight)

	if len(m.stringsFiltered) == 0 {
		return m.emptyList("no matching strings  ·  Esc clears filters", filterRow, header)
	}
	rows := []string{filterRow, header}
	for i := top; i < len(m.stringsFiltered); i++ {
		line := m.stringRow(i, addrW)
		if i == m.stringsCur {
			line = m.theme.tableSelStyle.Render(ansi.Strip(line))
		}
		if !appendRenderedRowsIndented(&rows, line, m.width, m.wrap, addrW+33, bodyH) {
			break
		}
	}
	return padBodyRows(rows, m.width, bodyH)
}

// renderStringsFlow draws the compact strings view: every string laid out inline,
// separated by a middle dot and wrapped to the width — no address/section/offset
// columns. The selected string (caret) is highlighted and the view scrolls to keep
// it visible; ←/→ and ↑/↓ all step the selection.
func (m *Model) renderStringsFlow(bodyH int, filterRow string) string {
	sep := m.theme.srcShadowStyle.Render(" · ")
	visible := max(1, bodyH-1) // filter row
	n := len(m.stringsFiltered)

	// pack lays strings out from top into at most `visible` lines, returning the
	// rendered lines and the last string index shown. Strings are printable ASCII
	// (width == byte length), so the bytes are written straight from the file image
	// (zero-copy) and only the highlighted caret string is converted to a string.
	pack := func(top int) (lines []string, last int) {
		lines = make([]string, 0, visible)
		var line strings.Builder
		line.Grow(m.width + len(sep))
		lineW := 0
		last = top - 1
		for i := top; i < n; i++ {
			e := m.stringsList[m.stringsFiltered[i]]
			sw, trunc := flowWidth(e)
			need := sw
			if lineW > 0 {
				need += flowSepW
			}
			if lineW > 0 && lineW+need > m.width {
				lines = append(lines, line.String())
				if len(lines) >= visible {
					return lines, last
				}
				line.Reset()
				lineW = 0
				need = sw
			}
			if lineW > 0 {
				line.WriteString(sep)
			}
			b := m.file.StringBytes(e)
			switch {
			case i == m.stringsCur:
				line.WriteString(m.theme.tableSelStyle.Render(flowText(b, trunc)))
			case trunc:
				line.Write(b[:flowMaxLen])
				line.WriteRune('…')
			default:
				line.Write(b)
			}
			lineW += need
			last = i
		}
		if lineW > 0 && len(lines) < visible {
			lines = append(lines, line.String())
		}
		return lines, last
	}

	// When the wheel has detached the viewport, render from the scrolled top as-is
	// (the caret may be off-screen); otherwise keep the caret visible.
	if m.viewportDetached {
		m.stringsTop = clamp(m.stringsTop, 0, max(0, n-1))
	} else if m.stringsCur < m.stringsTop {
		m.stringsTop = m.stringsCur
	}
	lines, last := pack(m.stringsTop)
	if !m.viewportDetached && m.stringsCur > last { // caret past the bottom — bring it up
		m.stringsTop = m.stringsCur
		lines, _ = pack(m.stringsTop)
	}
	m.renderedStringsTop = m.stringsTop
	rows := append([]string{filterRow}, lines...)
	return padBodyRows(rows, m.width, bodyH)
}

// flowSepW is the visible width of the " · " separator; flowMaxLen bounds a single
// flowed string so one entry can't fill the view (printable runs carry no newlines).
const (
	flowSepW   = 3
	flowMaxLen = 200
)

// flowWidth is the rendered width of a flowed string (== byte length for printable
// ASCII) and whether it was truncated to flowMaxLen. Uses the entry length only —
// no string copy — so the scroll/pack hot paths don't allocate per string.
func flowWidth(e binfile.StringEntry) (w int, trunc bool) {
	if int(e.Len) > flowMaxLen {
		return flowMaxLen + 1, true // flowMaxLen bytes + the "…"
	}
	return int(e.Len), false
}

// flowText materialises a flowed string (only needed for the highlighted caret).
func flowText(b []byte, trunc bool) string {
	if trunc {
		return string(b[:flowMaxLen]) + "…"
	}
	return string(b)
}

// flowStrW is the rendered width of the i-th filtered string in the compact flow.
func (m *Model) flowStrW(i int) int {
	w, _ := flowWidth(m.stringsList[m.stringsFiltered[i]])
	return w
}

// flowLineEnd returns the exclusive end index of the compact-flow line that starts
// at `top`: at least one string, then as many as fit `width`. Mirrors pack().
func (m *Model) flowLineEnd(top, width int) int {
	w, i := 0, top
	for i < len(m.stringsFiltered) {
		add := m.flowStrW(i)
		if w > 0 {
			add += flowSepW
		}
		if w > 0 && w+add > width {
			break
		}
		w += add
		i++
	}
	if i == top { // a single over-wide string still occupies its own line
		return top + 1
	}
	return i
}

// flowLineStart returns the start index of the line ending just before `top` — the
// exact inverse of flowLineEnd, so scrolling up then down returns to the same place.
func (m *Model) flowLineStart(top, width int) int {
	if top <= 0 {
		return 0
	}
	w, i := 0, top-1
	for i >= 0 {
		add := m.flowStrW(i)
		if w > 0 {
			add += flowSepW
		}
		if w > 0 && w+add > width {
			break
		}
		w += add
		i--
	}
	return i + 1
}

// flowStringAt maps a click at flow line `line` (0-based within the body, after
// the filter row) and column x to a string index, packing from `top` exactly like
// the renderer. A click in the separator gap selects the following string.
func (m *Model) flowStringAt(top, line, x int) (int, bool) {
	if line < 0 {
		return 0, false
	}
	curLine, col := 0, 0
	for i := top; i < len(m.stringsFiltered); i++ {
		sw, _ := flowWidth(m.stringsList[m.stringsFiltered[i]])
		if col > 0 && col+flowSepW+sw > m.width { // wrap, mirroring pack()
			curLine++
			col = 0
		}
		if curLine > line {
			return 0, false
		}
		end := col + sw
		if col > 0 {
			end += flowSepW
		}
		if curLine == line && x >= col && x < end {
			return i, true
		}
		col = end
	}
	return 0, false
}

// flowLineStartOf returns the start index of the compact-flow line that the
// string idx sits on. It anchors at the rendered top (a known line boundary) and
// walks the few lines to idx, so the result is stable under the same packing.
func (m *Model) flowLineStartOf(idx int) int {
	ls := m.stringsTop
	if idx < ls {
		for ls > 0 && idx < ls {
			ls = m.flowLineStart(ls, m.width)
		}
		return ls
	}
	for {
		end := m.flowLineEnd(ls, m.width)
		if idx < end || end >= len(m.stringsFiltered) {
			return ls
		}
		ls = end
	}
}

// flowColInLine returns the visual start column of string idx on the line that
// starts at ls.
func (m *Model) flowColInLine(ls, idx int) int {
	col := 0
	for i := ls; i < idx; i++ {
		col += m.flowStrW(i) + flowSepW
	}
	return col
}

// flowStringInLine returns the string on the line starting at ls whose span
// covers column col, or the last string on the line when col is past its end.
func (m *Model) flowStringInLine(ls, col int) int {
	end := m.flowLineEnd(ls, m.width)
	c := 0
	for i := ls; i < end; i++ {
		sw := m.flowStrW(i)
		if col < c+sw { // within the string's text
			return i
		}
		c += sw + flowSepW
		if col < c { // within the separator following it
			return i
		}
	}
	return end - 1
}

// flowMoveLine moves the caret dl visual lines (−1 up, +1 down) in the compact
// flow, holding roughly the same column.
func (m *Model) flowMoveLine(dl int) {
	n := len(m.stringsFiltered)
	if n == 0 {
		return
	}
	ls := m.flowLineStartOf(m.stringsCur)
	col := m.flowColInLine(ls, m.stringsCur)
	var target int
	if dl > 0 {
		target = m.flowLineEnd(ls, m.width)
		if target >= n { // already on the last line
			return
		}
	} else {
		if ls <= 0 { // already on the first line
			return
		}
		target = m.flowLineStart(ls, m.width)
	}
	m.stringsCur = m.flowStringInLine(target, col)
}

// scrollStringsFlow moves the compact view by delta lines (wheel scrolling).
func (m *Model) scrollStringsFlow(delta int) {
	for ; delta > 0; delta-- {
		next := m.flowLineEnd(m.stringsTop, m.width)
		if next >= len(m.stringsFiltered) {
			break
		}
		m.stringsTop = next
	}
	for ; delta < 0 && m.stringsTop > 0; delta++ {
		m.stringsTop = m.flowLineStart(m.stringsTop, m.width)
	}
}

func (m *Model) stringRowHeight(i int) int {
	if i < 0 || i >= len(m.stringsFiltered) {
		return 1
	}
	addrW := m.file.AddrHexWidth()
	key := rowCacheKey{i, m.width, addrW, m.wrap}
	if m.stringHeightCache != nil {
		if h, ok := m.stringHeightCache[key]; ok {
			return h
		}
	}
	line := m.stringRow(i, addrW)
	h := len(renderLineRowsIndented(line, m.width, m.wrap, addrW+33))
	if m.stringHeightCache == nil {
		m.stringHeightCache = make(map[rowCacheKey]int)
	}
	m.stringHeightCache[key] = h
	return h
}

func (m *Model) stringRow(i, addrW int) string {
	key := rowCacheKey{i, m.width, addrW, m.wrap}
	if m.stringRowCache != nil {
		if s, ok := m.stringRowCache[key]; ok {
			return s
		}
	}

	s := m.stringsList[m.stringsFiltered[i]]
	addr := strings.Repeat(" ", 2+addrW)
	if s.HasAddr {
		addr = fmt.Sprintf("0x%0*x", addrW, s.Addr)
	}
	full := m.file.StringText(s)
	text := sanitizeString(full)
	if m.wrap {
		text = full
	}
	line := fmt.Sprintf(" %s %s %s  %s",
		m.theme.addrStyle.Render(fmt.Sprintf("0x%-8x", s.Offset)),
		m.theme.addrStyle.Render(padVisual(addr, 2+addrW)),
		m.theme.footerStyle.Render(padVisual(truncateMiddle(s.Section, 16), 16)),
		m.theme.tableRowStyle.Render(text))
	line = m.stringRowStyle(s).Render(line)

	if m.stringRowCache == nil {
		m.stringRowCache = make(map[rowCacheKey]string)
	}
	m.stringRowCache[key] = line
	return line
}

// stringRowStyle colours a string row by the category of its owning section
// (matching the Sections and Hex views); unmapped strings render dim.
func (m *Model) stringRowStyle(s binfile.StringEntry) lipgloss.Style {
	if sec := m.sectionAtOffset(s.Offset); sec != nil {
		return m.theme.styleForSection(sec)
	}
	// srcShadowStyle is dim like footerStyle but, unlike it, carries no
	// horizontal padding (which would over-widen a full-width row and wrap).
	return m.theme.srcShadowStyle
}

// sanitizeString collapses control bytes (none should remain from extraction,
// but be defensive) and caps the visible length so one long string can't blow
// out the row.
func sanitizeString(s string) string {
	const maxLen = 160
	if len(s) > maxLen {
		s = s[:maxLen-1] + "…"
	}
	return s
}
