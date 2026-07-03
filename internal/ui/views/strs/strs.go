// Package strs implements the Strings view: the printable runs found in the
// file (à la strings(1)), each annotated with its file offset and — when the
// bytes are mapped — the virtual address and owning section. Enter jumps a
// mapped string into the hex view; `t` toggles a compact "·"-separated flow
// layout. Like the other extracted views, it depends only on a view.Context
// (render inputs) and a view.Host (actions). (The package is "strs", not
// "strings", to avoid colliding with the standard library.)
package strs

import (
	"fmt"
	"sort"
	"strings"

	"charm.land/bubbles/v2/textinput"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/ui/layout"
	"github.com/rabarbra/exex/internal/ui/view"
)

// SortField is the display order of the (filtered) strings list.
type SortField uint8

const (
	SortOffset SortField = iota // file order (the natural extraction order)
	SortAddr
	SortText
)

// String returns the sort's filter-status label.
func (s SortField) String() string {
	switch s {
	case SortAddr:
		return "address"
	case SortText:
		return "string"
	}
	return "offset"
}

// State stores list, filter and cache state for the Strings view.
type State struct {
	List        []binfile.StringEntry
	Filter      textinput.Model
	Filtered    []int // indices into List
	Cur         int   // index into Filtered
	Top         int
	RenderedTop int // Top as of the last render, for mouse hit-testing
	Sort        SortField
	SortDesc    bool
	SecOn       bool     // owning-section facet filter active
	Sec         string   // the section it restricts to
	Sections    []string // distinct owning sections, for cycling
	PathsOnly   bool     // show only path/URL-looking strings
	Compact     bool     // the "·"-separated flow layout instead of the table

	rowCache    layout.RowMemo[view.RowCacheKey, string]
	heightCache layout.RowMemo[view.RowCacheKey, int]
}

// DropCaches drops cached string rows and heights.
func (st *State) DropCaches() {
	st.rowCache = nil
	st.heightCache = nil
}

// Ensure extracts the file's printable strings lazily and builds the
// (initially unfiltered) view list.
func (st *State) Ensure(ctx view.Context) {
	if st.List == nil {
		st.List = ctx.File.Strings()
		st.BuildSections()
		st.Recompute(ctx)
	}
}

// buildSections collects the distinct owning-section names (sorted) so the
// ctrl+s filter can cycle through them.
func (st *State) BuildSections() {
	seen := map[string]bool{}
	st.Sections = st.Sections[:0]
	for _, s := range st.List {
		if s.Section != "" && !seen[s.Section] {
			seen[s.Section] = true
			st.Sections = append(st.Sections, s.Section)
		}
	}
	sort.Strings(st.Sections)
}

// cycleSectionFilter steps the section filter off → first → … → last → off.
func (st *State) cycleSectionFilter(host view.Host) {
	if len(st.Sections) == 0 {
		host.SetStatus("no section info for strings", false)
		return
	}
	if !st.SecOn {
		st.SecOn = true
		st.Sec = st.Sections[0]
		host.SetStatus("string section filter: "+st.Sec, false)
		return
	}
	for i, sec := range st.Sections {
		if sec == st.Sec {
			if i == len(st.Sections)-1 {
				st.SecOn = false
				host.SetStatus("string section filter: all", false)
				return
			}
			st.Sec = st.Sections[i+1]
			host.SetStatus("string section filter: "+st.Sec, false)
			return
		}
	}
	st.SecOn = false
}

// applySort orders Filtered by the active field. The natural order is
// offset-ascending (strings are extracted in offset order), so that case only
// needs reversing for descending.
func (st *State) applySort(ctx view.Context) {
	desc := st.SortDesc
	if st.Sort == SortOffset {
		if desc {
			layout.ReverseInts(st.Filtered)
		}
		return
	}
	sort.SliceStable(st.Filtered, func(a, b int) bool {
		sa, sb := st.List[st.Filtered[a]], st.List[st.Filtered[b]]
		var less bool
		switch st.Sort {
		case SortAddr:
			less = sa.Addr < sb.Addr
		case SortText:
			less = string(ctx.File.StringBytes(sa)) < string(ctx.File.StringBytes(sb))
		}
		if desc {
			return !less
		}
		return less
	})
}

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

// Recompute rebuilds Filtered from the current filter text, matching on the
// string text and its owning section.
func (st *State) Recompute(ctx view.Context) {
	st.DropCaches()
	needle := strings.ToLower(st.Filter.Value())
	st.Filtered = st.Filtered[:0]
	for i, s := range st.List {
		if st.SecOn && s.Section != st.Sec {
			continue
		}
		// Filter on the raw bytes (zero-copy) so scanning millions of strings on
		// each keystroke doesn't allocate a copy per entry.
		b := ctx.File.StringBytes(s)
		if st.PathsOnly && !looksLikePath(b) {
			continue
		}
		if needle == "" || layout.ContainsFoldBytes(b, needle) || layout.ContainsFold(s.Section, needle) {
			st.Filtered = append(st.Filtered, i)
		}
	}
	st.applySort(ctx)
	if st.Cur >= len(st.Filtered) {
		st.Cur = max(0, len(st.Filtered)-1)
	}
}

// Current returns the selected string through the active filter.
func (st *State) Current() (binfile.StringEntry, bool) {
	if st.Cur < 0 || st.Cur >= len(st.Filtered) {
		return binfile.StringEntry{}, false
	}
	return st.List[st.Filtered[st.Cur]], true
}

// CaretAddr returns the address of the string under the cursor, for the shell's
// cross-view "open caret in…" jump. ok is false for strings with no mapped
// address (e.g. those living only in an unallocated file region).
func (st *State) CaretAddr() (uint64, bool) {
	if s, ok := st.Current(); ok && s.Addr != 0 {
		return s.Addr, true
	}
	return 0, false
}

// StringAt returns the string whose mapped range covers addr, building the string
// list on first need. Used by the cross-view jump modal to preview and offer a
// "open in Strings" destination when the caret address falls inside a string.
func (st *State) StringAt(ctx view.Context, addr uint64) (binfile.StringEntry, bool) {
	st.Ensure(ctx)
	for _, s := range st.List {
		if s.HasAddr && addr >= s.Addr && addr < s.Addr+uint64(s.Len) {
			return s, true
		}
	}
	return binfile.StringEntry{}, false
}

// StringAtOffset returns the string whose file range covers off. Every string has
// a file offset (unlike a virtual address), so this is the lookup the jump modal
// uses from an offset-only caret (the Raw view over an unmapped region).
func (st *State) StringAtOffset(ctx view.Context, off uint64) (binfile.StringEntry, bool) {
	st.Ensure(ctx)
	for _, s := range st.List {
		if off >= s.Offset && off < s.Offset+uint64(s.Len) {
			return s, true
		}
	}
	return binfile.StringEntry{}, false
}

// SelectByAddr moves the cursor to the string covering addr (the shell's "open
// caret in Strings" jump), clearing filters that would hide it. Reports whether
// one was found.
func (st *State) SelectByAddr(ctx view.Context, addr uint64) bool {
	return st.selectMatching(ctx, func(s binfile.StringEntry) bool {
		return s.HasAddr && addr >= s.Addr && addr < s.Addr+uint64(s.Len)
	})
}

// SelectByOffset moves the cursor to the string covering file offset off (the
// offset-only counterpart of SelectByAddr).
func (st *State) SelectByOffset(ctx view.Context, off uint64) bool {
	return st.selectMatching(ctx, func(s binfile.StringEntry) bool {
		return off >= s.Offset && off < s.Offset+uint64(s.Len)
	})
}

// selectMatching clears the filters and moves the cursor to the first string
// satisfying pred, reporting whether one was found.
func (st *State) selectMatching(ctx view.Context, pred func(binfile.StringEntry) bool) bool {
	st.Ensure(ctx)
	st.Filter.SetValue("")
	st.SecOn = false
	st.Recompute(ctx)
	for i, idx := range st.Filtered {
		if pred(st.List[idx]) {
			st.Cur, st.Top = i, 0
			return true
		}
	}
	return false
}

// Update handles keys while the Strings view is active. A focused filter input
// is captured centrally by the host, so by the time a key reaches here it is
// navigation or an action.
func (st *State) Update(ctx view.Context, host view.Host, key string) {
	st.Ensure(ctx)
	// In the compact flow the strings tile a 2-D grid: ←/→ step one string along
	// the flow, ↑/↓ move a visual line keeping roughly the same column (so a long
	// scan reads like text, not a single ribbon).
	if st.Compact {
		switch key {
		case "left":
			st.Cur = max(0, st.Cur-1)
			return
		case "right":
			st.Cur = min(len(st.Filtered)-1, st.Cur+1)
			return
		case "up":
			st.flowMoveLine(ctx, -1)
			return
		case "down":
			st.flowMoveLine(ctx, 1)
			return
		case "pgup", "[": // also ⌥↑ / ctrl+↑ (normalised to pgup)
			for p := max(1, host.ListPage()); p > 0; p-- {
				st.flowMoveLine(ctx, -1)
			}
			return
		case "pgdown", "]": // also ⌥↓ / ctrl+↓
			for p := max(1, host.ListPage()); p > 0; p-- {
				st.flowMoveLine(ctx, 1)
			}
			return
		case "home": // also cmd+↑
			st.Cur = 0
			return
		case "end", "G": // also cmd+↓
			st.Cur = max(0, len(st.Filtered)-1)
			return
		}
	}
	if layout.NavKey(&st.Cur, len(st.Filtered), host.ListPage(), key) {
		return
	}
	switch key {
	case "t":
		st.Compact = !st.Compact
		mode := "table"
		if st.Compact {
			mode = "compact"
		}
		host.SetStatus("strings: "+mode, false)
	case "/":
		st.Filter.Focus()
	case "esc":
		dirty := st.SecOn || st.PathsOnly || st.Filter.Value() != "" || st.Filter.Focused()
		st.SecOn = false
		st.PathsOnly = false
		st.Filter.SetValue("")
		st.Filter.Blur()
		st.Cur, st.Top = 0, 0
		st.Recompute(ctx)
		if dirty {
			host.SetStatus("filters cleared", false)
		}
	case "ctrl+s":
		st.cycleSectionFilter(host)
		st.Cur, st.Top = 0, 0
		st.Recompute(ctx)
	case "ctrl+p":
		st.PathsOnly = !st.PathsOnly
		st.Cur, st.Top = 0, 0
		st.Recompute(ctx)
		state := "off"
		if st.PathsOnly {
			state = "on"
		}
		host.SetStatus("paths only: "+state, false)
	case "s":
		st.Sort = (st.Sort + 1) % 3
		st.Cur, st.Top = 0, 0
		st.Recompute(ctx)
		host.SetStatus("sort: "+st.Sort.String(), false)
	case "r":
		st.SortDesc = !st.SortDesc
		st.Cur, st.Top = 0, 0
		st.Recompute(ctx)
		dir := "ascending"
		if st.SortDesc {
			dir = "descending"
		}
		host.SetStatus("sort order: "+dir, false)
	case "w":
		host.ToggleWrap()
	case "d":
		if s, ok := st.Current(); ok && s.HasAddr {
			host.JumpDisasmAtAddr(s.Addr)
		} else {
			host.SetStatus("string has no mapped address", true)
		}
	case "h":
		if s, ok := st.Current(); ok && s.HasAddr {
			host.JumpHexAtAddr(s.Addr)
		} else {
			host.SetStatus("string has no mapped address", true)
		}
	case "m":
		if s, ok := st.Current(); ok {
			host.OpenRawAt(s.Offset)
		}
	case "enter":
		if s, ok := st.Current(); ok {
			if s.HasAddr {
				host.OpenHexAt(s.Addr)
			} else {
				host.OpenRawAt(s.Offset)
			}
		}
	case "A":
		if s, ok := st.Current(); ok {
			if s.HasAddr {
				host.CopyToClipboard(fmt.Sprintf("0x%0*x", ctx.File.AddrHexWidth(), s.Addr), "address")
			} else {
				host.CopyToClipboard(fmt.Sprintf("0x%x", s.Offset), "offset")
			}
		}
	case "S":
		if s, ok := st.Current(); ok {
			host.CopyToClipboard(ctx.File.StringText(s), "string")
		}
	}
}

// ClickHeader handles a click on the table's sortable header row.
func (st *State) ClickHeader(ctx view.Context, host view.Host, x int) bool {
	st.Ensure(ctx)
	if len(st.List) == 0 {
		return false
	}
	sort, ok := layout.HitSortableHeader(st.headerCols(ctx), x)
	if !ok {
		return false
	}
	fieldChanged := layout.ApplySortHeaderClick(&st.Sort, &st.SortDesc, sort)
	st.Cur, st.Top = 0, 0
	st.Recompute(ctx)
	if fieldChanged {
		host.SetStatus("sort: "+st.Sort.String(), false)
	} else {
		host.SetStatus("sort order: "+layout.SortDirectionLabel(st.SortDesc), false)
	}
	return true
}

// headerCols maps the table's header columns to their x ranges, matching the
// layout in Render / rowText.
func (st *State) headerCols(ctx view.Context) []layout.SortableHeaderCol[SortField] {
	addrW := ctx.File.AddrHexWidth()
	addrCol := 2 + addrW
	addrStart := 12
	stringStart := addrW + 33
	return []layout.SortableHeaderCol[SortField]{
		{Start: 1, End: 11, Sort: SortOffset},
		{Start: addrStart, End: addrStart + addrCol, Sort: SortAddr},
		{Start: stringStart, End: ctx.Width, Sort: SortText},
	}
}

// Render draws the view body.
func (st *State) Render(ctx view.Context, host view.Host) string {
	bodyH := ctx.BodyH
	if bodyH < 2 {
		bodyH = 2
	}
	st.Ensure(ctx)
	if len(st.List) == 0 {
		return ctx.EmptyBody("no printable strings found")
	}

	filterRow := st.Filter.View()
	if !st.Filter.Focused() {
		secLabel := "all"
		if st.SecOn {
			secLabel = st.Sec
		}
		dir := "↑"
		if st.SortDesc {
			dir = "↓"
		}
		pathsLabel := "off"
		if st.PathsOnly {
			pathsLabel = "on"
		}
		filterRow = ctx.FooterStyle.Render(fmt.Sprintf("/ %s   (%d / %d)   ", st.Filter.Value(), len(st.Filtered), len(st.List))) +
			ctx.KeyStyle.Render(layout.CtrlKeys("s")) + ctx.FooterStyle.Render(" section:"+secLabel) +
			ctx.FooterStyle.Render("   ") + ctx.KeyStyle.Render(layout.CtrlKeys("p")) + ctx.FooterStyle.Render(" paths:"+pathsLabel) +
			ctx.FooterStyle.Render("   ") + ctx.KeyStyle.Render("s") + ctx.FooterStyle.Render(" sort:"+st.Sort.String()+dir)
	}

	if st.Compact {
		return st.renderFlow(ctx, bodyH, filterRow)
	}

	addrW := ctx.File.AddrHexWidth()
	addrCol := 2 + addrW
	offsetLabel := layout.SortHeaderLabel("Offset", 10, SortOffset, st.Sort, st.SortDesc)
	addrLabel := layout.SortHeaderLabel("Address", addrCol, SortAddr, st.Sort, st.SortDesc)
	stringLabel := layout.TrailingSortHeaderLabel("String", SortText, st.Sort, st.SortDesc)
	hdr := fmt.Sprintf(" %-10s %-*s %-16s  %s", offsetLabel, 2+addrW, addrLabel, "Section", stringLabel)
	header := ctx.TableHeader(hdr)

	visible := bodyH - 2 // filter row + header
	if visible < 1 {
		visible = 1
	}
	rowHeight := st.RowHeightFn(ctx)
	top := ctx.VisualTop(st.Cur, st.Top, len(st.Filtered), visible, rowHeight)
	st.Top = top
	st.RenderedTop = top
	host.SetPageRows(layout.PageStep(top, len(st.Filtered), visible, rowHeight))

	if len(st.Filtered) == 0 {
		return ctx.EmptyList("no matching strings  ·  Esc clears filters", filterRow, header)
	}
	rows := []string{filterRow, header}
	for i := top; i < len(st.Filtered); i++ {
		line := st.row(ctx, i, addrW)
		if i == st.Cur {
			line = ctx.SelStyle.Render(ansi.Strip(line))
		}
		if !layout.AppendRenderedRowsIndented(&rows, line, ctx.Width, ctx.Wrap, addrW+33, bodyH) {
			break
		}
	}
	return layout.PadBodyRows(rows, ctx.Width, bodyH)
}

// renderFlow draws the compact strings view: every string laid out inline,
// separated by a middle dot and wrapped to the width — no address/section/offset
// columns. The selected string (caret) is highlighted and the view scrolls to keep
// it visible; ←/→ and ↑/↓ all step the selection.
func (st *State) renderFlow(ctx view.Context, bodyH int, filterRow string) string {
	sep := ctx.ShadowStyle.Render(" · ")
	visible := max(1, bodyH-1) // filter row
	n := len(st.Filtered)

	// pack lays strings out from top into at most `visible` lines, returning the
	// rendered lines and the last string index shown. Strings are printable ASCII
	// (width == byte length), so the bytes are written straight from the file image
	// (zero-copy) and only the highlighted caret string is converted to a string.
	pack := func(top int) (lines []string, last int) {
		lines = make([]string, 0, visible)
		var line strings.Builder
		line.Grow(ctx.Width + len(sep))
		lineW := 0
		last = top - 1
		for i := top; i < n; i++ {
			e := st.List[st.Filtered[i]]
			sw, trunc := flowWidth(e)
			need := sw
			if lineW > 0 {
				need += flowSepW
			}
			if lineW > 0 && lineW+need > ctx.Width {
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
			b := ctx.File.StringBytes(e)
			switch {
			case i == st.Cur:
				line.WriteString(ctx.SelStyle.Render(flowText(b, trunc)))
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
	if ctx.Detached {
		st.Top = layout.Clamp(st.Top, 0, max(0, n-1))
	} else if st.Cur < st.Top {
		st.Top = st.Cur
	}
	lines, last := pack(st.Top)
	if !ctx.Detached && st.Cur > last { // caret past the bottom — bring it up
		st.Top = st.Cur
		lines, _ = pack(st.Top)
	}
	st.RenderedTop = st.Top
	rows := append([]string{filterRow}, lines...)
	return layout.PadBodyRows(rows, ctx.Width, bodyH)
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
func (st *State) flowStrW(i int) int {
	w, _ := flowWidth(st.List[st.Filtered[i]])
	return w
}

// flowLineEnd returns the exclusive end index of the compact-flow line that starts
// at `top`: at least one string, then as many as fit `width`. Mirrors pack().
func (st *State) flowLineEnd(top, width int) int {
	w, i := 0, top
	for i < len(st.Filtered) {
		add := st.flowStrW(i)
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
func (st *State) flowLineStart(top, width int) int {
	if top <= 0 {
		return 0
	}
	w, i := 0, top-1
	for i >= 0 {
		add := st.flowStrW(i)
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

// FlowStringAt maps a click at flow line `line` (0-based within the body, after
// the filter row) and column x to a string index, packing from `top` exactly like
// the renderer. A click in the separator gap selects the following string.
func (st *State) FlowStringAt(ctx view.Context, top, line, x int) (int, bool) {
	if line < 0 {
		return 0, false
	}
	curLine, col := 0, 0
	for i := top; i < len(st.Filtered); i++ {
		sw, _ := flowWidth(st.List[st.Filtered[i]])
		if col > 0 && col+flowSepW+sw > ctx.Width { // wrap, mirroring pack()
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
func (st *State) flowLineStartOf(idx, width int) int {
	ls := st.Top
	if idx < ls {
		for ls > 0 && idx < ls {
			ls = st.flowLineStart(ls, width)
		}
		return ls
	}
	for {
		end := st.flowLineEnd(ls, width)
		if idx < end || end >= len(st.Filtered) {
			return ls
		}
		ls = end
	}
}

// flowColInLine returns the visual start column of string idx on the line that
// starts at ls.
func (st *State) flowColInLine(ls, idx int) int {
	col := 0
	for i := ls; i < idx; i++ {
		col += st.flowStrW(i) + flowSepW
	}
	return col
}

// flowStringInLine returns the string on the line starting at ls whose span
// covers column col, or the last string on the line when col is past its end.
func (st *State) flowStringInLine(ls, col, width int) int {
	end := st.flowLineEnd(ls, width)
	c := 0
	for i := ls; i < end; i++ {
		sw := st.flowStrW(i)
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
func (st *State) flowMoveLine(ctx view.Context, dl int) {
	n := len(st.Filtered)
	if n == 0 {
		return
	}
	ls := st.flowLineStartOf(st.Cur, ctx.Width)
	col := st.flowColInLine(ls, st.Cur)
	var target int
	if dl > 0 {
		target = st.flowLineEnd(ls, ctx.Width)
		if target >= n { // already on the last line
			return
		}
	} else {
		if ls <= 0 { // already on the first line
			return
		}
		target = st.flowLineStart(ls, ctx.Width)
	}
	st.Cur = st.flowStringInLine(target, col, ctx.Width)
}

// ScrollFlow moves the compact view by delta lines (wheel scrolling).
func (st *State) ScrollFlow(ctx view.Context, delta int) {
	for ; delta > 0; delta-- {
		next := st.flowLineEnd(st.Top, ctx.Width)
		if next >= len(st.Filtered) {
			break
		}
		st.Top = next
	}
	for ; delta < 0 && st.Top > 0; delta++ {
		st.Top = st.flowLineStart(st.Top, ctx.Width)
	}
}

// RowHeightFn returns the per-row rendered height, for the scroll geometry.
func (st *State) RowHeightFn(ctx view.Context) func(int) int {
	return func(i int) int {
		if i < 0 || i >= len(st.Filtered) {
			return 1
		}
		addrW := ctx.File.AddrHexWidth()
		return st.heightCache.Get(view.RowCacheKey{I: i, Width: ctx.Width, AddrW: addrW, Wrap: ctx.Wrap}, func() int {
			return len(layout.RenderLineRowsIndented(st.row(ctx, i, addrW), ctx.Width, ctx.Wrap, addrW+33))
		})
	}
}

// RowText returns the current row's rendered text, for the copy-line action.
func (st *State) RowText(ctx view.Context) string {
	st.Ensure(ctx)
	if st.Cur < 0 || st.Cur >= len(st.Filtered) {
		return ""
	}
	return st.row(ctx, st.Cur, ctx.File.AddrHexWidth())
}

// row renders one string row, memoised by the layout inputs.
func (st *State) row(ctx view.Context, i, addrW int) string {
	return st.rowCache.Get(view.RowCacheKey{I: i, Width: ctx.Width, AddrW: addrW, Wrap: ctx.Wrap}, func() string {
		return st.rowText(ctx, i, addrW)
	})
}

func (st *State) rowText(ctx view.Context, i, addrW int) string {
	s := st.List[st.Filtered[i]]
	addr := strings.Repeat(" ", 2+addrW)
	if s.HasAddr {
		addr = fmt.Sprintf("0x%0*x", addrW, s.Addr)
	}
	full := ctx.File.StringText(s)
	text := Sanitize(full)
	if ctx.Wrap {
		text = full
	}
	line := fmt.Sprintf(" %s %s %s  %s",
		ctx.AddrStyle.Render(fmt.Sprintf("0x%-8x", s.Offset)),
		ctx.AddrStyle.Render(layout.PadVisual(addr, 2+addrW)),
		ctx.FooterStyle.Render(layout.PadVisual(layout.TruncateMiddle(s.Section, 16), 16)),
		ctx.RowStyle.Render(text))
	return st.rowStyle(ctx, s).Render(line)
}

// rowStyle colours a string row by the category of its owning section (matching
// the Sections and Hex views); unmapped strings render dim.
func (st *State) rowStyle(ctx view.Context, s binfile.StringEntry) lipgloss.Style {
	if sec := ctx.SectionAtOffset(s.Offset); sec != nil {
		return ctx.SectionStyle(sec)
	}
	// ShadowStyle is dim like FooterStyle but, unlike it, carries no horizontal
	// padding (which would over-widen a full-width row and wrap).
	return ctx.ShadowStyle
}

// Sanitize collapses control bytes (none should remain from extraction,
// but be defensive) and caps the visible length so one long string can't blow
// out the row.
func Sanitize(s string) string {
	const maxLen = 160
	if len(s) > maxLen {
		s = s[:maxLen-1] + "…"
	}
	return s
}
