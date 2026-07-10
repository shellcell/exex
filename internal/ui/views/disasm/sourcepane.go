package disasm

// Rendering of the source split pane, in both layouts: source-first (the
// source text leads on the left, RenderSourceAsm follows on the right) and
// disasm-first (the scroller leads, RenderSourcePane follows). The colour
// policy the two layouts share — the line-number gutter and the instruction
// address column — lives here too, so both panes colour identically.

import (
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"

	"github.com/rabarbra/exex/internal/dump"
	"github.com/rabarbra/exex/internal/ui/layout"
	"github.com/rabarbra/exex/internal/ui/view"
)

// gutterWidth is the visible width of the source line-number gutter
// ("12345 ▸ ").
const gutterWidth = 8

// srcGutter renders the line-number gutter for a source line. Only the number
// is coloured — never the whole line: the current (caret) line is highlighted,
// lines that have machine code mapped to them are white, and unmapped lines are
// dimmed. digits is the field width of the number; the returned string is
// digits+3 columns wide ("<num> <marker> ").
func srcGutter(ctx *view.Context, ln, curLine int, mapped map[int]bool, digits int) string {
	switch {
	case ln == curLine:
		return ctx.SrcCurLine.Render(fmt.Sprintf("%*d ▸ ", digits, ln))
	case mapped[ln]:
		return ctx.PlainStyle.Render(fmt.Sprintf("%*d · ", digits, ln))
	default:
		return ctx.ShadowStyle.Render(fmt.Sprintf("%*d   ", digits, ln))
	}
}

// columnStyle returns the style assigned to column value col among the line's
// sorted distinct columns.
func columnStyle(ctx *view.Context, cols []int, col int) (lipgloss.Style, bool) {
	for i, c := range cols {
		if c == col {
			return ctx.ColumnStyleAt(i), true
		}
	}
	return lipgloss.Style{}, false
}

// AddrMapStyle classifies an instruction address against the current source
// location and returns the style its address column should use: dimmed when the
// address maps to no source line, the per-column colour when it maps to the
// current line (so it correlates with the source carets), and white when it
// maps to some other line.
func (st *State) AddrMapStyle(ctx *view.Context, addr uint64, curFile string, curLine int) lipgloss.Style {
	f, l, c := ctx.File.LookupAddrCol(addr)
	switch {
	case f == "" || l == 0:
		return ctx.ShadowStyle
	case curFile != "" && f == curFile && l == curLine:
		if cs, ok := columnStyle(ctx, st.SourceLineColumns(ctx, curFile, curLine), c); ok {
			return cs.Bold(true)
		}
		return ctx.SrcMapped
	default:
		return ctx.PlainStyle
	}
}

// HasOpenSourceFile reports whether a source file is open and readable.
func (st *State) HasOpenSourceFile(ctx *view.Context) bool {
	return st.SrcFile != "" && ctx.File.SourceLines(st.SrcFile) != nil
}

// ScrollRightPane nudges the follower pane's independent scroll offset; the
// renderers clamp it to the pane bounds.
func (st *State) ScrollRightPane(delta int) {
	st.RightScroll += delta
}

// RenderSourceText renders the leading source pane (source-first layout),
// anchoring the viewport around the cursor line and recording SrcPageRows for
// the shell's page-step keys.
func (st *State) RenderSourceText(ctx *view.Context, w, h int) string {
	src := ctx.File.SourceLines(st.SrcFile)
	if len(src) == 0 {
		return layout.PadBody("(source file not found on disk)\n", w, h)
	}
	hl := ctx.HighlightSource(st.SrcFile, src)

	contentH := h - 1
	if contentH < 1 {
		contentH = 1
	}
	top := max(0, st.SrcTop-1)
	top = ctx.VisualTop(st.SrcCur-1, top, len(src), contentH, st.SourceRowHeight(ctx, w))
	st.SrcTop = top + 1
	st.RenderedSrcTop = top
	st.SrcPageRows = layout.PageStep(top, len(src), contentH, st.SourceRowHeight(ctx, w))

	var b strings.Builder
	suffix := fmt.Sprintf(":%d", st.SrcCur)
	b.WriteString(ctx.ViewTitle(layout.TruncateMiddle(st.SrcFile, max(1, w-lipgloss.Width(suffix)))+suffix, w))
	b.WriteString("\n")

	rows := 0
	for ln := top + 1; ln <= len(src) && rows < contentH; ln++ {
		// The code is always shown syntax-highlighted; only the gutter colour
		// reflects the mapping (shared srcGutter policy, used by both panes).
		content := src[ln-1]
		if hl != nil && ln-1 < len(hl) {
			content = hl[ln-1]
		}

		prefix := srcGutter(ctx, ln, st.SrcCur, st.SrcCodeLines, 5)
		avail := w - lipgloss.Width(prefix)
		line := prefix + layout.FitANSIWidth(content, avail)
		if ctx.Wrap {
			line = prefix + content
		}
		for _, row := range layout.RenderLineRowsIndented(line, w, ctx.Wrap, gutterWidth) {
			if rows >= contentH {
				break
			}
			b.WriteString(row)
			b.WriteString("\n")
			rows++
		}

		// Beneath the cursor line, point carets at the exact columns code maps
		// to (a source line can map at several positions).
		if ln == st.SrcCur && rows < contentH {
			if caret := coloredCaretRow(ctx, st.SourceLineColumns(ctx, st.SrcFile, ln), gutterWidth, w); caret != "" {
				b.WriteString(caret)
				b.WriteString("\n")
				rows++
			}
		}
	}
	return layout.PadBody(b.String(), w, h)
}

// SourceRowHeight returns the per-line rendered-height function for the source
// pane at width w (the cursor line is one taller when it carries a caret row).
// Shared by every place that runs the source-pane scroll math.
func (st *State) SourceRowHeight(ctx *view.Context, w int) func(int) int {
	return func(i int) int {
		ln := i + 1
		h := st.sourceLineHeight(ctx, ln, w)
		if ln == st.SrcCur && len(st.SourceLineColumns(ctx, st.SrcFile, ln)) > 0 {
			h++
		}
		return h
	}
}

// SourceTextTop is the first line the source pane would render at the current
// scroll state (the mouse click mapping runs the same math as the renderer).
func (st *State) SourceTextTop(ctx *view.Context, w, contentH int) int {
	src := ctx.File.SourceLines(st.SrcFile)
	return ctx.VisualTop(st.SrcCur-1, max(0, st.SrcTop-1), len(src), contentH, st.SourceRowHeight(ctx, w))
}

func (st *State) sourceLineHeight(ctx *view.Context, line, w int) int {
	if !ctx.Wrap {
		return 1
	}
	src := ctx.File.SourceLines(st.SrcFile)
	if line < 1 || line > len(src) {
		return 1
	}
	key := SourceLineHeightKey{File: st.SrcFile, Line: line, W: w}
	if h, ok := st.SrcLineHeightCache[key]; ok {
		return h
	}
	plainPrefix := fmt.Sprintf("%5d   ", line)
	h := len(layout.RenderLineRowsIndented(plainPrefix+src[line-1], w, true, gutterWidth))
	if st.SrcLineHeightCache == nil {
		st.SrcLineHeightCache = make(map[SourceLineHeightKey]int)
	}
	st.SrcLineHeightCache[key] = h
	return h
}

// coloredCaretRow renders a '^' under each mapped column, each in that column's
// assigned colour (so it matches the highlighted instructions in the asm pane).
func coloredCaretRow(ctx *view.Context, cols []int, gutterW, w int) string {
	if len(cols) == 0 {
		return ""
	}
	maxc := cols[len(cols)-1]
	cells := make([]string, maxc)
	for i := range cells {
		cells[i] = " "
	}
	for i, c := range cols {
		if c >= 1 && c <= maxc {
			cells[c-1] = ctx.ColumnStyleAt(i).Bold(true).Render("^")
		}
	}
	row := strings.Repeat(" ", gutterW) + strings.Join(cells, "")
	return layout.FitANSIWidth(row, w)
}

// RenderSourceAsm renders the disassembly beside the source (source-first
// layout). Instructions that map to the current source line are highlighted in
// their column's colour (so they correlate with the carets under the line); a
// line can map to several, non-contiguous instructions and they're all shown.
// The shell ensures a decode happened before calling.
func (st *State) RenderSourceAsm(ctx *view.Context, w, h int) string {
	if len(st.Inst) == 0 {
		return layout.PadBody("no executable code\n", w, h)
	}

	anchor := st.sourceAsmAnchorIndex(ctx)
	cols := st.SourceLineColumns(ctx, st.SrcFile, st.SrcCur)
	head := st.sourceAsmHeader(ctx, anchor, cols, w)

	contentH := h - 1
	if contentH < 1 {
		contentH = 1
	}
	top := clampScroll(anchor-4+st.RightScroll, len(st.Inst), contentH)
	end := top + contentH
	if end > len(st.Inst) {
		end = len(st.Inst)
	}

	var b strings.Builder
	b.WriteString(head)
	b.WriteString("\n")
	addrW := ctx.File.AddrHexWidth()
	for i := top; i < end; i++ {
		b.WriteString(st.sourceAsmRow(ctx, i, addrW, w))
		b.WriteString("\n")
	}
	return layout.PadBody(b.String(), w, h)
}

func (st *State) sourceAsmHeader(ctx *view.Context, anchor int, cols []int, w int) string {
	const minSymbolHeaderWidth = 12
	sep := "  ·  "
	sepW := lipgloss.Width(sep)
	linePlain := fmt.Sprintf("line %d", st.SrcCur)
	colsPlain := ""
	if len(cols) > 0 {
		colsPlain = "cols " + intsString(cols)
	}
	origColsPlain := colsPlain
	name := ""
	if anchor >= 0 && anchor < len(st.Inst) {
		addr := st.Inst[anchor].Addr
		if sym, ok := ctx.File.SymbolAt(addr); ok {
			name = ctx.SymbolDisplay(sym)
			if off := addr - sym.Addr; off > 0 {
				name = fmt.Sprintf("%s+0x%x", name, off)
			}
		}
	}

	lineW := lipgloss.Width(linePlain)
	if name != "" && colsPlain != "" {
		colsBudget := w - lineW - sepW - sepW - minSymbolHeaderWidth
		colsPlain = layout.TruncateMiddle(colsPlain, max(1, colsBudget))
	}
	fixedW := lineW
	if colsPlain != "" {
		fixedW += sepW + lipgloss.Width(colsPlain)
	}

	var parts []string
	if name != "" {
		name = layout.TruncateMiddle(name, max(1, w-fixedW-sepW))
		parts = append(parts, ctx.SymStyle.Render(name))
	}
	parts = append(parts, linePlain)
	if colsPlain != "" {
		if colsPlain == origColsPlain {
			parts = append(parts, "cols "+coloredCols(ctx, cols))
		} else {
			parts = append(parts, colsPlain)
		}
	}
	return ctx.ViewTitle(strings.Join(parts, sep), w)
}

func intsString(v []int) string {
	parts := make([]string, len(v))
	for i, n := range v {
		parts[i] = fmt.Sprintf("%d", n)
	}
	return strings.Join(parts, " ")
}

func (st *State) sourceAsmAnchorIndex(ctx *view.Context) int {
	if len(st.Inst) == 0 {
		return 0
	}
	if addr, ok := ctx.File.LineToAddr(st.SrcFile, st.SrcCur); ok {
		idx := st.IndexAtOrAfter(addr)
		if idx >= 0 && idx < len(st.Inst) {
			return idx
		}
	}
	if st.Cur < 0 {
		return 0
	}
	if st.Cur >= len(st.Inst) {
		return len(st.Inst) - 1
	}
	return st.Cur
}

func (st *State) sourceAsmRow(ctx *view.Context, i, addrW, w int) string {
	return st.SourceAsmRowCache.Get(SourceAsmRowKey{I: i, W: w, File: st.SrcFile, Line: st.SrcCur}, func() string {
		inst := st.Inst[i]
		// Colour only the address by mapping (shared AddrMapStyle policy); the
		// instruction text keeps its normal class colours so the pane reads like
		// real disassembly.
		addrText := fmt.Sprintf("0x%0*x", addrW, inst.Addr)
		addr := st.AddrMapStyle(ctx, inst.Addr, st.SrcFile, st.SrcCur).Render(addrText)
		asm := st.RenderInstText(ctx, dump.AlignAsm(inst.Text), inst.Class, inst.Addr)
		var line string
		if ColumnsFor(ctx).ByteColW > 0 {
			line = fmt.Sprintf(" %s  %s  %s", addr, InstBytes(ctx, inst.Bytes), asm)
		} else {
			line = fmt.Sprintf(" %s  %s", addr, asm)
		}
		return layout.FitANSIWidth(line, w)
	})
}

// clampScroll keeps a viewport top within [0, n-h] so an independent-scroll
// offset can't run the follower pane off either end.
func clampScroll(top, n, h int) int {
	maxTop := n - h
	if maxTop < 0 {
		maxTop = 0
	}
	if top > maxTop {
		top = maxTop
	}
	if top < 0 {
		top = 0
	}
	return top
}

// coloredCols renders the line's column numbers, each in its assigned colour.
func coloredCols(ctx *view.Context, cols []int) string {
	parts := make([]string, len(cols))
	for i, c := range cols {
		parts[i] = ctx.ColumnStyleAt(i).Render(fmt.Sprintf("%d", c))
	}
	return strings.Join(parts, " ")
}

// RenderSourcePane renders the follower source pane beside the disasm scroller
// (disasm-first layout), centred on the line mapped from the cursor's address,
// offset by the independent RightScroll.
func (st *State) RenderSourcePane(ctx *view.Context, w, h int) string {
	border := ctx.PaneBorder
	inner := w - 1
	if inner < 8 {
		inner = w
	}

	if len(st.Inst) == 0 {
		return border.Render(layout.PadBody("", inner, h))
	}
	addr := st.Inst[st.Cur].Addr
	file, line, col := ctx.File.LookupAddrCol(addr)
	if file == "" {
		body := "no source mapping for 0x" + fmt.Sprintf("%x", addr)
		return border.Render(layout.PadBody(body+"\n", inner, h))
	}
	src := ctx.File.SourceLines(file)
	if src == nil {
		suffix := fmt.Sprintf(":%d (source file not found)", line)
		body := ctx.ViewTitle(layout.TruncateMiddle(file, max(1, inner-lipgloss.Width(suffix)))+suffix, inner) + "\n"
		return border.Render(layout.PadBody(body, inner, h))
	}

	hl := ctx.HighlightSource(file, src)
	mapped := st.MappedLines(ctx, file)

	suffix := fmt.Sprintf(":%d", line)
	if col > 0 {
		suffix = fmt.Sprintf(":%d:%d", line, col)
	}
	loc := layout.TruncateMiddle(file, max(1, inner-lipgloss.Width(suffix))) + suffix
	half := (h - 1) / 2
	base := line - half
	from := base + st.RightScroll
	if from < 1 {
		from = 1
	}
	to := from + h - 2
	if to > len(src) {
		to = len(src)
		from = to - (h - 2)
		if from < 1 {
			from = 1
		}
	}
	// Build the lines directly (vs accumulating into one Builder then splitting it
	// back apart in layout.PadBody) — fewer per-frame allocations on this hot path.
	rows := make([]string, 0, h)
	rows = append(rows, ctx.ViewTitle(loc, inner))
	for i := from; i <= to; i++ {
		var content string
		if i-1 >= 0 && i-1 < len(src) {
			content = src[i-1]
		}
		// The code is always shown syntax-highlighted; only the gutter colour
		// reflects the mapping (shared srcGutter policy — identical to the
		// source-first pane).
		if hl != nil && i-1 >= 0 && i-1 < len(hl) {
			content = hl[i-1]
		}
		prefix := srcGutter(ctx, i, line, mapped, 5)
		gutterW := lipgloss.Width(prefix)
		rows = append(rows, prefix+layout.FitANSIWidth(content, inner-gutterW))
		// Point carets at every column this source line maps to (a line can map
		// at several positions), each in its column colour — same as the
		// source-first pane.
		if i == line {
			if cols := st.SourceLineColumns(ctx, file, line); len(cols) > 0 {
				rows = append(rows, coloredCaretRow(ctx, cols, gutterW, inner))
			}
		}
	}
	return border.Render(layout.PadBodyRows(rows, inner, h))
}
