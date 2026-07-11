package disasm

// Rendering of the disasm scroller: instruction text colouring + annotations,
// the sticky symbol banner, section separators and the row/height math the
// shell's scroll and mouse code shares. The view renders at a caller-supplied
// width (half the screen when the source pane is open), so these take w rather
// than reading ctx.Width; composing the scroller with the source pane stays in
// the shell.

import (
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/rabarbra/exex/internal/binfile"
	dis "github.com/rabarbra/exex/internal/disasm"
	"github.com/rabarbra/exex/internal/dump"
	"github.com/rabarbra/exex/internal/ui/asmhl"
	"github.com/rabarbra/exex/internal/ui/layout"
	"github.com/rabarbra/exex/internal/ui/view"
)

// ColumnsFor is the row geometry for the current file and byte-column
// settings. Cheap to build (a switch and a few adds), so it is computed where
// it is used rather than cached, where a missed invalidation on a settings
// toggle would silently misalign every row.
func ColumnsFor(ctx *view.Context) Columns {
	return NewColumns(
		ctx.File.AddrHexWidth(),
		dis.MaxInstLen(ctx.File.Arch()),
		ctx.HideDisasmBytes,
		ctx.SpacedDisasmBytes,
	)
}

// RenderInstText colours an instruction's assembly text, caching the result.
func (st *State) RenderInstText(ctx *view.Context, text string, class dis.InstClass, instAddr uint64) string {
	return st.AsmCache.Get(AsmKey{Text: text, Addr: instAddr, Cls: class}, func() string {
		return st.asmHighlighter(ctx).Render(text, class, st.addrSpans(ctx, text, instAddr))
	})
}

// asmHighlighter returns the assembly highlighter for the current theme and
// architecture, building it on first use. Which implementation that is depends
// on the build tag, and this package deliberately doesn't know: see
// internal/ui/asmhl. Dropped (set nil) by the shell on a theme change, so the
// next frame rebuilds it rather than using a stale token-style cache.
func (st *State) asmHighlighter(ctx *view.Context) asmhl.Highlighter {
	if st.AsmHL == nil {
		st.AsmHL = ctx.NewAsmHighlighter()
	}
	return st.AsmHL
}

// addrSpans finds the followable (mapped) address literals in text and the
// link style each should use (intra- vs inter-function).
func (st *State) addrSpans(ctx *view.Context, text string, instAddr uint64) []asmhl.Span {
	if ctx.File == nil {
		return nil
	}
	curSym, hasCur := ctx.File.SymbolAt(instAddr)
	from := 0
	var spans []asmhl.Span
	for {
		addr, start, end, ok := dis.FindAddrOperand(text, from)
		if !ok {
			return spans
		}
		if ctx.File.IsMapped(addr) {
			isIntra := hasCur && curSym.Size > 0 && addr >= curSym.Addr && addr < curSym.Addr+curSym.Size
			linkSt := ctx.LinkStyle
			if isIntra {
				linkSt = ctx.LinkIntra
			}
			spans = append(spans, asmhl.Span{Start: start, End: end, Style: linkSt})
		}
		from = end
	}
}

func instAnnotation(ctx *view.Context, text string, class dis.InstClass) string {
	annotate := class == dis.ClassCall || class == dis.ClassJumpUnc ||
		class == dis.ClassJumpCond || dis.IsAddrLoad(dis.Mnemonic(text))
	from := 0
	var notes []string
	seen := map[string]bool{}
	add := func(note string) {
		if note == "" || seen[note] {
			return
		}
		seen[note] = true
		notes = append(notes, note)
	}
	for {
		addr, _, end, ok := dis.FindAddrOperand(text, from)
		if !ok {
			break
		}
		if ctx.File.IsMapped(addr) {
			if annotate {
				add(ctx.TargetAnnotation(addr))
			} else if sym, ok := ctx.File.SymbolAt(addr); ok && (sym.Kind == binfile.SymObject || sym.Kind == binfile.SymTLS || sym.Kind == binfile.SymCommon) {
				add(ctx.TargetAnnotation(addr))
			}
		}
		from = end
	}
	return strings.Join(notes, ", ")
}

// relocNote describes any relocation whose patched address lies within the
// instruction's bytes [addr, addr+n) — the resolved target of a placeholder
// operand. "" when the instruction carries no relocation.
func relocNote(ctx *view.Context, addr uint64, n int) string {
	// Only relocatable objects have relocs against code operands; gating on this
	// (a cheap flag) keeps the lazy reloc build from ever firing for a linked
	// binary that never needs it.
	if n <= 0 || !ctx.File.IsRelocatable() || !ctx.File.HasRelocs() {
		return ""
	}
	rs := ctx.File.RelocsInRange(addr, addr+uint64(n))
	if len(rs) == 0 {
		return ""
	}
	var parts []string
	for _, r := range rs {
		target := r.Sym
		if target == "" {
			target = r.Type // no symbol (e.g. a section-relative reloc): name the type
		}
		if r.HasAddend && r.Addend != 0 {
			if r.Addend > 0 {
				target += fmt.Sprintf("+0x%x", r.Addend)
			} else {
				target += fmt.Sprintf("-0x%x", -r.Addend)
			}
		}
		parts = append(parts, "→ "+target)
	}
	return strings.Join(parts, ", ")
}

// annotationNote assembles an instruction's full annotation. A relocation
// landing in the instruction resolves a placeholder operand (`call 0x0` →
// printf) — the key context for object files — so it is shown first.
func annotationNote(ctx *view.Context, inst dis.Inst) string {
	if ctx.HideAnnotations {
		return ""
	}
	note := instAnnotation(ctx, inst.Text, inst.Class)
	if rn := relocNote(ctx, inst.Addr, len(inst.Bytes)); rn != "" {
		if note != "" {
			return rn + ", " + note
		}
		return rn
	}
	return note
}

// RenderSticky always shows which symbol (and offset within it) the disasm
// cursor is currently parked on. Stays pinned regardless of scroll.
func (st *State) RenderSticky(ctx *view.Context, w int) string {
	if len(st.Inst) == 0 {
		return layout.PadRight("", w)
	}
	addr := st.Inst[st.Cur].Addr
	var text string
	if sym, ok := ctx.File.SymbolAt(addr); ok {
		off := addr - sym.Addr
		if off == 0 {
			text = fmt.Sprintf(" %s   @  0x%0*x", ctx.SymbolDisplay(sym), ctx.File.AddrHexWidth(), addr)
		} else {
			text = fmt.Sprintf(" %s + 0x%x   @  0x%0*x", ctx.SymbolDisplay(sym), off, ctx.File.AddrHexWidth(), addr)
		}
	} else {
		text = fmt.Sprintf(" (no symbol)   @  0x%0*x", ctx.File.AddrHexWidth(), addr)
	}
	// Relocatable object: the address is synthetic — flag it and show the real
	// (section-relative) position.
	if ctx.File.SyntheticAddrs() {
		if sec := ctx.File.SectionAt(addr); sec != nil {
			text += fmt.Sprintf("   ~synthetic · %s+0x%x", sec.Name, addr-sec.Addr)
		} else {
			text += "   ~synthetic"
		}
	}
	return ctx.StickyTitle(text, w)
}

// RowHeight returns the per-instruction rendered-height function for the
// disasm scroller at render width w (a symbol-start instruction is taller by
// its "<name>:" label rows). Shared by every place that runs the scroll math.
func (st *State) RowHeight(ctx *view.Context, w int) func(int) int {
	return func(i int) int { return st.InstVisualHeight(ctx, i, w) }
}

// RenderScroll renders the instruction rows of a w×h viewport, anchoring Top
// so the cursor is visible. addrMap, when non-nil, colours each row's address
// by its source mapping (the source-pane-open policy); the intra-function
// jump-target highlight takes priority over it.
//
// addrMap returns the style by value: handing back a *lipgloss.Style would
// force one heap allocation per rendered row, since a pointer returned across
// the call cannot be proven non-escaping. Taken by address here, it stays on
// the stack.
func (st *State) RenderScroll(ctx *view.Context, w, h int, addrMap func(addr uint64) (lipgloss.Style, bool)) string {
	if h < 1 {
		h = 1
	}
	rowHeight := st.RowHeight(ctx, w)
	top := ctx.VisualTop(st.Cur, st.Top, len(st.Inst), h, rowHeight)
	st.Top = top
	st.RenderedTop = top

	jumpTargets := st.intraJumpTargets(ctx)
	var rows []string
	for i := top; i < len(st.Inst) && len(rows) < h; i++ {
		inst := st.Inst[i]
		// A "═══ .section ═══" banner where an executable section begins (like the
		// hex view). Emitted before the symbol label; its row is accounted for in
		// InstVisualHeight so scroll/click math stays correct.
		if name, ok := st.sectionStart(ctx, i); ok {
			rows = append(rows, sectionBanner(ctx, name, w))
			if len(rows) >= h {
				break
			}
		}
		if sym, ok := ctx.File.SymbolAt(inst.Addr); ok && sym.Addr == inst.Addr {
			for _, row := range labelRows(ctx, ctx.SymbolDisplay(sym), w) {
				if len(rows) >= h {
					break
				}
				rows = append(rows, row)
			}
			if len(rows) >= h {
				break
			}
		}
		// The intra-function jump-target highlight takes priority; only addresses
		// that aren't a jump target fall back to the source-mapping colour.
		var targetStyle *lipgloss.Style
		if jt, ok := jumpTargets[inst.Addr]; ok {
			targetStyle = &jt
		} else if addrMap != nil {
			if ms, ok := addrMap(inst.Addr); ok {
				targetStyle = &ms
			}
		}
		for _, row := range st.InstRows(ctx, inst, w, i == st.Cur, targetStyle) {
			if len(rows) >= h {
				break
			}
			rows = append(rows, row)
		}
	}
	return layout.PadBodyRows(rows, w, h)
}

// InstVisualHeight is the rendered height of instruction i at width w,
// including its section banner and symbol label rows, memoised in HeightCache.
func (st *State) InstVisualHeight(ctx *view.Context, i, w int) int {
	if i < 0 || i >= len(st.Inst) {
		return 1
	}
	return st.HeightCache.Get(HeightKey{I: i, W: w, Wrap: ctx.Wrap}, func() int {
		inst := st.Inst[i]
		h := st.InstRowCount(ctx, inst, w)
		if _, ok := st.sectionStart(ctx, i); ok {
			h++ // the "═══ .section ═══" separator row
		}
		if st.isSymbolStart(ctx, i) {
			if sym, ok := ctx.File.SymbolAt(inst.Addr); ok && sym.Addr == inst.Addr {
				h += len(labelRows(ctx, ctx.SymbolDisplay(sym), w))
			} else {
				h++
			}
		}
		return h
	})
}

// InstBytes renders an instruction's bytes for the byte column, compact or
// spaced per the setting, padded with plain spaces to the column width so the
// assembly column lines up regardless of how many bytes the instruction took.
func InstBytes(ctx *view.Context, b []byte) string {
	maxN := dis.MaxInstLen(ctx.File.Arch())
	if len(b) > maxN {
		b = b[:maxN]
	}
	visible, want := len(b)*2, maxN*2
	if ctx.SpacedDisasmBytes {
		visible, want = max(0, len(b)*3-1), max(0, maxN*3-1)
	}
	var sb strings.Builder
	for i, x := range b {
		if ctx.SpacedDisasmBytes && i > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(ctx.ByteHex[x])
	}
	if visible < want {
		sb.WriteString(strings.Repeat(" ", want-visible))
	}
	return sb.String()
}

func labelRows(ctx *view.Context, name string, w int) []string {
	label := "<" + name + ">:"
	if !ctx.Wrap {
		return []string{layout.PadRight(" "+ctx.SymStyle.Render(layout.TruncateANSI(label, max(1, w-1))), w)}
	}
	parts := strings.Split(strings.TrimRight(ansi.Wrap(label, max(1, w-1), " \t/.-_:$@<>"), "\n"), "\n")
	if len(parts) == 0 {
		parts = []string{""}
	}
	rows := make([]string, 0, len(parts))
	for _, part := range parts {
		rows = append(rows, layout.PadRight(" "+ctx.SymStyle.Render(part), w))
	}
	return rows
}

// InstRowCount returns the number of rows InstRows would emit for inst at
// width w, WITHOUT building any of the styled strings — the height cache only
// needs the count, and computing it drives first-paint and every resize/
// wrap-toggle over the whole (possibly huge) instruction list. It mirrors
// InstRows' row-splitting decisions exactly; TestDisasmInstRowCountMatches
// pins the two together so they can't drift.
func (st *State) InstRowCount(ctx *view.Context, inst dis.Inst, w int) int {
	cols := ColumnsFor(ctx)
	asmCol := cols.Asm
	annCol := cols.Annotation(w)
	// Syntax highlighting adds no visible width, so the plain aligned text's width
	// matches the styled row's — no need to render (or cache-warm) the colours here.
	asmEnd := asmCol + min(lipgloss.Width(dump.AlignAsm(inst.Text)), max(1, w-asmCol))

	note := annotationNote(ctx, inst)
	if note == "" {
		return 1
	}
	inlineStart := max(annCol, asmEnd+2)
	if inlineAvail := w - inlineStart; inlineAvail > 0 {
		if first, rest := splitPlainWidth(note, inlineAvail); first != "" {
			if rest == "" || !ctx.Wrap {
				return 1
			}
			return 1 + annotationContinuationRowCount(ctx, rest, annCol, w)
		}
	}
	return 1 + annotationContinuationRowCount(ctx, note, annCol, w)
}

// annotationContinuationRowCount counts the rows annotationContinuationRows
// would emit, without building them.
func annotationContinuationRowCount(ctx *view.Context, note string, annCol, w int) int {
	if !ctx.Wrap {
		return 1
	}
	belowW := max(1, w-annCol)
	return len(strings.Split(strings.TrimRight(ansi.Wrap(strings.TrimLeft(note, " "), belowW, " \t/.-_:$@<>,"), "\n"), "\n"))
}

// InstRows renders one instruction as its full set of rows: the assembly row
// (optionally selection-highlighted) plus any annotation continuation rows.
func (st *State) InstRows(ctx *view.Context, inst dis.Inst, w int, selected bool, targetStyle *lipgloss.Style) []string {
	addrText := fmt.Sprintf("0x%0*x", ctx.File.AddrHexWidth(), inst.Addr)
	addrCol := ctx.AddrStyle.Render(addrText)
	if targetStyle != nil {
		addrCol = targetStyle.Render(addrText)
	}
	cols := ColumnsFor(ctx)
	asmCol := cols.Asm
	annCol := cols.Annotation(w)
	asm := st.RenderInstText(ctx, dump.AlignAsm(inst.Text), inst.Class, inst.Addr)
	note := annotationNote(ctx, inst)

	asmFit := layout.FitANSIWidth(asm, max(1, w-asmCol))
	asmEnd := asmCol + lipgloss.Width(asmFit)

	var asmRow string
	if cols.ByteColW > 0 {
		asmRow = fmt.Sprintf(" %s  %s  ", addrCol, InstBytes(ctx, inst.Bytes)) + asmFit
	} else {
		asmRow = fmt.Sprintf(" %s  ", addrCol) + asmFit
	}
	// Highlight only the assembly (prefix + code) of the selected line; the gap,
	// the annotation, and any continuation rows stay uncoloured.
	if selected {
		asmRow = selectedSegment(ctx, asmRow)
	}

	if note == "" {
		return []string{layout.PadRight(asmRow, w)}
	}

	inlineStart := max(annCol, asmEnd+2)
	inlineAvail := w - inlineStart
	if inlineAvail > 0 {
		first, rest := splitPlainWidth(note, inlineAvail)
		if first != "" {
			line := asmRow + strings.Repeat(" ", inlineStart-asmEnd) + ctx.AddrStyle.Render(first)
			rows := []string{layout.PadRight(line, w)}
			if rest == "" || !ctx.Wrap {
				return rows
			}
			return append(rows, annotationContinuationRows(ctx, rest, annCol, w)...)
		}
	}

	// No usable room remains beside the assembly; fall back to continuation rows.
	rows := []string{layout.PadRight(asmRow, w)}
	return append(rows, annotationContinuationRows(ctx, note, annCol, w)...)
}

func annotationContinuationRows(ctx *view.Context, note string, annCol, w int) []string {
	belowW := max(1, w-annCol)
	var parts []string
	if ctx.Wrap {
		parts = strings.Split(strings.TrimRight(ansi.Wrap(strings.TrimLeft(note, " "), belowW, " \t/.-_:$@<>,"), "\n"), "\n")
	} else {
		parts = []string{layout.TruncateANSI(note, belowW)}
	}
	indent := strings.Repeat(" ", annCol)
	rows := make([]string, 0, len(parts))
	for _, p := range parts {
		rows = append(rows, layout.PadRight(indent+ctx.AddrStyle.Render(p), w))
	}
	return rows
}

func splitPlainWidth(s string, w int) (string, string) {
	if w <= 0 {
		return "", s
	}
	if lipgloss.Width(s) <= w {
		return s, ""
	}
	used := 0
	for i, r := range s {
		rw := lipgloss.Width(string(r))
		if used+rw > w {
			return s[:i], s[i:]
		}
		used += rw
	}
	return s, ""
}

func selectedSegment(ctx *view.Context, s string) string {
	sel := ctx.DisasmSelSeq
	if sel == "" {
		sel = "\x1b[1;48;5;63m" // fallback if the theme didn't derive a sequence
	}
	return sel + strings.ReplaceAll(s, "\x1b[0m", "\x1b[0m"+sel) + "\x1b[0m"
}

func (st *State) intraJumpTargets(ctx *view.Context) map[uint64]lipgloss.Style {
	out := map[uint64]lipgloss.Style{}
	if len(st.Inst) == 0 || st.Cur < 0 || st.Cur >= len(st.Inst) {
		return out
	}
	cur := st.Inst[st.Cur]
	if cur.Class != dis.ClassJumpUnc && cur.Class != dis.ClassJumpCond {
		return out
	}
	curSym, ok := ctx.File.SymbolAt(cur.Addr)
	if !ok || curSym.Size == 0 {
		return out
	}
	from := 0
	for {
		addr, _, end, ok := dis.FindAddrOperand(cur.Text, from)
		if !ok {
			return out
		}
		if addr >= curSym.Addr && addr < curSym.Addr+curSym.Size {
			out[addr] = ctx.LinkIntra
		}
		from = end
	}
}

// isSymbolStart reports whether instruction i begins a symbol (and so is
// preceded by a "<name>:" label line in the scroller).
func (st *State) isSymbolStart(ctx *view.Context, i int) bool {
	if i < 0 || i >= len(st.Inst) {
		return false
	}
	sym, ok := ctx.File.SymbolAt(st.Inst[i].Addr)
	return ok && sym.Addr == st.Inst[i].Addr
}

// sectionStart reports whether instruction i begins an executable section
// (and so is preceded by a "═══ name ═══" separator in the scroller). The
// exec-section start addresses are indexed once so this is an O(1) lookup per
// row, not a scan over all sections on every render.
func (st *State) sectionStart(ctx *view.Context, i int) (string, bool) {
	if i < 0 || i >= len(st.Inst) {
		return "", false
	}
	if st.ExecSecStarts == nil {
		// Derive banners from the active disasm image's regions, so all-sections
		// mode labels data/object-file sections too (not just executable ones). When
		// a section's load address (LMA) differs from its virtual address — a
		// higher-half kernel, say — note it once here (it's a constant per-section
		// offset) rather than on every instruction row.
		st.ExecSecStarts = make(map[uint64]string)
		for _, r := range ctx.File.ExecImage().Regions {
			label := r.Name
			if sec := ctx.File.SectionAt(r.Addr); sec != nil {
				label += ctx.LMANote(sec.PhysAddr)
			}
			st.ExecSecStarts[r.Addr] = label
		}
	}
	name, ok := st.ExecSecStarts[st.Inst[i].Addr]
	return name, ok
}

// sectionBanner renders the centred section separator row (matching the hex
// view's "═══ name ═══" banner) to width w.
func sectionBanner(ctx *view.Context, name string, w int) string {
	banner := lipgloss.PlaceHorizontal(max(1, w-1), lipgloss.Center, " "+name+" ",
		lipgloss.WithWhitespaceChars("="))
	return layout.PadRight(ctx.BannerStyle.Render(banner), w)
}
