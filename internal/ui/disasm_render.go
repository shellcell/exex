package ui

// Disassembly rendering: instruction text colouring + annotations, the scroller
// with its sticky symbol banner, column layout, and the side-by-side source
// pane.

import (
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/disasm"
	"github.com/rabarbra/exex/internal/dump"
)

// renderInstText colours an instruction's assembly text, caching the result.
func (m *Model) renderInstText(text string, class disasm.InstClass, instAddr uint64) string {
	key := disasmAsmCacheKey{text: text, addr: instAddr, cls: class}
	if m.disasmAsmCache != nil {
		if rendered, ok := m.disasmAsmCache[key]; ok {
			return rendered
		}
	}
	rendered := m.renderInstTextStyled(text, class, instAddr)
	if m.disasmAsmCache == nil {
		m.disasmAsmCache = make(map[disasmAsmCacheKey]string)
	}
	m.disasmAsmCache[key] = rendered
	return rendered
}

// disasmAddrSpan marks a run of instruction text (a followable mapped address)
// that should be drawn in a link colour rather than the operand-token colours.
type disasmAddrSpan struct {
	start int
	end   int
	style lipgloss.Style
}

// disasmAddrSpans finds the followable (mapped) address literals in text and the
// link style each should use (intra- vs inter-function).
func (m *Model) disasmAddrSpans(text string, instAddr uint64) []disasmAddrSpan {
	if m.file == nil {
		return nil
	}
	curSym, hasCur := m.file.SymbolAt(instAddr)
	from := 0
	var spans []disasmAddrSpan
	for {
		addr, start, end, ok := extractTargetAt(text, from)
		if !ok {
			return spans
		}
		if m.file.IsMapped(addr) {
			isIntra := hasCur && curSym.Size > 0 && addr >= curSym.Addr && addr < curSym.Addr+curSym.Size
			linkSt := m.theme.linkAddrInterStyle
			if isIntra {
				linkSt = m.theme.linkAddrIntraStyle
			}
			spans = append(spans, disasmAddrSpan{start: start, end: end, style: linkSt})
		}
		from = end
	}
}

func (m *Model) instAnnotation(text string, class disasm.InstClass) string {
	annotate := class == disasm.ClassCall || class == disasm.ClassJumpUnc ||
		class == disasm.ClassJumpCond || isAddrLoadOp(firstToken(text))
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
		addr, _, end, ok := extractTargetAt(text, from)
		if !ok {
			break
		}
		if m.file.IsMapped(addr) {
			if annotate {
				add(m.targetAnnotation(addr))
			} else if sym, ok := m.file.SymbolAt(addr); ok && (sym.Kind == binfile.SymObject || sym.Kind == binfile.SymTLS || sym.Kind == binfile.SymCommon) {
				add(m.targetAnnotation(addr))
			}
		}
		from = end
	}
	return strings.Join(notes, ", ")
}

// firstToken returns the mnemonic (first whitespace-delimited token), lowered.
func firstToken(text string) string {
	text = strings.TrimSpace(text)
	if i := strings.IndexAny(text, " \t"); i >= 0 {
		text = text[:i]
	}
	return strings.ToLower(text)
}

// isAddrLoadOp reports whether op materialises an address (so its operand is
// worth annotating with the symbol/section it points at).
func isAddrLoadOp(op string) bool {
	switch op {
	case "lea", "leaq", "leal", "leaw", "adr", "adrp":
		return true
	}
	return false
}

// targetAnnotation labels a follow-able address with whatever the reader is
// most likely to want as context: the symbol name (with offset when not at
// the symbol's start), or the containing section name when no symbol covers
// it. Returns "" when neither is known.
func (m *Model) targetAnnotation(addr uint64) string {
	if sym, ok := m.file.SymbolAt(addr); ok {
		if addr == sym.Addr {
			return m.displaySymbolName(sym)
		}
		return fmt.Sprintf("%s+0x%x", m.displaySymbolName(sym), addr-sym.Addr)
	}
	if sec := m.file.SectionAt(addr); sec != nil {
		return sec.Name
	}
	return ""
}

func (m *Model) renderDisasm() string {
	bodyH := m.bodyHeight()
	if m.disasmDecoding {
		return padBody("decoding instructions…\n", m.width, bodyH)
	}
	if len(m.disasmInst) == 0 {
		msg := "no disassembly loaded — press g to go to an address, or pick a symbol from view 3"
		return padBody(msg+"\n", m.width, bodyH)
	}
	// The source pane only makes sense when the binary actually carries debug
	// info; otherwise keep the disasm full-width instead of opening an empty
	// "no source" pane.
	showSrc := m.showSource && m.file.HasDWARF()
	if !showSrc && m.sourceFirst && m.hasOpenSourceFile() {
		return m.renderSourceText(m.width, bodyH)
	}
	if showSrc && m.sourceFirst && m.hasOpenSourceFile() {
		leftW := m.width / 2
		rightW := m.width - leftW
		left := m.renderSourceText(leftW, bodyH)
		right := m.theme.leftBorderPane(m.renderSourceAsm(rightW-1, bodyH))
		return lipgloss.JoinHorizontal(lipgloss.Top, left, right)
	}
	leftW := m.width
	rightW := 0
	if showSrc {
		leftW = m.width / 2
		rightW = m.width - leftW
	}

	sticky := m.renderStickySymbol(leftW)
	left := sticky + "\n" + m.renderDisasmScroll(leftW, bodyH-1)

	if rightW == 0 {
		return left
	}
	right := m.renderSourcePane(rightW, bodyH)
	return lipgloss.JoinHorizontal(lipgloss.Top, left, right)
}

// renderStickySymbol always shows which symbol (and offset within it) the
// disasm cursor is currently parked on. Stays pinned regardless of scroll.
func (m *Model) renderStickySymbol(w int) string {
	if len(m.disasmInst) == 0 {
		return padRight("", w)
	}
	addr := m.disasmInst[m.disasmCur].Addr
	var text string
	if sym, ok := m.file.SymbolAt(addr); ok {
		off := addr - sym.Addr
		if off == 0 {
			text = fmt.Sprintf(" %s   @  0x%0*x", m.displaySymbolName(sym), m.file.AddrHexWidth(), addr)
		} else {
			text = fmt.Sprintf(" %s + 0x%x   @  0x%0*x", m.displaySymbolName(sym), off, m.file.AddrHexWidth(), addr)
		}
	} else {
		text = fmt.Sprintf(" (no symbol)   @  0x%0*x", m.file.AddrHexWidth(), addr)
	}
	return m.theme.stickyTitleLine(text, w)
}

// disasmRowHeight returns the per-instruction rendered-height function for the
// disasm scroller at render width w (a symbol-start instruction is taller by its
// "<name>:" label rows). Shared by every place that runs the scroll math.
func (m *Model) disasmRowHeight(w int) func(int) int {
	return func(i int) int { return m.disasmInstVisualHeight(i, w) }
}

func (m *Model) renderDisasmScroll(w, h int) string {
	if h < 1 {
		h = 1
	}
	rowHeight := m.disasmRowHeight(w)
	top := m.visualTopForView(m.disasmCur, m.disasmTop, len(m.disasmInst), h, rowHeight)
	m.disasmTop = top
	m.renderedDisasmTop = top

	jumpTargets := m.currentIntraJumpTargets()
	// When the source pane is open (disasm-first), addresses are coloured by
	// their source mapping — identical to the source-first disasm pane — instead
	// of the intra-function jump-target highlight used in the pure disasm view.
	sourceActive := m.rightPaneActive() && !m.sourceFirst && len(m.disasmInst) > 0
	var curFile string
	var curLine int
	if sourceActive {
		curFile, curLine, _ = m.file.LookupAddrCol(m.disasmInst[m.disasmCur].Addr)
	}
	var rows []string
	for i := top; i < len(m.disasmInst) && len(rows) < h; i++ {
		inst := m.disasmInst[i]
		// A "═══ .section ═══" banner where an executable section begins (like the
		// hex view). Emitted before the symbol label; its row is accounted for in
		// disasmInstVisualHeight so scroll/click math stays correct.
		if name, ok := m.disasmSectionStart(i); ok {
			rows = append(rows, m.disasmSectionBanner(name, w))
			if len(rows) >= h {
				break
			}
		}
		if sym, ok := m.file.SymbolAt(inst.Addr); ok && sym.Addr == inst.Addr {
			for _, row := range m.disasmLabelRows(m.displaySymbolName(sym), w) {
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
		if st, ok := jumpTargets[inst.Addr]; ok {
			targetStyle = &st
		} else if sourceActive {
			st := m.addrMapStyle(inst.Addr, curFile, curLine)
			targetStyle = &st
		}
		for _, row := range m.disasmInstRows(inst, w, i == m.disasmCur, targetStyle) {
			if len(rows) >= h {
				break
			}
			rows = append(rows, row)
		}
	}
	return padBodyRows(rows, w, h)
}

func (m *Model) disasmRenderWidth() int {
	if m.mode == modeDisasm && m.showSource && m.file.HasDWARF() && !m.sourceFirst {
		return m.width / 2
	}
	return m.width
}

func (m *Model) disasmInstVisualHeight(i, w int) int {
	if i < 0 || i >= len(m.disasmInst) {
		return 1
	}
	key := disasmHeightKey{i: i, w: w, wrap: m.wrap}
	if h, ok := m.disasmHeightCache[key]; ok {
		return h
	}
	inst := m.disasmInst[i]
	h := len(m.disasmInstRows(inst, w, false, nil))
	if _, ok := m.disasmSectionStart(i); ok {
		h++ // the "═══ .section ═══" separator row
	}
	if m.disasmIsSymbolStart(i) {
		if sym, ok := m.file.SymbolAt(inst.Addr); ok && sym.Addr == inst.Addr {
			h += len(m.disasmLabelRows(m.displaySymbolName(sym), w))
		} else {
			h++
		}
	}
	if m.disasmHeightCache == nil {
		m.disasmHeightCache = make(map[disasmHeightKey]int)
	}
	m.disasmHeightCache[key] = h
	return h
}

// instByteWidth is the number of instruction bytes the byte column is sized for:
// the arch's longest encoding, so fixed-length RISC ISAs get a tight column
// instead of x86's wide one.
func (m *Model) instByteWidth() int {
	return disasm.MaxInstLen(m.file.Arch())
}

// disasmByteColWidth is the printed width of the instruction-byte column, or 0
// when it is hidden (behavior.hide_disasm_bytes). Compact is 2 hex chars per
// byte; spaced inserts a space between bytes (3 per byte, less the trailing one).
func (m *Model) disasmByteColWidth() int {
	if m.cfg.Behavior.HideDisasmBytes {
		return 0
	}
	n := m.instByteWidth()
	if m.cfg.Behavior.SpacedDisasmBytes {
		return n*3 - 1
	}
	return n * 2
}

// disasmBytes renders an instruction's bytes for the byte column, compact or
// spaced per the setting, padded to disasmByteColWidth.
func (m *Model) disasmBytes(b []byte) string {
	if m.cfg.Behavior.SpacedDisasmBytes {
		return bytesHexSpaced(b, m.instByteWidth())
	}
	return bytesHex(b, m.instByteWidth())
}

func (m *Model) disasmAsmColumn() int {
	col := 1 + 2 + m.file.AddrHexWidth() + 2 // lead space + "0x" + addr + gap
	if bw := m.disasmByteColWidth(); bw > 0 {
		col += bw + 2 // byte column + gap
	}
	return col
}

func (m *Model) disasmAnnotationColumn(w int) int {
	// Keep annotations a short, fixed distance after the assembly column so they
	// sit close to the code instead of drifting out to mid-pane on a wide,
	// source-off disasm view. A long instruction pushes its own annotation
	// further right (see disasmInstRows), so this is only the preferred column.
	col := m.disasmAsmColumn() + 22
	if hi := w - 12; col > hi {
		col = max(m.disasmAsmColumn()+8, hi)
	}
	return col
}

func (m *Model) disasmLabelRows(name string, w int) []string {
	label := "<" + name + ">:"
	if !m.wrap {
		return []string{padRight(" "+m.theme.symbolNameStyle.Render(truncateANSI(label, max(1, w-1))), w)}
	}
	parts := strings.Split(strings.TrimRight(ansi.Wrap(label, max(1, w-1), " \t/.-_:$@<>"), "\n"), "\n")
	if len(parts) == 0 {
		parts = []string{""}
	}
	rows := make([]string, 0, len(parts))
	for _, part := range parts {
		rows = append(rows, padRight(" "+m.theme.symbolNameStyle.Render(part), w))
	}
	return rows
}

func (m *Model) disasmInstRows(inst disasm.Inst, w int, selected bool, targetStyle *lipgloss.Style) []string {
	addrText := fmt.Sprintf("0x%0*x", m.file.AddrHexWidth(), inst.Addr)
	addrCol := m.theme.addrStyle.Render(addrText)
	if targetStyle != nil {
		addrCol = targetStyle.Render(addrText)
	}
	asmCol := m.disasmAsmColumn()
	annCol := m.disasmAnnotationColumn(w)
	asm := m.renderInstText(dump.AlignAsm(inst.Text), inst.Class, inst.Addr)
	note := ""
	if !m.cfg.Behavior.HideAnnotations {
		note = m.instAnnotation(inst.Text, inst.Class)
	}

	asmFit := fitANSIWidth(asm, max(1, w-asmCol))
	asmEnd := asmCol + lipgloss.Width(asmFit)

	var asmRow string
	if m.disasmByteColWidth() > 0 {
		asmRow = fmt.Sprintf(" %s  %s  ", addrCol, m.disasmBytes(inst.Bytes)) + asmFit
	} else {
		asmRow = fmt.Sprintf(" %s  ", addrCol) + asmFit
	}
	// Highlight only the assembly (prefix + code) of the selected line; the gap,
	// the annotation, and any continuation rows stay uncoloured.
	if selected {
		asmRow = m.selectedDisasmSegment(asmRow)
	}

	if note == "" {
		return []string{padRight(asmRow, w)}
	}

	inlineStart := max(annCol, asmEnd+2)
	inlineAvail := w - inlineStart
	if inlineAvail > 0 {
		first, rest := splitPlainWidth(note, inlineAvail)
		if first != "" {
			line := asmRow + strings.Repeat(" ", inlineStart-asmEnd) + m.theme.addrStyle.Render(first)
			rows := []string{padRight(line, w)}
			if rest == "" || !m.wrap {
				return rows
			}
			return append(rows, m.disasmAnnotationContinuationRows(rest, annCol, w)...)
		}
	}

	// No usable room remains beside the assembly; fall back to continuation rows.
	rows := []string{padRight(asmRow, w)}
	return append(rows, m.disasmAnnotationContinuationRows(note, annCol, w)...)
}

func (m *Model) disasmAnnotationContinuationRows(note string, annCol, w int) []string {
	belowW := max(1, w-annCol)
	var parts []string
	if m.wrap {
		parts = strings.Split(strings.TrimRight(ansi.Wrap(strings.TrimLeft(note, " "), belowW, " \t/.-_:$@<>,"), "\n"), "\n")
	} else {
		parts = []string{truncateANSI(note, belowW)}
	}
	indent := strings.Repeat(" ", annCol)
	rows := make([]string, 0, len(parts))
	for _, p := range parts {
		rows = append(rows, padRight(indent+m.theme.addrStyle.Render(p), w))
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

func (m *Model) selectedDisasmSegment(s string) string {
	sel := m.theme.disasmSelSeq
	if sel == "" {
		sel = "\x1b[1;48;5;63m" // fallback if the theme didn't derive a sequence
	}
	return sel + strings.ReplaceAll(s, "\x1b[0m", "\x1b[0m"+sel) + "\x1b[0m"
}

func (m *Model) currentIntraJumpTargets() map[uint64]lipgloss.Style {
	out := map[uint64]lipgloss.Style{}
	if len(m.disasmInst) == 0 || m.disasmCur < 0 || m.disasmCur >= len(m.disasmInst) {
		return out
	}
	cur := m.disasmInst[m.disasmCur]
	if cur.Class != disasm.ClassJumpUnc && cur.Class != disasm.ClassJumpCond {
		return out
	}
	curSym, ok := m.file.SymbolAt(cur.Addr)
	if !ok || curSym.Size == 0 {
		return out
	}
	from := 0
	for {
		addr, _, end, ok := extractTargetAt(cur.Text, from)
		if !ok {
			return out
		}
		if addr >= curSym.Addr && addr < curSym.Addr+curSym.Size {
			out[addr] = m.theme.linkAddrIntraStyle
		}
		from = end
	}
}

func (m *Model) ensureSourceForDisasmCursor() bool {
	// In source-first mode the source cursor is authoritative — the asm pane
	// follows it via syncSourceAsm. Re-deriving srcCur from the disasm cursor
	// here would snap the cursor back whenever it moved onto an unmapped
	// (shadow) line, which is why "up" sometimes appeared stuck.
	if m.sourceFirst && m.srcFile != "" && m.file.SourceLines(m.srcFile) != nil {
		return true
	}
	if len(m.disasmInst) == 0 || m.disasmCur < 0 || m.disasmCur >= len(m.disasmInst) {
		return false
	}
	file, line := m.file.LookupAddr(m.disasmInst[m.disasmCur].Addr)
	if file == "" || line == 0 || m.file.SourceLines(file) == nil {
		return false
	}
	if m.srcFile != file {
		m.srcFile = file
		m.srcCodeLines = m.mappedSourceLines(file)
	}
	m.srcCur = line
	return true
}

func (m *Model) hasOpenSourceFile() bool {
	return m.srcFile != "" && m.file.SourceLines(m.srcFile) != nil
}

// disasmIsSymbolStart reports whether instruction i begins a symbol (and so is
// preceded by a "<name>:" label line in the scroller).
func (m *Model) disasmIsSymbolStart(i int) bool {
	if i < 0 || i >= len(m.disasmInst) {
		return false
	}
	sym, ok := m.file.SymbolAt(m.disasmInst[i].Addr)
	return ok && sym.Addr == m.disasmInst[i].Addr
}

// disasmSectionStart reports whether instruction i begins an executable section
// (and so is preceded by a "═══ name ═══" separator in the scroller). The
// exec-section start addresses are indexed once so this is an O(1) lookup per
// row, not a scan over all sections on every render.
func (m *Model) disasmSectionStart(i int) (string, bool) {
	if i < 0 || i >= len(m.disasmInst) {
		return "", false
	}
	if m.execSecStarts == nil {
		m.execSecStarts = make(map[uint64]string)
		for j := range m.file.Sections {
			s := &m.file.Sections[j]
			if s.Exec && s.Size > 0 {
				m.execSecStarts[s.Addr] = s.Name
			}
		}
	}
	name, ok := m.execSecStarts[m.disasmInst[i].Addr]
	return name, ok
}

// disasmSectionBanner renders the centred section separator row (matching the
// hex view's "═══ name ═══" banner) to width w.
func (m *Model) disasmSectionBanner(name string, w int) string {
	banner := lipgloss.PlaceHorizontal(max(1, w-1), lipgloss.Center, " "+name+" ",
		lipgloss.WithWhitespaceChars("="))
	return padRight(m.theme.sectionStyle.Render(banner), w)
}

func (m *Model) renderSourcePane(w, h int) string {
	border := m.theme.paneBorderStyle
	inner := w - 1
	if inner < 8 {
		inner = w
	}

	if len(m.disasmInst) == 0 {
		return border.Render(padBody("", inner, h))
	}
	addr := m.disasmInst[m.disasmCur].Addr
	file, line, col := m.file.LookupAddrCol(addr)
	if file == "" {
		body := "no source mapping for 0x" + fmt.Sprintf("%x", addr)
		return border.Render(padBody(body+"\n", inner, h))
	}
	src := m.file.SourceLines(file)
	if src == nil {
		suffix := fmt.Sprintf(":%d (source file not found)", line)
		body := m.theme.viewTitleLine(truncateMiddle(file, max(1, inner-lipgloss.Width(suffix)))+suffix, inner) + "\n"
		return border.Render(padBody(body, inner, h))
	}

	hl := m.highlightedSource(file, src)
	mapped := m.mappedSourceLines(file)

	suffix := fmt.Sprintf(":%d", line)
	if col > 0 {
		suffix = fmt.Sprintf(":%d:%d", line, col)
	}
	loc := truncateMiddle(file, max(1, inner-lipgloss.Width(suffix))) + suffix
	var b strings.Builder
	b.WriteString(m.theme.viewTitleLine(loc, inner))
	b.WriteString("\n")
	half := (h - 1) / 2
	base := line - half
	from := base + m.rightScroll
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
		prefix := m.srcGutter(i, line, mapped, 5)
		gutterW := lipgloss.Width(prefix)
		avail := inner - gutterW
		b.WriteString(prefix)
		b.WriteString(fitANSIWidth(content, avail))
		b.WriteString("\n")
		// Point carets at every column this source line maps to (a line can map
		// at several positions), each in its column colour — same as the
		// source-first pane.
		if i == line {
			if cols := m.sourceLineColumns(file, line); len(cols) > 0 {
				b.WriteString(m.theme.coloredCaretRow(cols, gutterW, inner))
				b.WriteString("\n")
			}
		}
	}
	return border.Render(padBody(b.String(), inner, h))
}
