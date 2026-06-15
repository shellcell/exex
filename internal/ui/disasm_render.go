package ui

// Disassembly rendering: instruction text colouring + annotations, the scroller
// with its sticky symbol banner, column layout, and the side-by-side source
// pane.

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/disasm"
)

// For transfer-of-control instructions (call/jmp/jcc) that reach into a
// *different* symbol, the target literal is followed by " (symbol)" or
// " (.section)" so the reader sees where control is going without leaving
// the disasm view.
func (m *Model) renderInstText(text string, class disasm.InstClass, instAddr uint64) string {
	classSt := styleForClass(class)
	// Determine the symbol that contains the instruction we're rendering.
	curSym, hasCur := m.file.SymbolAt(instAddr)

	from := 0
	var b strings.Builder
	for {
		addr, start, end, ok := extractTargetAt(text, from)
		if !ok {
			b.WriteString(classSt.Render(text[from:]))
			return b.String()
		}
		if !m.file.IsMapped(addr) {
			b.WriteString(classSt.Render(text[from:end]))
			from = end
			continue
		}
		// Pick intra vs inter colour.
		isIntra := hasCur && curSym.Size > 0 && addr >= curSym.Addr && addr < curSym.Addr+curSym.Size
		linkSt := linkAddrInterStyle
		if isIntra {
			linkSt = linkAddrIntraStyle
		}
		b.WriteString(classSt.Render(text[from:start]))
		b.WriteString(linkSt.Render(text[start:end]))
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
			return sym.Display()
		}
		return fmt.Sprintf("%s+0x%x", sym.Display(), addr-sym.Addr)
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
	if showSrc && m.sourceFirst && m.ensureSourceForDisasmCursor() {
		leftW := m.width / 2
		rightW := m.width - leftW
		left := m.renderSourceText(leftW, bodyH)
		right := leftBorderPane(m.renderSourceAsm(rightW-1, bodyH))
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
			text = fmt.Sprintf(" %s   @  0x%0*x", sym.Display(), m.file.AddrHexWidth(), addr)
		} else {
			text = fmt.Sprintf(" %s + 0x%x   @  0x%0*x", sym.Display(), off, m.file.AddrHexWidth(), addr)
		}
	} else {
		text = fmt.Sprintf(" (no symbol)   @  0x%0*x", m.file.AddrHexWidth(), addr)
	}
	return stickySymStyle.Render(padRight(text, w))
}

func (m *Model) renderDisasmScroll(w, h int) string {
	if h < 1 {
		h = 1
	}
	m.ensureDisasmViewport(h)
	rowHeight := func(i int) int { return m.disasmInstVisualHeight(i, w) }
	ensureVisualTop(m.disasmCur, &m.disasmTop, len(m.disasmInst), h, rowHeight)

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
	for i := m.disasmTop; i < len(m.disasmInst) && len(rows) < h; i++ {
		inst := m.disasmInst[i]
		if sym, ok := m.file.SymbolAt(inst.Addr); ok && sym.Addr == inst.Addr {
			for _, row := range m.disasmLabelRows(sym.Display(), w) {
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
	inst := m.disasmInst[i]
	h := len(m.disasmInstRows(inst, w, false, nil))
	if m.disasmIsSymbolStart(i) {
		inst := m.disasmInst[i]
		if sym, ok := m.file.SymbolAt(inst.Addr); ok && sym.Addr == inst.Addr {
			h += len(m.disasmLabelRows(sym.Display(), w))
		} else {
			h++
		}
	}
	return h
}

func (m *Model) disasmAsmColumn() int {
	return 1 + 2 + m.file.AddrHexWidth() + 2 + (8*3 - 1) + 2
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
		return []string{padRight(" "+symbolNameStyle.Render(truncateANSI(label, max(1, w-1))), w)}
	}
	parts := strings.Split(strings.TrimRight(ansi.Wrap(label, max(1, w-1), " \t/.-_:$@<>"), "\n"), "\n")
	if len(parts) == 0 {
		parts = []string{""}
	}
	rows := make([]string, 0, len(parts))
	for _, part := range parts {
		rows = append(rows, padRight(" "+symbolNameStyle.Render(part), w))
	}
	return rows
}

func (m *Model) disasmInstRows(inst disasm.Inst, w int, selected bool, targetStyle *lipgloss.Style) []string {
	addrText := fmt.Sprintf("0x%0*x", m.file.AddrHexWidth(), inst.Addr)
	addrCol := addrStyle.Render(addrText)
	if targetStyle != nil {
		addrCol = targetStyle.Render(addrText)
	}
	asmCol := m.disasmAsmColumn()
	annCol := m.disasmAnnotationColumn(w)
	asm := m.renderInstText(inst.Text, inst.Class, inst.Addr)
	note := m.instAnnotation(inst.Text, inst.Class)

	// The assembly is never wrapped and never trimmed to a narrow column — it is
	// only clamped to the pane width so it can't wrap. The annotation prefers its
	// column (annCol); a long instruction pushes it to the right of the assembly
	// instead of truncating the code, and if it still doesn't fit it drops onto
	// continuation row(s) indented at the annotation column.
	asmFit := fitANSIWidth(asm, max(1, w-asmCol))
	asmEnd := asmCol + lipgloss.Width(stripANSI(asmFit))

	asmRow := fmt.Sprintf(" %s  %s  ", addrCol, bytesHex(inst.Bytes, 8)) + asmFit
	// Highlight only the assembly (prefix + code) of the selected line; the gap,
	// the annotation, and any continuation rows stay uncoloured.
	if selected {
		asmRow = tableSelStyle.Render(stripANSI(asmRow))
	}

	if note == "" {
		return []string{padRight(asmRow, w)}
	}

	inlineStart := max(annCol, asmEnd+2)
	if inlineStart+lipgloss.Width(note) <= w {
		// Fits on the same row: pad out to the annotation position, then the note.
		line := asmRow + strings.Repeat(" ", inlineStart-asmEnd) + addrStyle.Render(note)
		return []string{padRight(line, w)}
	}

	// Doesn't fit beside the assembly — move it to indented continuation row(s).
	rows := []string{padRight(asmRow, w)}
	belowW := max(1, w-annCol)
	var parts []string
	if m.wrap {
		parts = strings.Split(strings.TrimRight(ansi.Wrap(note, belowW, " \t/.-_:$@<>,"), "\n"), "\n")
	} else {
		parts = []string{truncateANSI(note, belowW)}
	}
	indent := strings.Repeat(" ", annCol)
	for _, p := range parts {
		rows = append(rows, padRight(indent+addrStyle.Render(p), w))
	}
	return rows
}

func (m *Model) renderDisasmColumns(inst disasm.Inst, w int) string {
	asm := m.renderInstText(inst.Text, inst.Class, inst.Addr)
	note := m.instAnnotation(inst.Text, inst.Class)
	if note == "" {
		return asm
	}
	asmCol := m.disasmAsmColumn()
	annCol := max(asmCol+24, w/2)
	asmW := annCol - asmCol - 2
	if asmW < 12 {
		asmW = 12
	}
	if !m.wrap {
		asm = fitANSIWidth(asm, asmW)
	}
	pad := annCol - asmCol - lipgloss.Width(stripANSI(asm))
	if pad < 2 {
		pad = 2
	}
	return asm + strings.Repeat(" ", pad) + addrStyle.Render(note)
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
			out[addr] = linkAddrIntraStyle
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
		return m.srcFile != "" && m.file.SourceLines(m.srcFile) != nil
	}
	if m.srcFile != file {
		m.srcFile = file
		m.srcCodeLines = m.file.MappedLines(file)
	}
	m.srcCur = line
	return true
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

func (m *Model) ensureDisasmViewport(h int) {
	if len(m.disasmInst) == 0 || h < 1 {
		return
	}
	img := m.file.ExecImage()
	curAddr := m.disasmInst[m.disasmCur].Addr
	for tries := 0; tries < 2; tries++ {
		if m.disasmCur < m.disasmTop {
			m.disasmTop = m.disasmCur
		} else if m.disasmCur >= m.disasmTop+h {
			m.disasmTop = m.disasmCur - h + 1
		}
		end := min(len(m.disasmInst), m.disasmTop+h)
		needAbove := m.disasmTop == 0 && m.disasmPosLo > 0
		needBelow := end == len(m.disasmInst) && m.disasmPosHi < img.Len()
		if !needAbove && !needBelow {
			return
		}
		if needAbove {
			before := m.disasmMaxBytes - m.disasmOverlapBytes()
			if !m.loadDisasmWindow(img.AddrAt(m.disasmPosLo-1), before) {
				return
			}
		} else {
			last := m.disasmInst[len(m.disasmInst)-1]
			nextAddr := last.Addr + uint64(len(last.Bytes))
			if _, ok := img.PosForAddr(nextAddr); !ok || !m.loadDisasmWindow(nextAddr, m.disasmOverlapBytes()) {
				return
			}
		}
		m.disasmCur = m.instIndexAtOrAfterAddr(curAddr)
		if m.disasmCur >= h {
			m.disasmTop = m.disasmCur - min(m.disasmCur, h/2)
		} else {
			m.disasmTop = 0
		}
	}
}

func (m *Model) renderSourcePane(w, h int) string {
	border := lipgloss.NewStyle().BorderStyle(lipgloss.NormalBorder()).BorderLeft(true).BorderForeground(lipgloss.Color("240"))
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
		body := fmt.Sprintf("%s:%d (source file not found)\n", file, line)
		return border.Render(padBody(body, inner, h))
	}

	hl := m.highlightedSource(file, src)
	mapped := m.file.MappedLines(file)

	loc := fmt.Sprintf("%s:%d", file, line)
	if col > 0 {
		loc = fmt.Sprintf("%s:%d:%d", file, line, col)
	}
	var b strings.Builder
	b.WriteString(infoStyle.Render(loc))
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
	m.rightScroll = from - base // store the actually-applied (clamped) offset
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
		gutterW := lipgloss.Width(stripANSI(prefix))
		avail := inner - gutterW
		b.WriteString(prefix + fitANSIWidth(content, avail))
		b.WriteString("\n")
		// Point carets at every column this source line maps to (a line can map
		// at several positions), each in its column colour — same as the
		// source-first pane.
		if i == line {
			if cols := m.file.LineColumns(file, line); len(cols) > 0 {
				b.WriteString(coloredCaretRow(cols, gutterW, inner))
				b.WriteString("\n")
			}
		}
	}
	return border.Render(padBody(b.String(), inner, h))
}
