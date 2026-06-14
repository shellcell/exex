package ui

// This file owns everything specific to the disassembly view: navigation
// history, address following, sticky current-symbol banner, instruction
// rendering with class-based colour + in-binary address links, and the
// optional side-by-side source pane.

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/disasm"
)

// historyCap caps the depth of the back/forward stack in the disasm view.
const historyCap = 10

// disasmReadyMsg carries the finished decode from the background worker.
type disasmReadyMsg struct{ insts []disasm.Inst }

// decodeExecImage decodes *every* executable section in virtual-address order.
// The whole-binary decode means the view can scroll across all code without
// reloading windows, and jumps become a cursor move rather than a re-decode.
func (m *Model) decodeExecImage() []disasm.Inst {
	if m.dis == nil {
		return nil
	}
	img := m.file.ExecImage()
	insts := make([]disasm.Inst, 0, img.Len()/4+16)
	for _, r := range img.Regions {
		seg := img.Data[r.Off : r.Off+int(r.Size)]
		insts = append(insts, disasm.Range(m.dis, seg, r.Addr, 0)...)
	}
	return insts
}

// ensureDisasm decodes synchronously on first use. It's the path jumps take
// (goto/follow/openSymbol): the user asked to land somewhere specific, so we
// can't defer. Returns false when there's no disassembler or no code. The
// view-switch path uses the asynchronous decodeDisasmCmd instead.
func (m *Model) ensureDisasm() bool {
	if m.disasmBuilt {
		return m.dis != nil && len(m.disasmInst) > 0
	}
	m.disasmBuilt = true
	m.disasmDecoding = false
	if m.dis == nil {
		return false
	}
	m.disasmInst = m.decodeExecImage()
	return len(m.disasmInst) > 0
}

// decodeDisasmCmd decodes the executable image off the main goroutine and
// delivers it as a disasmReadyMsg. The image is built here (on the main
// goroutine) so the worker only reads already-cached data.
func (m *Model) decodeDisasmCmd() tea.Cmd {
	img := m.file.ExecImage()
	dis := m.dis
	return func() tea.Msg {
		insts := make([]disasm.Inst, 0, img.Len()/4+16)
		for _, r := range img.Regions {
			insts = append(insts, disasm.Range(dis, img.Data[r.Off:r.Off+int(r.Size)], r.Addr, 0)...)
		}
		return disasmReadyMsg{insts: insts}
	}
}

// instIndexForAddr finds the instruction covering addr (or the nearest one at
// a lower address). ok reports whether addr actually falls within the returned
// instruction's bytes.
func (m *Model) instIndexForAddr(addr uint64) (idx int, ok bool) {
	insts := m.disasmInst
	if len(insts) == 0 {
		return 0, false
	}
	i := sort.Search(len(insts), func(i int) bool { return insts[i].Addr > addr })
	if i == 0 {
		return 0, false
	}
	j := i - 1
	in := insts[j]
	if addr >= in.Addr && addr < in.Addr+uint64(len(in.Bytes)) {
		return j, true
	}
	return j, in.Addr == addr
}

// loadDisasmAt moves the disasm cursor to addr and records the jump in the
// back/forward history. The cursor position the user is leaving behind is
// snapshotted into the *previous* history entry first, so the back arrow lands
// them on the exact instruction they jumped from.
func (m *Model) loadDisasmAt(addr uint64) {
	m.snapshotCursorToHistory()
	if m.loadDisasmAtNoHistory(addr) {
		m.pushHistory(m.disasmInst[m.disasmCur].Addr)
	}
}

// loadDisasmAtNoHistory is loadDisasmAt minus the history push. Used by
// back/forward so they don't recursively record their own steps. Returns true
// on success.
func (m *Model) loadDisasmAtNoHistory(addr uint64) bool {
	if !m.ensureDisasm() {
		m.setStatus("no disassembler / no executable code", true)
		return false
	}
	// Going to disasm must always succeed: if the requested address isn't in
	// executable code, redirect to a sensible default (lowest exec address by
	// default, or whatever the config chose) instead of refusing.
	target := addr
	if _, mapped := m.file.ExecImage().PosForAddr(target); !mapped {
		def := m.file.DefaultExecAddr(m.disasmTarget)
		if def == 0 {
			m.setStatus("no executable code to disassemble", true)
			return false
		}
		m.setStatus(fmt.Sprintf("0x%x isn't executable — showing 0x%x", target, def), false)
		target = def
	} else {
		m.status = ""
	}
	idx, _ := m.instIndexForAddr(target)
	m.disasmCur = idx
	m.disasmTop = idx
	m.disasmPositioned = true
	m.mode = modeDisasm
	return true
}

// snapshotCursorToHistory updates the current history entry to the precise
// address the cursor is currently parked on. Called before any operation
// that moves us away from the current entry (pushHistory, goBack, goForward),
// so coming back lands on the exact instruction the user was looking at —
// not the window base.
func (m *Model) snapshotCursorToHistory() {
	if m.historyPos < 0 || m.historyPos >= len(m.history) {
		return
	}
	if len(m.disasmInst) == 0 {
		return
	}
	m.history[m.historyPos] = m.disasmInst[m.disasmCur].Addr
}

func (m *Model) pushHistory(addr uint64) {
	// Caller is responsible for snapshotting the cursor *before* loading the
	// new window — see loadDisasmAt. Doing it here would be too late: the
	// disasm has already been re-decoded and the cursor sits at the new
	// address, so we'd overwrite the old entry with the new addr and the
	// dedup check would silently drop the new push.
	if m.historyPos < len(m.history)-1 {
		m.history = m.history[:m.historyPos+1]
	}
	// Don't duplicate the most-recent entry.
	if len(m.history) > 0 && m.history[len(m.history)-1] == addr {
		m.historyPos = len(m.history) - 1
		return
	}
	m.history = append(m.history, addr)
	if len(m.history) > historyCap {
		m.history = m.history[len(m.history)-historyCap:]
	}
	m.historyPos = len(m.history) - 1
}

func (m *Model) goBack() {
	if m.historyPos <= 0 {
		m.setStatus("at start of history", false)
		return
	}
	m.snapshotCursorToHistory()
	m.historyPos--
	if m.loadDisasmAtNoHistory(m.history[m.historyPos]) {
		m.scrollDisasmContext(10)
	}
	m.setStatus(fmt.Sprintf("back (%d/%d)", m.historyPos+1, len(m.history)), false)
}

func (m *Model) goForward() {
	if m.historyPos >= len(m.history)-1 {
		m.setStatus("at end of history", false)
		return
	}
	m.snapshotCursorToHistory()
	m.historyPos++
	if m.loadDisasmAtNoHistory(m.history[m.historyPos]) {
		m.scrollDisasmContext(10)
	}
	m.setStatus(fmt.Sprintf("forward (%d/%d)", m.historyPos+1, len(m.history)), false)
}

// scrollDisasmContext positions the scroll window so the cursor shows with
// context above it: from the start of the containing symbol when that fits in
// the viewport, otherwise linesAbove instructions above the cursor.
func (m *Model) scrollDisasmContext(linesAbove int) {
	n := len(m.disasmInst)
	if n == 0 {
		return
	}
	cur := m.disasmCur
	h := m.bodyHeight() - 1 // disasm scroller height (minus the sticky row)
	if h < 2 {
		m.disasmTop = max(0, cur-linesAbove)
		return
	}
	top := cur - linesAbove
	if sym, ok := m.file.SymbolAt(m.disasmInst[cur].Addr); ok {
		if si, found := m.instIndexForAddr(sym.Addr); found && si <= cur && cur-si <= h-2 {
			// The symbol header line plus its instructions up to the cursor all
			// fit above, so start the window at the symbol's first instruction.
			top = si
		}
	}
	if top < 0 {
		top = 0
	}
	m.disasmTop = top
}

// jumpSymbol moves the cursor to the next (or previous) symbol that lives in
// executable code, so the user can step function-by-function through the
// disassembly. The jump is recorded in the back/forward history.
func (m *Model) jumpSymbol(forward bool) {
	if len(m.disasmInst) == 0 {
		return
	}
	cur := m.disasmInst[m.disasmCur].Addr
	inExec := func(s binfile.Symbol) bool {
		_, ok := m.file.ExecImage().PosForAddr(s.Addr)
		return ok
	}
	var (
		sym binfile.Symbol
		ok  bool
	)
	if forward {
		sym, ok = m.file.NextSymbol(cur, inExec)
	} else {
		sym, ok = m.file.PrevSymbol(cur, inExec)
	}
	if !ok {
		m.setStatus("no more symbols in this direction", false)
		return
	}
	m.loadDisasmAt(sym.Addr)
	m.setStatus("→ "+sym.Display(), false)
}

func (m *Model) updateDisasm(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "left":
		m.goBack()
		return m, nil
	case "right":
		m.goForward()
		return m, nil
	case "]":
		m.jumpSymbol(true)
		return m, nil
	case "[":
		m.jumpSymbol(false)
		return m, nil
	case "/":
		m.openSearch()
		return m, nil
	case "n":
		m.runSearch(true, false)
		return m, nil
	case "N":
		m.runSearch(false, false)
		return m, nil
	case "up", "k":
		if m.disasmCur > 0 {
			m.disasmCur--
		}
	case "down", "j":
		if m.disasmCur < len(m.disasmInst)-1 {
			m.disasmCur++
		}
	case "pgup":
		m.disasmCur = max(0, m.disasmCur-m.bodyHeight())
	case "pgdown":
		m.disasmCur = min(len(m.disasmInst)-1, m.disasmCur+m.bodyHeight())
	case "home":
		m.disasmCur = 0
	case "end", "G":
		m.disasmCur = len(m.disasmInst) - 1
	case "enter":
		if len(m.disasmInst) == 0 {
			return m, nil
		}
		inst := m.disasmInst[m.disasmCur]
		if target, ok := m.followableAddr(inst.Text); ok {
			m.loadDisasmAt(target)
		} else {
			m.setStatus("no in-file address to follow", true)
		}
	case "a":
		if len(m.disasmInst) == 0 {
			return m, nil
		}
		addr := m.disasmInst[m.disasmCur].Addr
		m.copyToClipboard(fmt.Sprintf("0x%0*x", m.file.AddrHexWidth(), addr), "address")
	case "s":
		if len(m.disasmInst) == 0 {
			return m, nil
		}
		addr := m.disasmInst[m.disasmCur].Addr
		if sym, ok := m.file.SymbolAt(addr); ok {
			m.copyToClipboard(sym.Name, "symbol")
		} else {
			m.setStatus("no symbol at this address", true)
		}
	}
	return m, nil
}

// extractTargetAt finds the first 0x-prefixed hex number in text starting at
// or after `from`. Returns the address, the byte range it occupied in text,
// and whether anything was found.
func extractTargetAt(text string, from int) (addr uint64, start, end int, ok bool) {
	idx := strings.Index(text[from:], "0x")
	if idx < 0 {
		return 0, 0, 0, false
	}
	idx += from
	rest := text[idx+2:]
	n := 0
	for n < len(rest) {
		c := rest[n]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			n++
			continue
		}
		break
	}
	if n == 0 {
		return 0, 0, 0, false
	}
	v, err := strconv.ParseUint(rest[:n], 16, 64)
	if err != nil {
		return 0, 0, 0, false
	}
	return v, idx, idx + 2 + n, true
}

// followableAddr returns the first hex literal in text that maps to somewhere
// inside this binary.
func (m *Model) followableAddr(text string) (uint64, bool) {
	from := 0
	for {
		addr, _, end, ok := extractTargetAt(text, from)
		if !ok {
			return 0, false
		}
		if m.file.IsMapped(addr) {
			return addr, true
		}
		from = end
	}
}

// renderInstText applies the class colour to the mnemonic + operands while
// highlighting any in-file address as a follow-able target. Targets inside
// the *same* function/symbol as the current instruction get linkAddrIntraStyle
// (local branches); targets in other symbols get linkAddrInterStyle (calls
// into other functions, PLT stubs, etc.).
//
// For transfer-of-control instructions (call/jmp/jcc) that reach into a
// *different* symbol, the target literal is followed by " (symbol)" or
// " (.section)" so the reader sees where control is going without leaving
// the disasm view.
func (m *Model) renderInstText(text string, class disasm.InstClass, instAddr uint64) string {
	classSt := styleForClass(class)
	annotate := class == disasm.ClassCall || class == disasm.ClassJumpUnc || class == disasm.ClassJumpCond

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
		if annotate && !isIntra {
			if note := m.targetAnnotation(addr); note != "" {
				b.WriteString(footerStyle.Render(" (" + note + ")"))
			}
		}
		from = end
	}
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
	leftW := m.width
	rightW := 0
	if m.showSource {
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
	if m.disasmCur < m.disasmTop {
		m.disasmTop = m.disasmCur
	} else if m.disasmCur >= m.disasmTop+h {
		m.disasmTop = m.disasmCur - h + 1
	}
	end := m.disasmTop + h
	if end > len(m.disasmInst) {
		end = len(m.disasmInst)
	}

	var b strings.Builder
	emitted := 0
	for i := m.disasmTop; i < end && emitted < h; i++ {
		inst := m.disasmInst[i]
		if sym, ok := m.file.SymbolAt(inst.Addr); ok && sym.Addr == inst.Addr {
			tag := symbolNameStyle.Render("<" + sym.Display() + ">:")
			b.WriteString(padRight(" "+tag, w))
			b.WriteString("\n")
			emitted++
			if emitted >= h {
				break
			}
		}
		line := fmt.Sprintf(" %s  %s  %s",
			addrStyle.Render(fmt.Sprintf("0x%0*x", m.file.AddrHexWidth(), inst.Addr)),
			bytesHex(inst.Bytes, 8),
			m.renderInstText(inst.Text, inst.Class, inst.Addr),
		)
		plain := stripANSI(line)
		if lipgloss.Width(plain) < w {
			line += strings.Repeat(" ", w-lipgloss.Width(plain))
		} else if lipgloss.Width(plain) > w {
			line = truncateANSI(line, w)
		}
		if i == m.disasmCur {
			line = tableSelStyle.Render(stripANSI(line))
			if lipgloss.Width(line) < w {
				line += strings.Repeat(" ", w-lipgloss.Width(line))
			}
		}
		b.WriteString(line)
		b.WriteString("\n")
		emitted++
	}
	return padBody(b.String(), w, h)
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
	file, line := m.file.LookupAddr(addr)
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

	var b strings.Builder
	b.WriteString(infoStyle.Render(fmt.Sprintf("%s:%d", file, line)))
	b.WriteString("\n")
	half := (h - 1) / 2
	from := line - half
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
		// Prefer the syntax-highlighted rendering of this line when available.
		shown := content
		if hl != nil && i-1 >= 0 && i-1 < len(hl) {
			shown = hl[i-1]
		}
		// The current line gets a highlighted gutter + marker so it stands out
		// without flattening the token colours of the code itself.
		var prefix string
		if i == line {
			prefix = srcCurLineStyle.Render(fmt.Sprintf("%4d ▸ ", i))
		} else {
			prefix = srcLineNoStyle.Render(fmt.Sprintf("%4d   ", i))
		}
		avail := inner - lipgloss.Width(stripANSI(prefix))
		b.WriteString(prefix + fitANSIWidth(shown, avail))
		b.WriteString("\n")
	}
	return border.Render(padBody(b.String(), inner, h))
}
