package ui

// This file owns everything specific to the disassembly view: navigation
// history, address following, sticky current-symbol banner, instruction
// rendering with class-based colour + in-binary address links, and the
// optional side-by-side source pane.

import (
	"fmt"
	"runtime"
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
type disasmReadyMsg struct {
	addr  uint64
	posLo int
	posHi int
	insts []disasm.Inst
}

type disasmCacheKey struct {
	start       int
	end         int
	decodeStart int
}

type disasmCacheEntry struct {
	insts []disasm.Inst
}

const disasmCacheCap = 24

type disasmPrefetchMsg struct{}

func (m *Model) disasmOverlapBytes() int {
	overlap := m.disasmMaxBytes / 8
	if overlap < 4<<10 {
		overlap = 4 << 10
	}
	if overlap >= m.disasmMaxBytes {
		overlap = max(1, m.disasmMaxBytes/2)
	}
	return overlap
}

func (m *Model) disasmLeadBytes() int {
	lead := m.disasmMaxBytes / 4
	if lead < m.disasmOverlapBytes() {
		lead = m.disasmOverlapBytes()
	}
	if lead >= m.disasmMaxBytes {
		lead = max(0, m.disasmMaxBytes-1)
	}
	return lead
}

func (m *Model) disasmSearchChunkBytes() int {
	chunk := m.disasmMaxBytes / 8
	if chunk < 64<<10 {
		chunk = 64 << 10
	}
	if chunk > 512<<10 {
		chunk = 512 << 10
	}
	if chunk > m.disasmMaxBytes {
		chunk = m.disasmMaxBytes
	}
	return chunk
}

func (m *Model) disasmSearchBatchChunks() int {
	n := m.disasmSearchWorkersFor(0)
	if n < 2 {
		n = 2
	}
	if m.disasmSearchChunkBytes() <= 128<<10 {
		n *= 2
	}
	if n > 8 {
		n = 8
	}
	return n
}

func (m *Model) disasmSearchWorkersFor(chunks int) int {
	workers := m.disasmSearchWorkers
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
		if workers > 6 {
			workers = 6
		}
		if workers < 1 {
			workers = 1
		}
	}
	if chunks > 0 && workers > chunks {
		workers = chunks
	}
	if workers < 1 {
		workers = 1
	}
	return workers
}

func (m *Model) prefetchDisasmAroundCmd(addr uint64) tea.Cmd {
	if m.dis == nil {
		return nil
	}
	img := m.file.ExecImage()
	if img.Len() == 0 {
		return nil
	}
	pos, ok := img.PosForAddr(addr)
	if !ok {
		return nil
	}
	chunk := m.disasmSearchChunkBytes()
	before := max(0, pos-chunk)
	after := pos + chunk
	if after > img.Len()-1 {
		after = img.Len() - 1
	}
	return func() tea.Msg {
		wins := []binfile.Window{
			img.Window(before, min(chunk, img.Len()-before)),
			img.Window(pos, min(chunk, img.Len()-pos)),
		}
		for _, win := range wins {
			if len(win.Data) == 0 {
				continue
			}
			m.disasmDecodeWindow(win)
		}
		if after > pos {
			win := img.Window(after, min(chunk, img.Len()-after))
			if len(win.Data) > 0 {
				m.disasmDecodeWindow(win)
			}
		}
		return disasmPrefetchMsg{}
	}
}

func (m *Model) disasmCacheGet(key disasmCacheKey) ([]disasm.Inst, bool) {
	m.disasmCacheMu.RLock()
	entry, ok := m.disasmCache[key]
	m.disasmCacheMu.RUnlock()
	if !ok {
		return nil, false
	}
	return entry.insts, true
}

func (m *Model) disasmCachePut(key disasmCacheKey, insts []disasm.Inst) {
	m.disasmCacheMu.Lock()
	defer m.disasmCacheMu.Unlock()
	if _, ok := m.disasmCache[key]; !ok {
		m.disasmCacheOrder = append(m.disasmCacheOrder, key)
	}
	m.disasmCache[key] = disasmCacheEntry{insts: insts}
	for len(m.disasmCacheOrder) > disasmCacheCap {
		old := m.disasmCacheOrder[0]
		m.disasmCacheOrder = m.disasmCacheOrder[1:]
		delete(m.disasmCache, old)
	}
}

func (m *Model) decodeInstWindow(win binfile.Window, decodeStart int) []disasm.Inst {
	if len(win.Data) == 0 || m.dis == nil {
		return nil
	}
	key := disasmCacheKey{start: win.Start, end: win.End, decodeStart: decodeStart}
	if insts, ok := m.disasmCacheGet(key); ok {
		return insts
	}
	img := m.file.ExecImage()
	decodeWin := img.Window(decodeStart, win.End-decodeStart)
	insts := disasm.Range(m.dis, decodeWin.Data, decodeWin.Addr, 0)
	lo := win.Addr
	hi := win.Addr + uint64(len(win.Data))
	keep := insts[:0]
	for _, inst := range insts {
		end := inst.Addr + uint64(len(inst.Bytes))
		if end <= lo || inst.Addr >= hi {
			continue
		}
		keep = append(keep, inst)
	}
	insts = append([]disasm.Inst(nil), keep...)
	m.disasmCachePut(key, insts)
	return insts
}

func (m *Model) disasmDecodeWindow(win binfile.Window) []disasm.Inst {
	if len(win.Data) == 0 || m.dis == nil {
		return nil
	}
	decodeStart := max(0, win.Start-m.disasmOverlapBytes())
	return m.decodeInstWindow(win, decodeStart)
}

func (m *Model) decodeDisasmAt(addr uint64, before int) (binfile.Window, []disasm.Inst) {
	if m.dis == nil {
		return binfile.Window{}, nil
	}
	img := m.file.ExecImage()
	win, ok := img.WindowContaining(addr, m.disasmMaxBytes, before)
	if !ok {
		return binfile.Window{}, nil
	}
	decodeStart := max(0, win.Start-m.disasmOverlapBytes())
	if sym, ok := m.file.SymbolAt(addr); ok {
		if pos, mapped := img.PosForAddr(sym.Addr); mapped && pos < win.End {
			if sym.Addr == addr {
				decodeStart = pos
			} else if pos >= decodeStart {
				decodeStart = pos
			}
		}
	}
	return win, m.decodeInstWindow(win, decodeStart)

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
	m.disasmPendingAddr = 0
	if m.dis == nil {
		return false
	}
	target := m.disasmInitAddr
	if target == 0 {
		target = m.file.DefaultExecAddr(m.disasmTarget)
	}
	win, insts := m.decodeDisasmAt(target, m.disasmLeadBytes())
	m.disasmPosLo, m.disasmPosHi, m.disasmInst = win.Start, win.End, insts
	return len(m.disasmInst) > 0
}

// decodeDisasmCmd decodes a bounded executable span off the main goroutine and
// delivers it as a disasmReadyMsg.
func (m *Model) decodeDisasmCmd(addr uint64) tea.Cmd {
	return func() tea.Msg {
		win, insts := m.decodeDisasmAt(addr, m.disasmLeadBytes())
		return disasmReadyMsg{addr: addr, posLo: win.Start, posHi: win.End, insts: insts}
	}
}

func (m *Model) disasmLoadedAddr(addr uint64) bool {
	if len(m.disasmInst) == 0 {
		return false
	}
	pos, ok := m.file.ExecImage().PosForAddr(addr)
	if !ok || pos < m.disasmPosLo || pos >= m.disasmPosHi {
		return false
	}
	_, ok = m.instIndexForAddr(addr)
	return ok
}

func (m *Model) disasmHasExactInst(addr uint64) bool {
	if len(m.disasmInst) == 0 {
		return false
	}
	i := sort.Search(len(m.disasmInst), func(i int) bool { return m.disasmInst[i].Addr >= addr })
	return i < len(m.disasmInst) && m.disasmInst[i].Addr == addr
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

// instIndexAtOrAfterAddr returns the first instruction at or after addr, or the
// last preceding instruction when there is no later one in the loaded window.
func (m *Model) instIndexAtOrAfterAddr(addr uint64) int {
	insts := m.disasmInst
	if len(insts) == 0 {
		return 0
	}
	idx, ok := m.instIndexForAddr(addr)
	if ok {
		return idx
	}
	i := sort.Search(len(insts), func(i int) bool { return insts[i].Addr >= addr })
	if i < len(insts) {
		return i
	}
	if idx >= 0 && idx < len(insts) {
		return idx
	}
	return len(insts) - 1
}

func (m *Model) setDisasmWindow(win binfile.Window, insts []disasm.Inst) bool {
	m.disasmInst = insts
	m.disasmPosLo = win.Start
	m.disasmPosHi = win.End
	m.disasmBuilt = true
	m.disasmDecoding = false
	m.disasmPendingAddr = 0
	return len(insts) > 0
}

func (m *Model) loadDisasmWindow(addr uint64, before int) bool {
	win, insts := m.decodeDisasmAt(addr, before)
	if !m.setDisasmWindow(win, insts) {
		m.setStatus("no executable code to disassemble", true)
		return false
	}
	m.mode = modeDisasm
	return true
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
	reload := !m.disasmLoadedAddr(target)
	if !reload {
		if sym, ok := m.file.SymbolAt(target); ok && sym.Addr == target && !m.disasmHasExactInst(target) {
			reload = true
		}
	}
	if reload {
		if !m.loadDisasmWindow(target, m.disasmLeadBytes()) {
			return false
		}
	}
	idx := m.instIndexAtOrAfterAddr(target)
	m.disasmCur = idx
	m.disasmTop = idx
	m.disasmPositioned = true
	m.mode = modeDisasm
	return true
}

func (m *Model) loadDisasmWindowForStep(forward bool) bool {
	if len(m.disasmInst) == 0 {
		return false
	}
	img := m.file.ExecImage()
	if forward {
		last := m.disasmInst[len(m.disasmInst)-1]
		nextAddr := last.Addr + uint64(len(last.Bytes))
		if _, ok := img.PosForAddr(nextAddr); !ok {
			m.setStatus("at end of executable code", false)
			return false
		}
		if !m.loadDisasmWindow(nextAddr, m.disasmOverlapBytes()) {
			return false
		}
		idx, _ := m.instIndexForAddr(nextAddr)
		m.disasmCur = idx
		m.scrollDisasmContext(3)
		return true
	}
	firstAddr := m.disasmInst[0].Addr
	pos, ok := img.PosForAddr(firstAddr)
	if !ok || pos == 0 {
		m.setStatus("at start of executable code", false)
		return false
	}
	if !m.loadDisasmWindow(img.AddrAt(pos-1), m.disasmMaxBytes-m.disasmOverlapBytes()) {
		return false
	}
	idx, found := m.instIndexForAddr(firstAddr)
	if found && idx > 0 {
		m.disasmCur = idx - 1
	} else {
		m.disasmCur = max(0, idx)
	}
	m.scrollDisasmContext(3)
	return true
}

func (m *Model) stepDisasm(forward bool) bool {
	if len(m.disasmInst) == 0 {
		return false
	}
	if forward {
		if m.disasmCur < len(m.disasmInst)-1 {
			m.disasmCur++
			return true
		}
		return m.loadDisasmWindowForStep(true)
	}
	if m.disasmCur > 0 {
		m.disasmCur--
		return true
	}
	return m.loadDisasmWindowForStep(false)
}

func (m *Model) moveDisasmPage(forward bool) {
	steps := max(1, m.bodyHeight())
	for i := 0; i < steps; i++ {
		if !m.stepDisasm(forward) {
			return
		}
	}
}

func (m *Model) jumpDisasmBoundary(forward bool) {
	img := m.file.ExecImage()
	if img.Len() == 0 {
		return
	}
	if !forward {
		if !m.loadDisasmWindow(img.AddrAt(0), 0) {
			return
		}
		m.disasmCur = 0
		m.disasmTop = 0
		return
	}
	lastPos := img.Len() - 1
	if !m.loadDisasmWindow(img.AddrAt(lastPos), m.disasmMaxBytes-1) {
		return
	}
	m.disasmCur = len(m.disasmInst) - 1
	m.scrollDisasmContext(m.bodyHeight() / 2)
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
		return m, m.runSearch(true, false)
	case "N":
		return m, m.runSearch(false, false)
	case "up", "k":
		m.stepDisasm(false)
	case "down", "j":
		m.stepDisasm(true)
	case "pgup":
		m.moveDisasmPage(false)
	case "pgdown":
		m.moveDisasmPage(true)
	case "home":
		m.jumpDisasmBoundary(false)
	case "end", "G":
		m.jumpDisasmBoundary(true)
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
	m.ensureDisasmViewport(h)
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
