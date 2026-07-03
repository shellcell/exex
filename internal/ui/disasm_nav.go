package ui

// Disassembly navigation: moving the cursor, paging, jumping to symbols and
// boundaries, and the back/forward history stack.

import (
	"fmt"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/explorer"
	"github.com/rabarbra/exex/internal/ui/layout"
)

// historyCap caps the depth of the back/forward stack in the disasm view.
const historyCap = 30

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
		def := explorer.DefaultExecAddr(m.file, m.disasmTarget)
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
	m.renderedDisasmTop = m.disasmTop
	m.disasmPositioned = true
	m.viewportDetached = false
	m.setMode(modeDisasm)
	return true
}

func (m *Model) disasmViewportHeight() int {
	return max(1, m.bodyHeight()-1)
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
		needAbove := m.disasmTop == 0 && m.disasmCur == 0 && m.disasmPosLo > 0
		needBelow := end == len(m.disasmInst) && m.disasmCur == len(m.disasmInst)-1 && m.disasmPosHi < img.Len()
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
			m.ensureDisasmViewport(m.disasmViewportHeight())
			return true
		}
		if m.loadDisasmWindowForStep(true) {
			m.ensureDisasmViewport(m.disasmViewportHeight())
			return true
		}
		return false
	}
	if m.disasmCur > 0 {
		m.disasmCur--
		m.ensureDisasmViewport(m.disasmViewportHeight())
		return true
	}
	if m.loadDisasmWindowForStep(false) {
		m.ensureDisasmViewport(m.disasmViewportHeight())
		return true
	}
	return false
}

func (m *Model) moveDisasmPage(forward bool) {
	// Advance by one screenful of instructions: the number that fill the scroller
	// height at the current top, accounting for multi-line (wrapped) rows.
	w := m.disasmRenderWidth()
	rowHeight := func(i int) int { return m.disasmInstVisualHeight(i, w) }
	steps := layout.PageStep(m.disasmTop, len(m.disasmInst), m.disasmViewportHeight(), rowHeight)
	steps = max(1, steps-1) // keep one instruction of context between pages
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
		m.renderedDisasmTop = 0
		m.viewportDetached = false
		return
	}
	if !m.loadDisasmWindowEnding(img.Len()) {
		return
	}
	m.disasmCur = len(m.disasmInst) - 1
	m.scrollDisasmToBottom()
	m.renderedDisasmTop = m.disasmTop
}

func (m *Model) scrollDisasmToBottom() {
	w := m.disasmRenderWidth()
	rowHeight := func(i int) int { return m.disasmInstVisualHeight(i, w) }
	m.disasmTop = layout.MaxViewportTop(len(m.disasmInst), m.disasmViewportHeight(), rowHeight)
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
