package ui

// Disassembly navigation: moving the cursor, paging, jumping to symbols and
// boundaries, and the back/forward history stack.

import (
	"fmt"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/explorer"
	"github.com/rabarbra/exex/internal/ui/layout"
)

// loadDisasmAt moves the disasm cursor to addr and records the jump in the
// back/forward history. The cursor position the user is leaving behind is
// snapshotted into the *previous* history entry first, so the back arrow lands
// them on the exact instruction they jumped from.
func (m *Model) loadDisasmAt(addr uint64) {
	m.dasm.SnapshotCursorToHistory()
	if m.loadDisasmAtNoHistory(addr) {
		m.dasm.PushHistory(m.dasm.Inst[m.dasm.Cur].Addr)
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
		if sym, ok := m.file.SymbolAt(target); ok && sym.Addr == target && !m.dasm.HasExact(target) {
			reload = true
		}
	}
	if reload {
		if !m.loadDisasmWindow(target, m.disasmLeadBytes()) {
			return false
		}
	}
	idx := m.dasm.IndexAtOrAfter(target)
	m.dasm.Cur = idx
	m.dasm.Top = idx
	m.dasm.RenderedTop = m.dasm.Top
	m.dasm.Positioned = true
	m.viewportDetached = false
	m.setMode(modeDisasm)
	return true
}

func (m *Model) disasmViewportHeight() int {
	return max(1, m.bodyHeight()-1)
}

func (m *Model) ensureDisasmViewport(h int) {
	if len(m.dasm.Inst) == 0 || h < 1 {
		return
	}
	img := m.file.ExecImage()
	curAddr := m.dasm.Inst[m.dasm.Cur].Addr
	for tries := 0; tries < 2; tries++ {
		if m.dasm.Cur < m.dasm.Top {
			m.dasm.Top = m.dasm.Cur
		} else if m.dasm.Cur >= m.dasm.Top+h {
			m.dasm.Top = m.dasm.Cur - h + 1
		}
		end := min(len(m.dasm.Inst), m.dasm.Top+h)
		needAbove := m.dasm.Top == 0 && m.dasm.Cur == 0 && m.dasm.PosLo > 0
		needBelow := end == len(m.dasm.Inst) && m.dasm.Cur == len(m.dasm.Inst)-1 && m.dasm.PosHi < img.Len()
		if !needAbove && !needBelow {
			return
		}
		if needAbove {
			before := m.disasmMaxBytes - m.disasmOverlapBytes()
			if !m.loadDisasmWindow(img.AddrAt(m.dasm.PosLo-1), before) {
				return
			}
		} else {
			last := m.dasm.Inst[len(m.dasm.Inst)-1]
			nextAddr := last.Addr + uint64(len(last.Bytes))
			if _, ok := img.PosForAddr(nextAddr); !ok || !m.loadDisasmWindow(nextAddr, m.disasmOverlapBytes()) {
				return
			}
		}
		m.dasm.Cur = m.dasm.IndexAtOrAfter(curAddr)
		if m.dasm.Cur >= h {
			m.dasm.Top = m.dasm.Cur - min(m.dasm.Cur, h/2)
		} else {
			m.dasm.Top = 0
		}
	}
}

func (m *Model) loadDisasmWindowForStep(forward bool) bool {
	if len(m.dasm.Inst) == 0 {
		return false
	}
	img := m.file.ExecImage()
	if forward {
		last := m.dasm.Inst[len(m.dasm.Inst)-1]
		nextAddr := last.Addr + uint64(len(last.Bytes))
		if _, ok := img.PosForAddr(nextAddr); !ok {
			m.setStatus("at end of executable code", false)
			return false
		}
		if !m.loadDisasmWindow(nextAddr, m.disasmOverlapBytes()) {
			return false
		}
		idx, _ := m.dasm.IndexForAddr(nextAddr)
		m.dasm.Cur = idx
		m.scrollDisasmContext(3)
		return true
	}
	firstAddr := m.dasm.Inst[0].Addr
	pos, ok := img.PosForAddr(firstAddr)
	if !ok || pos == 0 {
		m.setStatus("at start of executable code", false)
		return false
	}
	if !m.loadDisasmWindow(img.AddrAt(pos-1), m.disasmMaxBytes-m.disasmOverlapBytes()) {
		return false
	}
	idx, found := m.dasm.IndexForAddr(firstAddr)
	if found && idx > 0 {
		m.dasm.Cur = idx - 1
	} else {
		m.dasm.Cur = max(0, idx)
	}
	m.scrollDisasmContext(3)
	return true
}

func (m *Model) stepDisasm(forward bool) bool {
	if len(m.dasm.Inst) == 0 {
		return false
	}
	if forward {
		if m.dasm.Cur < len(m.dasm.Inst)-1 {
			m.dasm.Cur++
			m.ensureDisasmViewport(m.disasmViewportHeight())
			return true
		}
		if m.loadDisasmWindowForStep(true) {
			m.ensureDisasmViewport(m.disasmViewportHeight())
			return true
		}
		return false
	}
	if m.dasm.Cur > 0 {
		m.dasm.Cur--
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
	steps := layout.PageStep(m.dasm.Top, len(m.dasm.Inst), m.disasmViewportHeight(), rowHeight)
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
		m.dasm.Cur = 0
		m.dasm.Top = 0
		m.dasm.RenderedTop = 0
		m.viewportDetached = false
		return
	}
	if !m.loadDisasmWindowEnding(img.Len()) {
		return
	}
	m.dasm.Cur = len(m.dasm.Inst) - 1
	m.scrollDisasmToBottom()
	m.dasm.RenderedTop = m.dasm.Top
}

func (m *Model) scrollDisasmToBottom() {
	w := m.disasmRenderWidth()
	rowHeight := func(i int) int { return m.disasmInstVisualHeight(i, w) }
	m.dasm.Top = layout.MaxViewportTop(len(m.dasm.Inst), m.disasmViewportHeight(), rowHeight)
}

func (m *Model) goBack() {
	if m.dasm.HistoryPos <= 0 {
		m.setStatus("at start of history", false)
		return
	}
	m.dasm.SnapshotCursorToHistory()
	m.dasm.HistoryPos--
	if m.loadDisasmAtNoHistory(m.dasm.History[m.dasm.HistoryPos]) {
		m.scrollDisasmContext(10)
	}
	m.setStatus(fmt.Sprintf("back (%d/%d)", m.dasm.HistoryPos+1, len(m.dasm.History)), false)
}

func (m *Model) goForward() {
	if m.dasm.HistoryPos >= len(m.dasm.History)-1 {
		m.setStatus("at end of history", false)
		return
	}
	m.dasm.SnapshotCursorToHistory()
	m.dasm.HistoryPos++
	if m.loadDisasmAtNoHistory(m.dasm.History[m.dasm.HistoryPos]) {
		m.scrollDisasmContext(10)
	}
	m.setStatus(fmt.Sprintf("forward (%d/%d)", m.dasm.HistoryPos+1, len(m.dasm.History)), false)
}

// scrollDisasmContext positions the scroll window so the cursor shows with
// context above it: from the start of the containing symbol when that fits in
// the viewport, otherwise linesAbove instructions above the cursor.
func (m *Model) scrollDisasmContext(linesAbove int) {
	n := len(m.dasm.Inst)
	if n == 0 {
		return
	}
	cur := m.dasm.Cur
	h := m.bodyHeight() - 1 // disasm scroller height (minus the sticky row)
	if h < 2 {
		m.dasm.Top = max(0, cur-linesAbove)
		return
	}
	top := cur - linesAbove
	if sym, ok := m.file.SymbolAt(m.dasm.Inst[cur].Addr); ok {
		if si, found := m.dasm.IndexForAddr(sym.Addr); found && si <= cur && cur-si <= h-2 {
			// The symbol header line plus its instructions up to the cursor all
			// fit above, so start the window at the symbol's first instruction.
			top = si
		}
	}
	if top < 0 {
		top = 0
	}
	m.dasm.Top = top
}

// jumpSymbol moves the cursor to the next (or previous) symbol that lives in
// executable code, so the user can step function-by-function through the
// disassembly. The jump is recorded in the back/forward history.
func (m *Model) jumpSymbol(forward bool) {
	if len(m.dasm.Inst) == 0 {
		return
	}
	cur := m.dasm.Inst[m.dasm.Cur].Addr
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
