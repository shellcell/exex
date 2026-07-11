package ui

// Disassembly navigation: moving the cursor, paging, jumping to symbols and
// boundaries, and the back/forward history stack.

import (
	"fmt"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/explorer"
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
	m.dasm.EnsureViewport(m.dasmEnv(), h)
}

func (m *Model) stepDisasm(forward bool) bool {
	return m.dasm.Step(m.dasmEnv(), forward, m.disasmViewportHeight())
}

func (m *Model) moveDisasmPage(forward bool) {
	m.dasm.MovePage(m.dasmEnv(), forward, m.disasmViewportHeight(), m.disasmRowHeight(m.disasmRenderWidth()))
}

func (m *Model) jumpDisasmBoundary(forward bool) {
	ok := m.dasm.JumpBoundary(m.dasmEnv(), forward, m.disasmViewportHeight(), m.disasmRowHeight(m.disasmRenderWidth()))
	// Only the jump to the start re-attaches the viewport; the end jump keeps a
	// detached viewport where the user scrolled it.
	if ok && !forward {
		m.viewportDetached = false
	}
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

func (m *Model) scrollDisasmContext(linesAbove int) {
	m.dasm.ScrollContext(m.dasmEnv(), linesAbove, m.bodyHeight()-1)
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
