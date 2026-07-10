package ui

// Windowed disassembly decode: turning an address into a bounded, cached slice
// of decoded instructions (the engine adapter between binfile's byte image and
// the disasm package), plus the cache, the background-decode command, and the
// index helpers that locate an instruction by address.

import (
	tea "charm.land/bubbletea/v2"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/disasm"
	"github.com/rabarbra/exex/internal/dump"
	"github.com/rabarbra/exex/internal/explorer"
)

// functionInsts decodes the instructions making up sym's extent, fresh from the
// executable image so the whole function is covered even when the visible window
// doesn't span it. Shares the decode with the non-interactive `-o` dump.
func (m *Model) functionInsts(sym binfile.Symbol) []disasm.Inst {
	if sym.Size == 0 || m.dis == nil {
		return nil
	}
	return dump.FunctionInsts(m.file, m.disasmService(), sym)
}

// disasmReadyMsg carries the finished decode from the background worker.
type disasmReadyMsg struct {
	file *binfile.File
	addr uint64
	span explorer.Span
}

type disasmPrefetchMsg struct{}

func (m *Model) disasmService() *explorer.DisasmService {
	if m.disasmSvc == nil {
		m.disasmSvc = explorer.NewDisasmService(m.file, m.dis, m.disasmMaxBytes, m.disasmSearchWorkers)
	}
	m.disasmSvc.SetOptions(m.disasmMaxBytes, m.disasmSearchWorkers)
	return m.disasmSvc
}

func (m *Model) disasmOverlapBytes() int {
	return m.disasmService().OverlapBytes()
}

func (m *Model) disasmLeadBytes() int {
	return m.disasmService().LeadBytes()
}

func (m *Model) disasmSearchChunkBytes() int {
	return m.disasmService().SearchChunkBytes()
}

func (m *Model) prefetchDisasmAroundCmd(addr uint64) tea.Cmd {
	if m.dis == nil {
		return nil
	}
	svc := m.disasmService()
	return func() tea.Msg {
		svc.PrefetchAround(addr)
		return disasmPrefetchMsg{}
	}
}

func (m *Model) decodeDisasmAt(addr uint64, before int) explorer.Span {
	return m.disasmService().DecodeSpanAt(addr, before)
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
		target = explorer.DefaultExecAddr(m.file, m.disasmTarget)
	}
	span := m.decodeDisasmAt(target, m.disasmLeadBytes())
	m.disasmInst = span.Insts
	m.disasmPosLo, m.disasmPosHi = span.PosLo, span.PosHi
	m.disasmHeightCache = nil
	return len(m.disasmInst) > 0
}

// decodeDisasmCmd decodes a bounded executable span off the main goroutine and
// delivers it as a disasmReadyMsg.
func (m *Model) decodeDisasmCmd(addr uint64) tea.Cmd {
	svc := m.disasmService()
	file := m.file
	before := svc.LeadBytes()
	return func() tea.Msg {
		span := svc.DecodeSpanAt(addr, before)
		return disasmReadyMsg{file: file, addr: addr, span: span}
	}
}

// disasmLoadedAddr reports whether addr is inside the decoded window *and* lands
// on an instruction there.
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
	return disasm.HasExact(m.disasmInst, addr)
}

// instIndexForAddr finds the instruction covering addr, or the nearest one below.
func (m *Model) instIndexForAddr(addr uint64) (idx int, ok bool) {
	return disasm.IndexForAddr(m.disasmInst, addr)
}

// instIndexAtOrAfterAddr returns the first instruction at or after addr.
func (m *Model) instIndexAtOrAfterAddr(addr uint64) int {
	return disasm.IndexAtOrAfter(m.disasmInst, addr)
}

// setDisasmSpan installs a freshly decoded span as the visible window.
func (m *Model) setDisasmSpan(span explorer.Span) bool {
	// Never clobber a good window with an empty decode (e.g. a step that ran off
	// the end): keep what we have so the cursor stays valid.
	if span.Empty() && len(m.disasmInst) > 0 {
		return false
	}
	m.disasmInst = span.Insts
	m.disasmPosLo, m.disasmPosHi = span.PosLo, span.PosHi
	m.disasmBuilt = true
	m.disasmDecoding = false
	m.disasmPendingAddr = 0
	m.sourceAsmRowCache = nil
	m.disasmHeightCache = nil
	return !span.Empty()
}

func (m *Model) loadDisasmWindow(addr uint64, before int) bool {
	if !m.setDisasmSpan(m.decodeDisasmAt(addr, before)) {
		m.setStatus("no executable code to disassemble", true)
		return false
	}
	m.setMode(modeDisasm)
	return true
}

func (m *Model) loadDisasmWindowEnding(end int) bool {
	img := m.file.ExecImage()
	if end <= 0 || img.Len() == 0 {
		return false
	}
	if end > img.Len() {
		end = img.Len()
	}
	start := max(0, end-m.disasmMaxBytes)
	if !m.setDisasmSpan(m.disasmService().DecodeSpanWindow(img.Window(start, end-start))) {
		m.setStatus("no executable code to disassemble", true)
		return false
	}
	m.setMode(modeDisasm)
	return true
}
