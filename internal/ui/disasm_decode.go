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
	disasmview "github.com/rabarbra/exex/internal/ui/views/disasm"
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
	return m.backgroundCmd(func() tea.Msg {
		svc.PrefetchAround(addr)
		return disasmPrefetchMsg{}
	})
}

func (m *Model) decodeDisasmAt(addr uint64, before int) explorer.Span {
	return m.disasmService().DecodeSpanAt(addr, before)
}

// ensureDisasm decodes synchronously on first use. It's the path jumps take
// (goto/follow/openSymbol): the user asked to land somewhere specific, so we
// can't defer. Returns false when there's no disassembler or no code. The
// view-switch path uses the asynchronous decodeDisasmCmd instead.
func (m *Model) ensureDisasm() bool {
	if m.dasm.Built {
		return m.dis != nil && len(m.dasm.Inst) > 0
	}
	m.dasm.Built = true
	m.dasm.Decoding = false
	m.dasm.PendingAddr = 0
	if m.dis == nil {
		return false
	}
	target := m.disasmInitAddr
	if target == 0 {
		target = explorer.DefaultExecAddr(m.file, m.disasmTarget)
	}
	span := m.decodeDisasmAt(target, m.disasmLeadBytes())
	m.dasm.Inst = span.Insts
	m.dasm.PosLo, m.dasm.PosHi = span.PosLo, span.PosHi
	m.dasm.HeightCache = nil
	return len(m.dasm.Inst) > 0
}

// decodeDisasmCmd decodes a bounded executable span off the main goroutine and
// delivers it as a disasmReadyMsg.
func (m *Model) decodeDisasmCmd(addr uint64) tea.Cmd {
	svc := m.disasmService()
	file := m.file
	before := svc.LeadBytes()
	return m.backgroundCmd(func() tea.Msg {
		span := svc.DecodeSpanAt(addr, before)
		return disasmReadyMsg{file: file, addr: addr, span: span}
	})
}

// disasmLoadedAddr reports whether addr is inside the decoded window *and* lands
// on an instruction there.
func (m *Model) disasmLoadedAddr(addr uint64) bool {
	return m.dasm.LoadedAddr(m.file, addr)
}

func (m *Model) loadDisasmWindow(addr uint64, before int) bool {
	return m.dasm.LoadWindow(m.dasmEnv(), addr, before)
}

// dasmEnv bundles what the disasm view's navigation needs from the shell.
func (m *Model) dasmEnv() disasmview.Env {
	return disasmview.Env{File: m.file, Svc: m.disasmService(), Host: m}
}

// ShowDisasmView implements disasmview.Host.
func (m *Model) ShowDisasmView() {
	m.setMode(modeDisasm)
}
