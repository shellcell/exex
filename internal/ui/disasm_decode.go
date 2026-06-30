package ui

// Windowed disassembly decode: turning an address into a bounded, cached slice
// of decoded instructions (the engine adapter between binfile's byte image and
// the disasm package), plus the cache, the background-decode command, and the
// index helpers that locate an instruction by address.

import (
	"sort"

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
	file  *binfile.File
	addr  uint64
	posLo int
	posHi int
	insts []disasm.Inst
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

func (m *Model) decodeDisasmAt(addr uint64, before int) (binfile.Window, []disasm.Inst) {
	return m.disasmService().DecodeAt(addr, before)
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
	win, insts := m.decodeDisasmAt(target, m.disasmLeadBytes())
	m.disasmInst = insts
	m.disasmPosLo, m.disasmPosHi = m.posLoFor(win.Start, insts), win.End
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
		win, insts := svc.DecodeAt(addr, before)
		return disasmReadyMsg{file: file, addr: addr, posLo: win.Start, posHi: win.End, insts: insts}
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

// posLoFor returns the image position of the first decoded instruction, which is
// what bounds "is there code above / where does it start". It differs from the
// decode window's Start when DecodeAt began at a symbol (a section/function jump):
// the window reserves lead bytes that hold no decoded instructions, so anchoring
// scroll-up on win.Start would jump far before the actual preceding code.
func (m *Model) posLoFor(winStart int, insts []disasm.Inst) int {
	if len(insts) > 0 {
		if p, ok := m.file.ExecImage().PosForAddr(insts[0].Addr); ok {
			return p
		}
	}
	return winStart
}

func (m *Model) setDisasmWindow(win binfile.Window, insts []disasm.Inst) bool {
	// Never clobber a good window with an empty decode (e.g. a step that ran off
	// the end): keep what we have so the cursor stays valid.
	if len(insts) == 0 && len(m.disasmInst) > 0 {
		return false
	}
	m.disasmInst = insts
	m.disasmPosLo = m.posLoFor(win.Start, insts)
	m.disasmPosHi = win.End
	m.disasmBuilt = true
	m.disasmDecoding = false
	m.disasmPendingAddr = 0
	m.sourceAsmRowCache = nil
	m.disasmHeightCache = nil
	return len(insts) > 0
}

func (m *Model) loadDisasmWindow(addr uint64, before int) bool {
	win, insts := m.decodeDisasmAt(addr, before)
	if !m.setDisasmWindow(win, insts) {
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
	win := img.Window(start, end-start)
	insts := m.disasmService().DecodeWindow(win)
	if !m.setDisasmWindow(win, insts) {
		m.setStatus("no executable code to disassemble", true)
		return false
	}
	m.setMode(modeDisasm)
	return true
}
