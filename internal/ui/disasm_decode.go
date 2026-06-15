package ui

// Windowed disassembly decode: turning an address into a bounded, cached slice
// of decoded instructions (the engine adapter between binfile's byte image and
// the disasm package), plus the cache, the background-decode command, and the
// index helpers that locate an instruction by address.

import (
	"runtime"
	"sort"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/disasm"
)

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
	// Never clobber a good window with an empty decode (e.g. a step that ran off
	// the end): keep what we have so the cursor stays valid.
	if len(insts) == 0 && len(m.disasmInst) > 0 {
		return false
	}
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
