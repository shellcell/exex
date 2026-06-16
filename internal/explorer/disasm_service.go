package explorer

import (
	"runtime"
	"sync"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/disasm"
)

// DisasmService owns bounded disassembly window decoding and its cache. It is
// independent of the TUI event loop; callers decide how decoded windows affect
// UI state.
type DisasmService struct {
	file          *binfile.File
	dis           disasm.Disassembler
	maxBytes      int
	searchWorkers int

	mu    sync.RWMutex
	cache map[disasmCacheKey][]disasm.Inst
	order []disasmCacheKey
}

type disasmCacheKey struct {
	start       int
	end         int
	decodeStart int
}

const disasmCacheCap = 24

func NewDisasmService(file *binfile.File, dis disasm.Disassembler, maxBytes, searchWorkers int) *DisasmService {
	s := &DisasmService{
		file:  file,
		dis:   dis,
		cache: map[disasmCacheKey][]disasm.Inst{},
	}
	s.SetOptions(maxBytes, searchWorkers)
	return s
}

func (s *DisasmService) SetOptions(maxBytes, searchWorkers int) {
	if maxBytes <= 0 {
		maxBytes = 1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxBytes = maxBytes
	s.searchWorkers = searchWorkers
}

func (s *DisasmService) OverlapBytes() int {
	maxBytes, _ := s.options()
	return overlapBytes(maxBytes)
}

func overlapBytes(maxBytes int) int {
	overlap := maxBytes / 8
	if overlap < 4<<10 {
		overlap = 4 << 10
	}
	if overlap >= maxBytes {
		overlap = max(1, maxBytes/2)
	}
	return overlap
}

func (s *DisasmService) LeadBytes() int {
	maxBytes, _ := s.options()
	return leadBytes(maxBytes)
}

func leadBytes(maxBytes int) int {
	overlap := overlapBytes(maxBytes)
	lead := maxBytes / 4
	if lead < overlap {
		lead = overlap
	}
	if lead >= maxBytes {
		lead = max(0, maxBytes-1)
	}
	return lead
}

func (s *DisasmService) SearchChunkBytes() int {
	maxBytes, _ := s.options()
	return searchChunkBytes(maxBytes)
}

func searchChunkBytes(maxBytes int) int {
	chunk := maxBytes / 8
	if chunk < 64<<10 {
		chunk = 64 << 10
	}
	if chunk > 512<<10 {
		chunk = 512 << 10
	}
	if chunk > maxBytes {
		chunk = maxBytes
	}
	return chunk
}

func (s *DisasmService) SearchBatchChunks() int {
	maxBytes, searchWorkers := s.options()
	n := searchWorkersFor(searchWorkers, 0)
	if n < 2 {
		n = 2
	}
	if searchChunkBytes(maxBytes) <= 128<<10 {
		n *= 2
	}
	if n > 8 {
		n = 8
	}
	return n
}

func (s *DisasmService) SearchWorkersFor(chunks int) int {
	_, searchWorkers := s.options()
	return searchWorkersFor(searchWorkers, chunks)
}

func searchWorkersFor(configured, chunks int) int {
	workers := configured
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

func (s *DisasmService) DecodeWindow(win binfile.Window) []disasm.Inst {
	if len(win.Data) == 0 || s == nil || s.file == nil || s.dis == nil {
		return nil
	}
	maxBytes, _ := s.options()
	decodeStart := max(0, win.Start-overlapBytes(maxBytes))
	return s.decodeInstWindow(win, decodeStart)
}

func (s *DisasmService) DecodeAt(addr uint64, before int) (binfile.Window, []disasm.Inst) {
	if s == nil || s.file == nil || s.dis == nil {
		return binfile.Window{}, nil
	}
	maxBytes, _ := s.options()
	img := s.file.ExecImage()
	win, ok := img.WindowContaining(addr, maxBytes, before)
	if !ok {
		return binfile.Window{}, nil
	}
	decodeStart := max(0, win.Start-overlapBytes(maxBytes))
	if sym, ok := s.file.SymbolAt(addr); ok {
		if pos, mapped := img.PosForAddr(sym.Addr); mapped && pos < win.End {
			if sym.Addr == addr {
				decodeStart = pos
			} else if pos >= decodeStart {
				decodeStart = pos
			}
		}
	}
	return win, s.decodeInstWindow(win, decodeStart)
}

func (s *DisasmService) PrefetchAround(addr uint64) {
	if s == nil || s.file == nil || s.dis == nil {
		return
	}
	img := s.file.ExecImage()
	if img.Len() == 0 {
		return
	}
	pos, ok := img.PosForAddr(addr)
	if !ok {
		return
	}
	maxBytes, _ := s.options()
	chunk := searchChunkBytes(maxBytes)
	before := max(0, pos-chunk)
	after := pos + chunk
	if after > img.Len()-1 {
		after = img.Len() - 1
	}
	wins := []binfile.Window{
		img.Window(before, min(chunk, img.Len()-before)),
		img.Window(pos, min(chunk, img.Len()-pos)),
	}
	for _, win := range wins {
		if len(win.Data) > 0 {
			s.DecodeWindow(win)
		}
	}
	if after > pos {
		win := img.Window(after, min(chunk, img.Len()-after))
		if len(win.Data) > 0 {
			s.DecodeWindow(win)
		}
	}
}

func (s *DisasmService) decodeInstWindow(win binfile.Window, decodeStart int) []disasm.Inst {
	if len(win.Data) == 0 || s.file == nil || s.dis == nil {
		return nil
	}
	key := disasmCacheKey{start: win.Start, end: win.End, decodeStart: decodeStart}
	if insts, ok := s.cacheGet(key); ok {
		return insts
	}
	img := s.file.ExecImage()
	decodeWin := img.Window(decodeStart, win.End-decodeStart)
	insts := disasm.Range(s.dis, decodeWin.Data, decodeWin.Addr, 0)
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
	s.cachePut(key, insts)
	return insts
}

func (s *DisasmService) options() (maxBytes, searchWorkers int) {
	s.mu.RLock()
	maxBytes, searchWorkers = s.maxBytes, s.searchWorkers
	s.mu.RUnlock()
	return maxBytes, searchWorkers
}

func (s *DisasmService) cacheGet(key disasmCacheKey) ([]disasm.Inst, bool) {
	s.mu.RLock()
	insts, ok := s.cache[key]
	s.mu.RUnlock()
	return insts, ok
}

func (s *DisasmService) cachePut(key disasmCacheKey, insts []disasm.Inst) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.cache[key]; !ok {
		s.order = append(s.order, key)
	}
	s.cache[key] = insts
	for len(s.order) > disasmCacheCap {
		old := s.order[0]
		s.order = s.order[1:]
		delete(s.cache, old)
	}
}
