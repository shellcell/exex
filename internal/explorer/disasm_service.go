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

// disasmCacheKey identifies a decoded instruction window and its overlap start.
type disasmCacheKey struct {
	start       int
	end         int
	decodeStart int
}

// disasmCacheCap bounds decoded-window memory retained by the service.
const disasmCacheCap = 24

// NewDisasmService creates a bounded disassembly decoder/cache.
func NewDisasmService(file *binfile.File, dis disasm.Disassembler, maxBytes, searchWorkers int) *DisasmService {
	s := &DisasmService{
		file:  file,
		dis:   dis,
		cache: map[disasmCacheKey][]disasm.Inst{},
	}
	s.SetOptions(maxBytes, searchWorkers)
	return s
}

// SetOptions updates the decode budget and search worker preference.
func (s *DisasmService) SetOptions(maxBytes, searchWorkers int) {
	if maxBytes <= 0 {
		maxBytes = 1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxBytes = maxBytes
	s.searchWorkers = searchWorkers
}

// OverlapBytes returns the context decoded before each visible window.
func (s *DisasmService) OverlapBytes() int {
	maxBytes, _ := s.options()
	return overlapBytes(maxBytes)
}

// overlapBytes derives a safe overlap from a decode budget.
func overlapBytes(maxBytes int) int {
	overlap := max(maxBytes/8, 4<<10)
	if overlap >= maxBytes {
		overlap = max(1, maxBytes/2)
	}
	return overlap
}

// LeadBytes returns the preferred bytes of context before a target address.
func (s *DisasmService) LeadBytes() int {
	maxBytes, _ := s.options()
	return leadBytes(maxBytes)
}

// leadBytes derives pre-target context from a decode budget.
func leadBytes(maxBytes int) int {
	overlap := overlapBytes(maxBytes)
	lead := max(maxBytes/4, overlap)
	if lead >= maxBytes {
		lead = max(0, maxBytes-1)
	}
	return lead
}

// SearchChunkBytes returns the background-search chunk size.
func (s *DisasmService) SearchChunkBytes() int {
	maxBytes, _ := s.options()
	return searchChunkBytes(maxBytes)
}

// searchChunkBytes derives a bounded search chunk size from a decode budget.
func searchChunkBytes(maxBytes int) int {
	return min(min(max(maxBytes/8, 64<<10), 512<<10), maxBytes)
}

// SearchBatchChunks returns how many chunks should be queued per search batch.
func (s *DisasmService) SearchBatchChunks() int {
	maxBytes, searchWorkers := s.options()
	n := max(searchWorkersFor(searchWorkers, 0), 2)
	if searchChunkBytes(maxBytes) <= 128<<10 {
		n *= 2
	}
	if n > 8 {
		n = 8
	}
	return n
}

// SearchWorkersFor returns the worker count capped by available chunks.
func (s *DisasmService) SearchWorkersFor(chunks int) int {
	_, searchWorkers := s.options()
	return searchWorkersFor(searchWorkers, chunks)
}

// searchWorkersFor applies configured/default worker policy.
func searchWorkersFor(configured, chunks int) int {
	workers := configured
	if workers <= 0 {
		workers = max(min(runtime.GOMAXPROCS(0), 6), 1)
	}
	if chunks > 0 && workers > chunks {
		workers = chunks
	}
	if workers < 1 {
		workers = 1
	}
	return workers
}

// DecodeWindow decodes instructions overlapping win, using cache and overlap.
func (s *DisasmService) DecodeWindow(win binfile.Window) []disasm.Inst {
	if len(win.Data) == 0 || s == nil || s.file == nil || s.dis == nil {
		return nil
	}
	maxBytes, _ := s.options()
	decodeStart := max(0, win.Start-overlapBytes(maxBytes))
	return s.decodeInstWindow(win, decodeStart)
}

// DecodeRange decodes the instructions in [start, start+size) of the executable
// image, using only `lead` bytes of context before start to re-synchronise the
// decoder (vs DecodeWindow's large interactive overlap). It is uncached, so a
// contiguous full-image scan neither re-decodes each chunk's predecessor (~2×
// less work) nor evicts the interactive decode cache. `lead` should keep the
// architecture's instruction alignment (a multiple of 4 covers arm64/riscv).
func (s *DisasmService) DecodeRange(start, size, lead int) []disasm.Inst {
	if s == nil || s.file == nil || s.dis == nil {
		return nil
	}
	img := s.file.ExecImage()
	win := img.Window(start, size)
	if len(win.Data) == 0 {
		return nil
	}
	decodeStart := max(0, win.Start-lead)
	return s.decodeAcross(img, decodeStart, win.End, win.Start)
}

// DecodeAt returns a window containing addr and the instructions overlapping it.
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

// PrefetchAround warms the decode cache around addr for smoother navigation.
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

// decodeInstWindow decodes from decodeStart and filters to visible instructions.
func (s *DisasmService) decodeInstWindow(win binfile.Window, decodeStart int) []disasm.Inst {
	if len(win.Data) == 0 || s.file == nil || s.dis == nil {
		return nil
	}
	key := disasmCacheKey{start: win.Start, end: win.End, decodeStart: decodeStart}
	if insts, ok := s.cacheGet(key); ok {
		return insts
	}
	insts := s.decodeAcross(s.file.ExecImage(), decodeStart, win.End, win.Start)
	s.cachePut(key, insts)
	return insts
}

// decodeAcross decodes [decodeStart, end) of img one region at a time, so each
// section's bytes are addressed from its own virtual address — correct even when
// the image flattens sections with non-contiguous addresses (a higher-half
// kernel's low .multiboot code and high .text, an object file's sections, …). A
// single linear decode across such a gap would mis-address everything past the
// jump. Only instructions at offset >= visibleStart are returned; the bytes
// before it are decode-resync context that is dropped.
func (s *DisasmService) decodeAcross(img *binfile.Image, decodeStart, end, visibleStart int) []disasm.Inst {
	if img == nil || s.dis == nil || decodeStart < 0 || end > img.Len() {
		end = min(end, img.Len())
	}
	var out []disasm.Inst
	for p := decodeStart; p < end; {
		r := img.RegionAt(p)
		if r == nil {
			break // gap (sparse maps only); section images are contiguous in offset
		}
		regEnd := min(r.Off+int(r.Size), end)
		data := img.Bytes(p, regEnd)
		if len(data) == 0 {
			break
		}
		stop := false
		disasm.RangeFunc(s.dis, data, img.AddrAt(p), func(in disasm.Inst) bool {
			off := r.Off + int(in.Addr-r.Addr) // this instruction's image offset
			if off < visibleStart {
				return true // resync context before the visible window
			}
			if off >= end {
				stop = true
				return false
			}
			out = append(out, in)
			return true
		})
		if stop {
			break
		}
		p = regEnd
	}
	return out
}

// options returns a consistent snapshot of mutable service options.
func (s *DisasmService) options() (maxBytes, searchWorkers int) {
	s.mu.RLock()
	maxBytes, searchWorkers = s.maxBytes, s.searchWorkers
	s.mu.RUnlock()
	return maxBytes, searchWorkers
}

// cacheGet returns a cached decoded window.
func (s *DisasmService) cacheGet(key disasmCacheKey) ([]disasm.Inst, bool) {
	s.mu.RLock()
	insts, ok := s.cache[key]
	s.mu.RUnlock()
	return insts, ok
}

// cachePut stores a decoded window and evicts the oldest entries over capacity.
func (s *DisasmService) cachePut(key disasmCacheKey, insts []disasm.Inst) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.cache[key]; !ok {
		s.order = append(s.order, key)
	}
	s.cache[key] = insts
	// Evict oldest over capacity, compacting in place so the backing array's head
	// isn't leaked by repeated reslicing.
	if n := len(s.order) - disasmCacheCap; n > 0 {
		for _, old := range s.order[:n] {
			delete(s.cache, old)
		}
		s.order = append(s.order[:0], s.order[n:]...)
	}
}
