package explorer

import (
	"container/heap"
	"sort"
	"strings"
	"sync"

	"github.com/rabarbra/exex/internal/disasm"
)

// scanLead is the resync context decoded before each scan chunk; small (vs the
// interactive overlap) since chunks are contiguous, and a multiple of 4 to keep
// arm64/riscv instruction alignment.
const scanLead = 1 << 10

// Match is one instruction a whole-image scan kept.
type Match struct {
	Addr uint64 // address of the matching instruction
	Text string // its (trimmed) assembly text
	Sym  string // display name of the symbol it lives in, or ""
}

// ScanMatching decodes the executable image in parallel chunks and returns the
// `limit` lowest-addressed instructions whose text satisfies match. It stops
// early when done is closed.
//
// Retained memory is bounded by limit, not by the number of matches. Each worker
// used to accumulate *every* match in its chunk, and the cap was applied only
// after all of them had been joined and sorted: searching "mov" over exex's own
// 15 MB binary matches ~98,000 instructions, so ~10 MB was allocated (and sorted)
// to show 500 rows — and it grew linearly with the target's size.
//
// Bounding it also fixes what the cap discarded. The old merge stopped after the
// first chunks filled the quota, so matches in later chunks were dropped before
// the sort even looked at them; a low-addressed hit late in the image lost to a
// high-addressed one early in it. The shared heap below compares every match, so
// the result is exactly the lowest `limit` by address.
func (s *DisasmService) ScanMatching(match func(text string) bool, limit int, done <-chan struct{}) []Match {
	if s == nil || s.file == nil || s.dis == nil || limit <= 0 {
		return nil
	}
	img := s.file.ExecImage()
	chunk := s.SearchChunkBytes()

	var starts []int
	for pos := 0; pos < img.Len(); {
		win := img.Window(pos, chunk)
		if len(win.Data) == 0 || win.End <= pos {
			break
		}
		starts = append(starts, pos)
		pos = win.End
	}
	workers := s.SearchWorkersFor(len(starts))
	sem := make(chan struct{}, workers)

	// One heap for all workers: a per-worker cap would still scale with the chunk
	// count. The lock is taken only on a match, which is rare next to the decode.
	var mu sync.Mutex
	best := make(lowestMatches, 0, limit)

	var wg sync.WaitGroup
	for _, start := range starts {
		if cancelled(done) {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(start int) {
			defer wg.Done()
			defer func() { <-sem }()
			if cancelled(done) {
				return
			}
			s.DecodeRangeFunc(start, chunk, scanLead, func(inst disasm.Inst) bool {
				if cancelled(done) {
					return false
				}
				if !match(inst.Text) {
					return true
				}
				// Check the threshold before building the match, so a saturated scan
				// stops calling SymbolAt and trimming text for hits it will discard.
				mu.Lock()
				if !best.wants(inst.Addr, limit) {
					mu.Unlock()
					return true
				}
				mu.Unlock()

				sym := ""
				if sm, ok := s.file.SymbolAt(inst.Addr); ok {
					sym = sm.Display()
				}
				hit := Match{Addr: inst.Addr, Text: strings.TrimSpace(inst.Text), Sym: sym}

				mu.Lock()
				best.push(hit, limit)
				mu.Unlock()
				return true
			})
		}(start)
	}
	wg.Wait()

	hits := []Match(best)
	sort.Slice(hits, func(i, j int) bool { return hits[i].Addr < hits[j].Addr })
	return dedupeByAddr(hits)
}

// cancelled reports whether the caller closed done.
func cancelled(done <-chan struct{}) bool {
	if done == nil {
		return false
	}
	select {
	case <-done:
		return true
	default:
		return false
	}
}

// dedupeByAddr drops repeated addresses from an address-sorted slice. Chunks
// cover disjoint offset ranges, so a duplicate needs two offsets mapping to one
// address (overlapping regions in a sparse image) — rare, and cheap to handle
// here rather than by retaining a set of every match seen.
func dedupeByAddr(hits []Match) []Match {
	out := hits[:0]
	for i, h := range hits {
		if i > 0 && h.Addr == hits[i-1].Addr {
			continue
		}
		out = append(out, h)
	}
	return out
}

// lowestMatches is a max-heap by address holding the lowest-addressed matches
// seen so far, so the largest — the next to be evicted — sits at index 0. It
// never grows beyond the caller's limit.
type lowestMatches []Match

func (h lowestMatches) Len() int           { return len(h) }
func (h lowestMatches) Less(i, j int) bool { return h[i].Addr > h[j].Addr }
func (h lowestMatches) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *lowestMatches) Push(x any)        { *h = append(*h, x.(Match)) }
func (h *lowestMatches) Pop() any {
	old := *h
	n := len(old) - 1
	it := old[n]
	*h = old[:n]
	return it
}

// wants reports whether addr would be kept: either the heap has room, or addr
// beats the worst match currently held.
func (h lowestMatches) wants(addr uint64, limit int) bool {
	return len(h) < limit || addr < h[0].Addr
}

// push inserts hit, evicting the highest-addressed match once at limit.
func (h *lowestMatches) push(hit Match, limit int) {
	if len(*h) < limit {
		heap.Push(h, hit)
		return
	}
	if hit.Addr < (*h)[0].Addr {
		(*h)[0] = hit
		heap.Fix(h, 0)
	}
}
