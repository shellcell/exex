package binfile

import (
	"container/heap"
	"runtime"
	"slices"
	"strings"
	"sync"
)

// sortSymbolsByName sorts syms by Name in place. For large tables it sorts
// per-CPU chunks concurrently, then k-way merges them — a noticeable win at
// startup, where the symbol sort is one of the biggest Open costs on binaries
// with hundreds of thousands of symbols.
func sortSymbolsByName(syms []Symbol) {
	byName := func(a, b Symbol) int { return strings.Compare(a.Name, b.Name) }
	n := len(syms)
	w := min(max(runtime.NumCPU(), 1), 16)
	if n < 1<<13 || w == 1 {
		slices.SortFunc(syms, byName)
		return
	}

	chunk := (n + w - 1) / w
	runs := make([][]Symbol, 0, w)
	var wg sync.WaitGroup
	for lo := 0; lo < n; lo += chunk {
		r := syms[lo:min(lo+chunk, n)]
		runs = append(runs, r)
		wg.Add(1)
		go func(r []Symbol) { defer wg.Done(); slices.SortFunc(r, byName) }(r)
	}
	wg.Wait()

	// k-way merge the sorted runs into a temporary, then copy back so the symbol
	// slice keeps its backing (symByAddr et al. are built from it afterward).
	out := make([]Symbol, 0, n)
	h := &symRunHeap{runs: runs, pos: make([]int, len(runs))}
	for i := range runs {
		if len(runs[i]) > 0 {
			h.order = append(h.order, i)
		}
	}
	heap.Init(h)
	for h.Len() > 0 {
		r := h.order[0]
		out = append(out, runs[r][h.pos[r]])
		h.pos[r]++
		if h.pos[r] < len(runs[r]) {
			heap.Fix(h, 0)
		} else {
			heap.Pop(h)
		}
	}
	copy(syms, out)
}

// symRunHeap is a min-heap over the head element of each not-yet-exhausted run,
// keyed by symbol name, for the k-way merge above.
type symRunHeap struct {
	runs  [][]Symbol
	pos   []int // current index within each run
	order []int // heap of run indices still in play
}

func (h *symRunHeap) Len() int { return len(h.order) }
func (h *symRunHeap) Less(i, j int) bool {
	ri, rj := h.order[i], h.order[j]
	return h.runs[ri][h.pos[ri]].Name < h.runs[rj][h.pos[rj]].Name
}
func (h *symRunHeap) Swap(i, j int) { h.order[i], h.order[j] = h.order[j], h.order[i] }
func (h *symRunHeap) Push(x any)    { h.order = append(h.order, x.(int)) }
func (h *symRunHeap) Pop() any {
	m := len(h.order) - 1
	v := h.order[m]
	h.order = h.order[:m]
	return v
}
