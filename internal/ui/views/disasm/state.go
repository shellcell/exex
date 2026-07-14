package disasm

import (
	dis "github.com/shellcell/exex/internal/disasm"
	"github.com/shellcell/exex/internal/explorer"
	"github.com/shellcell/exex/internal/ui/asmhl"
	"github.com/shellcell/exex/internal/ui/layout"
)

// HistoryCap caps the depth of the back/forward stack.
const HistoryCap = 30

// State is the disassembly view's own state: the currently loaded decode
// window, the cursor and scroll position over it, the back/forward history, and
// the render caches keyed to the window.
//
// The window is bounded: the first one is decoded lazily on first open, and
// later jumps replace it with a span around the requested address, so large
// binaries never expand into a whole-image instruction slice. The decode engine
// that produces the spans (explorer.DisasmService) and its budget/strategy
// settings stay in the shell, which also drives the async search/xref/syscall
// scans over the same image.
type State struct {
	// Inst is the decoded window; PosLo/PosHi are the image positions bounding
	// it (see explorer.Span for why PosLo is the first instruction, not the
	// window start).
	Inst  []dis.Inst
	PosLo int
	PosHi int

	Built       bool   // a first decode has happened (even if it found nothing)
	Decoding    bool   // background decode in flight
	PendingAddr uint64 // where the in-flight decode will land
	Positioned  bool   // cursor has been placed (vs. carried over a re-decode)

	Cur int // instruction the cursor is on
	Top int // first instruction row shown
	// RenderedTop is the top actually drawn by the last render. Wheel input
	// starts from this screen snapshot so queued key/mouse events cannot snap
	// the first wheel step back to the caret-derived top.
	RenderedTop int

	// History is the back/forward jump stack; HistoryPos is where in it we are.
	History    []uint64
	HistoryPos int

	// AsmHL highlights instruction text. Which implementation it is depends on
	// the build tag (Chroma or the lite scanner); only the interface is held
	// here. Rebuilt, not mutated, when the theme changes.
	AsmHL asmhl.Highlighter
	// AsmCache memoizes highlighted instruction text (colour-bearing: dropped
	// on theme changes).
	AsmCache layout.RowMemo[AsmKey, string]
	// AnnCache memoizes an instruction's annotation, keyed by its address (see
	// State.annotation). Not colour-bearing, but it bakes in symbol display
	// names, so the shell drops it with the other name-dependent caches.
	AnnCache layout.RowMemo[uint64, string]
	// HeightCache memoizes per-instruction rendered height (it otherwise
	// re-renders each instruction to count rows, which the scroll math calls
	// dozens of times per wheel tick). Reset whenever Inst is replaced.
	HeightCache layout.RowMemo[HeightKey, int]

	// ExecSecStarts maps each executable section's start address to its name,
	// so the scroller's per-row section-separator check is an O(1) lookup
	// instead of a scan over all sections. Built once (sections are immutable).
	ExecSecStarts map[uint64]string

	// SourceState is the source split pane (see source.go).
	SourceState
}

// HeightKey identifies a cached instruction height for one layout.
type HeightKey struct {
	I    int
	W    int
	Wrap bool
}

// AsmKey identifies one highlighted instruction/comment string.
type AsmKey struct {
	Text string
	Addr uint64
	Cls  dis.InstClass
}

// CurAddr returns the address under the cursor, when a window is loaded.
func (st *State) CurAddr() (uint64, bool) {
	if st.Cur < 0 || st.Cur >= len(st.Inst) {
		return 0, false
	}
	return st.Inst[st.Cur].Addr, true
}

// SetSpan installs a freshly decoded span as the visible window, dropping the
// caches keyed to the old one. It never clobbers a good window with an empty
// decode (e.g. a step that ran off the end): keeping what we have keeps the
// cursor valid. Reports whether the installed window is non-empty.
func (st *State) SetSpan(span explorer.Span) bool {
	if span.Empty() && len(st.Inst) > 0 {
		return false
	}
	st.Inst = span.Insts
	st.PosLo, st.PosHi = span.PosLo, span.PosHi
	if len(st.Inst) == 0 {
		st.Cur, st.Top, st.RenderedTop = 0, 0, 0
	} else {
		st.Cur = min(max(st.Cur, 0), len(st.Inst)-1)
		st.Top = min(max(st.Top, 0), len(st.Inst)-1)
		st.RenderedTop = min(max(st.RenderedTop, 0), len(st.Inst)-1)
	}
	st.Built = true
	st.Decoding = false
	st.PendingAddr = 0
	st.HeightCache = nil
	st.SourceAsmRowCache = nil // keyed by instruction index into the old window
	return !span.Empty()
}

// IndexForAddr finds the instruction covering addr, or the nearest one below.
func (st *State) IndexForAddr(addr uint64) (idx int, ok bool) {
	return dis.IndexForAddr(st.Inst, addr)
}

// IndexAtOrAfter returns the first instruction at or after addr.
func (st *State) IndexAtOrAfter(addr uint64) int {
	return dis.IndexAtOrAfter(st.Inst, addr)
}

// HasExact reports whether addr is exactly an instruction start in the window.
func (st *State) HasExact(addr uint64) bool {
	return dis.HasExact(st.Inst, addr)
}

// SnapshotCursorToHistory updates the current history entry to the precise
// address the cursor is parked on. Called before any operation that moves away
// from the current entry (PushHistory, back, forward), so coming back lands on
// the exact instruction the user was looking at — not the window base.
func (st *State) SnapshotCursorToHistory() {
	if st.HistoryPos < 0 || st.HistoryPos >= len(st.History) {
		return
	}
	if st.Cur < 0 || st.Cur >= len(st.Inst) {
		return
	}
	st.History[st.HistoryPos] = st.Inst[st.Cur].Addr
}

// PushHistory records a jump target as the newest history entry, truncating any
// forward entries. The caller is responsible for snapshotting the cursor
// *before* loading the new window; doing it here would be too late — the disasm
// has already been re-decoded and the cursor sits at the new address, so the
// old entry would be overwritten with the new addr and the dedup check would
// silently drop the new push.
func (st *State) PushHistory(addr uint64) {
	if st.HistoryPos < len(st.History)-1 {
		st.History = st.History[:st.HistoryPos+1]
	}
	// Don't duplicate the most-recent entry.
	if len(st.History) > 0 && st.History[len(st.History)-1] == addr {
		st.HistoryPos = len(st.History) - 1
		return
	}
	st.History = append(st.History, addr)
	if len(st.History) > HistoryCap {
		st.History = st.History[len(st.History)-HistoryCap:]
	}
	st.HistoryPos = len(st.History) - 1
}
