package disasm

// Navigation over the decoded window: moving the cursor, paging, keeping the
// viewport around the cursor, and re-decoding a neighbouring span when movement
// runs off the window's edge. Jump policy (where an address outside executable
// code redirects to, mode switching, the back/forward commands and symbol
// jumps) stays in the shell — it decides *where* to go; State moves there.

import (
	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/explorer"
	"github.com/rabarbra/exex/internal/ui/layout"
)

// Host is what navigation needs back from the shell.
type Host interface {
	SetStatus(msg string, isErr bool)
	// DisasmWindowSwapped tells the shell a new decode window replaced the old
	// one, so shell-side caches keyed to instruction indices (the source pane's
	// asm rows) must drop.
	DisasmWindowSwapped()
	// ShowDisasmView makes the disasm view the active one. Every successful
	// window install implies it: navigation that decoded a window must also be
	// looking at it (jumps can arrive from any view).
	ShowDisasmView()
}

// Env bundles the per-call dependencies of a navigation step: the binary, the
// decode engine, and the shell. Built fresh by the shell for each call, like a
// view.Context.
type Env struct {
	File *binfile.File
	Svc  *explorer.DisasmService
	Host Host
}

// installSpan is SetSpan plus the shell notifications.
func (st *State) installSpan(env Env, span explorer.Span) bool {
	ok := st.SetSpan(span)
	env.Host.DisasmWindowSwapped()
	if ok {
		env.Host.ShowDisasmView()
	}
	return ok
}

// LoadWindow decodes a span around addr (with `before` bytes of lead-in) and
// installs it as the visible window.
func (st *State) LoadWindow(env Env, addr uint64, before int) bool {
	if !st.installSpan(env, env.Svc.DecodeSpanAt(addr, before)) {
		env.Host.SetStatus("no executable code to disassemble", true)
		return false
	}
	return true
}

// LoadWindowEnding decodes the span that ends at image position end, for
// jumping to the bottom of the executable code.
func (st *State) LoadWindowEnding(env Env, end int) bool {
	img := env.File.ExecImage()
	if end <= 0 || img.Len() == 0 {
		return false
	}
	if end > img.Len() {
		end = img.Len()
	}
	start := max(0, end-env.Svc.MaxBytes())
	if !st.installSpan(env, env.Svc.DecodeSpanWindow(img.Window(start, end-start))) {
		env.Host.SetStatus("no executable code to disassemble", true)
		return false
	}
	return true
}

// EnsureViewport scrolls Top so the cursor is visible in a viewport of h rows,
// re-decoding a neighbouring window when the cursor is pinned to an edge that
// still has undecoded code beyond it.
func (st *State) EnsureViewport(env Env, h int) {
	if len(st.Inst) == 0 || h < 1 {
		return
	}
	img := env.File.ExecImage()
	curAddr := st.Inst[st.Cur].Addr
	for tries := 0; tries < 2; tries++ {
		if st.Cur < st.Top {
			st.Top = st.Cur
		} else if st.Cur >= st.Top+h {
			st.Top = st.Cur - h + 1
		}
		end := min(len(st.Inst), st.Top+h)
		needAbove := st.Top == 0 && st.Cur == 0 && st.PosLo > 0
		needBelow := end == len(st.Inst) && st.Cur == len(st.Inst)-1 && st.PosHi < img.Len()
		if !needAbove && !needBelow {
			return
		}
		if needAbove {
			before := env.Svc.MaxBytes() - env.Svc.OverlapBytes()
			if !st.LoadWindow(env, img.AddrAt(st.PosLo-1), before) {
				return
			}
		} else {
			last := st.Inst[len(st.Inst)-1]
			nextAddr := last.Addr + uint64(len(last.Bytes))
			if _, ok := img.PosForAddr(nextAddr); !ok || !st.LoadWindow(env, nextAddr, env.Svc.OverlapBytes()) {
				return
			}
		}
		st.Cur = st.IndexAtOrAfter(curAddr)
		if st.Cur >= h {
			st.Top = st.Cur - min(st.Cur, h/2)
		} else {
			st.Top = 0
		}
	}
}

// loadWindowForStep re-decodes one window forward or backward when a cursor
// step runs off the current window's edge.
func (st *State) loadWindowForStep(env Env, forward bool, h int) bool {
	if len(st.Inst) == 0 {
		return false
	}
	img := env.File.ExecImage()
	if forward {
		last := st.Inst[len(st.Inst)-1]
		nextAddr := last.Addr + uint64(len(last.Bytes))
		if _, ok := img.PosForAddr(nextAddr); !ok {
			env.Host.SetStatus("at end of executable code", false)
			return false
		}
		if !st.LoadWindow(env, nextAddr, env.Svc.OverlapBytes()) {
			return false
		}
		idx, _ := st.IndexForAddr(nextAddr)
		st.Cur = idx
		st.ScrollContext(env, 3, h)
		return true
	}
	firstAddr := st.Inst[0].Addr
	pos, ok := img.PosForAddr(firstAddr)
	if !ok || pos == 0 {
		env.Host.SetStatus("at start of executable code", false)
		return false
	}
	if !st.LoadWindow(env, img.AddrAt(pos-1), env.Svc.MaxBytes()-env.Svc.OverlapBytes()) {
		return false
	}
	idx, found := st.IndexForAddr(firstAddr)
	if found && idx > 0 {
		st.Cur = idx - 1
	} else {
		st.Cur = max(0, idx)
	}
	st.ScrollContext(env, 3, h)
	return true
}

// Step moves the cursor one instruction, re-decoding past the window edge.
func (st *State) Step(env Env, forward bool, h int) bool {
	if len(st.Inst) == 0 {
		return false
	}
	if forward {
		if st.Cur < len(st.Inst)-1 {
			st.Cur++
			st.EnsureViewport(env, h)
			return true
		}
		if st.loadWindowForStep(env, true, h) {
			st.EnsureViewport(env, h)
			return true
		}
		return false
	}
	if st.Cur > 0 {
		st.Cur--
		st.EnsureViewport(env, h)
		return true
	}
	if st.loadWindowForStep(env, false, h) {
		st.EnsureViewport(env, h)
		return true
	}
	return false
}

// MovePage advances by one screenful of instructions: the number that fill the
// scroller height at the current top, accounting for multi-line (wrapped) rows
// via rowHeight.
func (st *State) MovePage(env Env, forward bool, h int, rowHeight func(int) int) {
	steps := layout.PageStep(st.Top, len(st.Inst), h, rowHeight)
	steps = max(1, steps-1) // keep one instruction of context between pages
	for range steps {
		if !st.Step(env, forward, h) {
			return
		}
	}
}

// JumpBoundary jumps to the first or last decodable instruction of the image.
// Reports whether the viewport should re-attach (the shell owns that flag).
func (st *State) JumpBoundary(env Env, forward bool, h int, rowHeight func(int) int) bool {
	img := env.File.ExecImage()
	if img.Len() == 0 {
		return false
	}
	if !forward {
		if !st.LoadWindow(env, img.AddrAt(0), 0) {
			return false
		}
		st.Cur = 0
		st.Top = 0
		st.RenderedTop = 0
		return true
	}
	if !st.LoadWindowEnding(env, img.Len()) {
		return false
	}
	st.Cur = len(st.Inst) - 1
	st.ScrollToBottom(h, rowHeight)
	st.RenderedTop = st.Top
	return true
}

// ScrollToBottom pins the viewport to the end of the window.
func (st *State) ScrollToBottom(h int, rowHeight func(int) int) {
	st.Top = layout.MaxViewportTop(len(st.Inst), h, rowHeight)
}

// ScrollContext positions the scroll window so the cursor shows with context
// above it: from the start of the containing symbol when that fits in a
// viewport of h rows, otherwise linesAbove instructions above the cursor. An
// h < 2 (degenerate pane) skips the symbol heuristic.
func (st *State) ScrollContext(env Env, linesAbove, h int) {
	n := len(st.Inst)
	if n == 0 {
		return
	}
	cur := st.Cur
	if h < 2 {
		st.Top = max(0, cur-linesAbove)
		return
	}
	top := cur - linesAbove
	if sym, ok := env.File.SymbolAt(st.Inst[cur].Addr); ok {
		if si, found := st.IndexForAddr(sym.Addr); found && si <= cur && cur-si <= h-2 {
			// The symbol header line plus its instructions up to the cursor all
			// fit above, so start the window at the symbol's first instruction.
			top = si
		}
	}
	if top < 0 {
		top = 0
	}
	st.Top = top
}
