package disasm

// Mouse geometry: mapping a wheel delta or a click row onto the view's own
// scroll state. Every other view keeps this next to its renderer (see hexraw's
// Scroll/CaptureViewportTop/Click), because the mapping has to replay exactly
// what the renderer emitted — variable-height rows, the sticky symbol line, the
// source pane's header and caret rows.
//
// These run only while the disasm view is active, so the pane geometry is
// derived from the Context rather than passed in.

import (
	"github.com/rabarbra/exex/internal/ui/layout"
	"github.com/rabarbra/exex/internal/ui/view"
)

// RenderWidth is the width the instruction scroller renders at: half the
// screen when the source pane rides beside it, otherwise the full width.
func (st *State) RenderWidth(ctx *view.Context) int {
	if st.ShowSource && ctx.File.HasDWARF() && !st.SourceFirst {
		return ctx.Width / 2
	}
	return ctx.Width
}

// ViewportHeight is the scroller's row count: the body minus the sticky symbol
// line. It is also the source pane's content height (its title row costs the
// same one row).
func (st *State) ViewportHeight(ctx *view.Context) int { return max(1, ctx.BodyH-1) }

// SourcePaneWidth is the width of the source pane in the source-first split.
func (st *State) SourcePaneWidth(ctx *view.Context) int {
	if ctx.Width <= 1 {
		return ctx.Width
	}
	return ctx.Width / 2
}

// sourceFirstOpen reports whether the source text is the leading pane. The
// file may still be unreadable — the wheel handlers below deliberately do
// nothing in that case rather than falling through to the scroller, which is
// behind the source pane and not what the user is pointing at.
func (st *State) sourceFirstOpen() bool { return st.SourceFirst && st.SrcFile != "" }

// CaptureViewportTop pins the scroll state to the top actually drawn by the
// last render, so a wheel gesture starts from what the user sees rather than
// from the caret-derived top.
func (st *State) CaptureViewportTop(ctx *view.Context) {
	if st.sourceFirstOpen() {
		src := ctx.File.SourceLines(st.SrcFile)
		if len(src) == 0 {
			return
		}
		paneW := st.SourcePaneWidth(ctx)
		top := layout.ViewportTop(st.RenderedSrcTop, len(src), st.ViewportHeight(ctx), st.SourceRowHeight(ctx, paneW))
		st.SrcTop = top + 1
		return
	}
	if len(st.Inst) == 0 {
		return
	}
	st.Top = layout.ViewportTop(st.RenderedTop, len(st.Inst), st.ViewportHeight(ctx), st.RowHeight(ctx, st.RenderWidth(ctx)))
}

// Scroll moves the leading pane by delta rows. Scrolling up off the top of the
// decoded window re-decodes the span above it, so the wheel walks a large
// binary continuously instead of stopping at the window's edge.
func (st *State) Scroll(ctx *view.Context, env Env, delta int) {
	if delta == 0 {
		return
	}
	if st.sourceFirstOpen() {
		src := ctx.File.SourceLines(st.SrcFile)
		if len(src) == 0 {
			return
		}
		paneW := st.SourcePaneWidth(ctx)
		top := scrollTop(max(0, st.SrcTop-1), len(src), st.ViewportHeight(ctx), delta, st.SourceRowHeight(ctx, paneW))
		st.SrcTop = top + 1
		return
	}
	if len(st.Inst) == 0 {
		return
	}
	visible := st.ViewportHeight(ctx)
	rowHeight := st.RowHeight(ctx, st.RenderWidth(ctx))
	next := scrollTop(st.Top, len(st.Inst), visible, delta, rowHeight)
	if next == st.Top && delta < 0 && st.Top == 0 && st.PosLo > 0 {
		if st.loadWindowAboveForScroll(ctx, env, delta, visible) {
			return
		}
	}
	st.Top = next
}

// loadWindowAboveForScroll decodes the span above the window and re-anchors the
// scroll onto it, keeping the instruction that was on top in view.
func (st *State) loadWindowAboveForScroll(ctx *view.Context, env Env, delta, visible int) bool {
	if len(st.Inst) == 0 || st.PosLo <= 0 {
		return false
	}
	img := env.File.ExecImage()
	oldFirst := st.Inst[0].Addr
	curAddr := st.Inst[st.Cur].Addr
	if !st.LoadWindow(env, img.AddrAt(st.PosLo-1), env.Svc.MaxBytes()-env.Svc.OverlapBytes()) {
		return false
	}
	st.Cur = st.IndexAtOrAfter(curAddr)
	top := st.Cur + delta
	if idx, found := st.IndexForAddr(oldFirst); found {
		top = idx + delta
	}
	st.Top = layout.ViewportTop(top, len(st.Inst), visible, st.RowHeight(ctx, st.RenderWidth(ctx)))
	return true
}

func scrollTop(top, n, visible, delta int, rowHeight func(int) int) int {
	if n <= 0 {
		return 0
	}
	return layout.ViewportTop(top+delta, n, visible, rowHeight)
}

// Click moves the cursor to whatever the pointer is over: a source line when
// the click lands in the source-first pane (the left half), otherwise an
// instruction in the scroller.
func (st *State) Click(ctx *view.Context, env Env, x, bodyRow int) {
	if st.sourceFirstOpen() && x < ctx.Width/2 {
		if ln, ok := st.SourceLineAtRow(ctx, bodyRow); ok {
			st.SrcCur = ln
			st.SyncSourceAsm(env, st.ViewportHeight(ctx))
		}
		return
	}
	if i, ok := st.InstAtRow(ctx, bodyRow); ok {
		st.Cur = i
	}
}

// SourceLineAtRow maps a body row in the source-first pane to a 1-based source
// line, stripping the pane's title row.
func (st *State) SourceLineAtRow(ctx *view.Context, bodyRow int) (int, bool) {
	r := bodyRow - 1
	if r < 0 {
		return 0, false
	}
	paneW := st.SourcePaneWidth(ctx)
	src := ctx.File.SourceLines(st.SrcFile)
	top := st.SourceTextTop(ctx, paneW, st.ViewportHeight(ctx))
	idx, ok := layout.VisualItemAtRow(top, len(src), r, st.SourceRowHeight(ctx, paneW))
	return idx + 1, ok
}

// InstAtRow maps a click in the scroller to an instruction index. It replays
// RenderScroll's emit order: a symbol-start instruction is preceded by a
// "<name>:" label line (and possibly a section banner), so rows are not 1:1
// with instructions.
func (st *State) InstAtRow(ctx *view.Context, bodyRow int) (int, bool) {
	r := bodyRow - 1 // strip the sticky-symbol row
	if r < 0 {
		return 0, false
	}
	visible := st.ViewportHeight(ctx)
	rowHeight := st.RowHeight(ctx, st.RenderWidth(ctx))
	top := ctx.VisualTop(st.Cur, st.Top, len(st.Inst), visible, rowHeight)
	return layout.VisualItemAtRow(top, len(st.Inst), r, rowHeight)
}
