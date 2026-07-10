package ui

// Mouse support: the wheel scrolls the active view and a left click selects
// whatever the pointer is over —
// a row in the list views, a byte in the hex/raw dumps, or an instruction in
// the disassembly.

import (
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/rabarbra/exex/internal/ui/layout"
	"github.com/rabarbra/exex/internal/ui/modal"
	searchmodal "github.com/rabarbra/exex/internal/ui/modals/search"
	"github.com/rabarbra/exex/internal/ui/modals/textoverlay"
	"github.com/rabarbra/exex/internal/ui/views/hexraw"
)

// doubleClickWindow is how close two clicks must be (in time, on the same row)
// to count as a double-click.
const doubleClickWindow = 350 * time.Millisecond

const wheelQuietInterval = 120 * time.Millisecond

// wheelCoalesceInterval bounds how often accumulated wheel deltas are actually
// applied. A trackpad can emit hundreds of wheel events per gesture; without
// this, each one ran a full scroll+render synchronously and the backlog blocked
// all other input (clicks, keys) until it drained.
const wheelCoalesceInterval = 16 * time.Millisecond

// wheelScrollLines is how many lines one wheel notch moves a scrollable surface.
const wheelScrollLines = 3

// wheelTickMsg fires after wheelCoalesceInterval to apply any accumulated scroll.
type wheelTickMsg struct{}

func (m *Model) handleMouse(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
	ms := msg.Mouse()
	shift := ms.Mod&tea.ModShift != 0
	if shift && ms.Button == tea.MouseLeft {
		return m, nil
	}
	// An open overlay owns the mouse. Anything that reaches past this switch is
	// aimed at the view, so every overlay must either consume the event or
	// deliberately let it through — help and header used to be absent here
	// entirely, which let clicks switch tabs and the wheel scroll the view behind
	// an overlay that covered it.
	switch kind := m.activeModal(); kind {
	case modalNone:
		// Fall through to the view handling below.

	case modalSearch:
		// The search prompt is a thin popup, not a full overlay: clicks target its
		// mode switches, but the wheel deliberately still scrolls the view behind
		// it so results can be scanned without dismissing the prompt.
		if _, ok := msg.(tea.MouseClickMsg); ok && ms.Button == tea.MouseLeft {
			m.handleSearchPopupClick(ms.X, ms.Y)
			return m, nil
		}

	case modalHeader, modalHelp:
		// Scrollable text overlays with no selection: the wheel pages them (as the
		// arrow keys do), and everything else is swallowed.
		if _, ok := msg.(tea.MouseWheelMsg); ok {
			delta := wheelScrollLines
			if ms.Button == tea.MouseWheelUp {
				delta = -wheelScrollLines
			}
			// Both overlays are textoverlay.Scrollers; the offset is clamped where
			// they render, since the row count depends on the terminal size.
			m.scrollableOverlay(kind).Scroll(delta)
		}
		return m, nil

	default:
		// List/field overlays capture the mouse so it drives the modal, not the
		// view behind it: wheel moves the selection, a click selects an item, a
		// double-click activates it. Overlays with no list (findQuery) simply
		// swallow the event.
		if _, ok := msg.(tea.MouseWheelMsg); ok {
			switch ms.Button {
			case tea.MouseWheelUp:
				m.modalScrollSel(-1)
			case tea.MouseWheelDown:
				m.modalScrollSel(1)
			}
			return m, nil
		}
		if _, ok := msg.(tea.MouseClickMsg); ok && ms.Button == tea.MouseLeft {
			now := time.Now()
			isDouble := ms.Y == m.lastClickY && now.Sub(m.lastClickAt) < doubleClickWindow
			m.lastClickY, m.lastClickAt = ms.Y, now
			if m.modalClick(ms.Y) && isDouble {
				return m.modalActivate()
			}
		}
		return m, nil
	}

	if _, ok := msg.(tea.MouseWheelMsg); ok {
		switch ms.Button {
		case tea.MouseWheelUp:
			if m.mouseOverRightPane(ms.X) || (shift && m.rightPaneActive()) {
				m.scrollRightPane(-3)
				return m, nil
			}
			return m.enqueueWheel(-3)
		case tea.MouseWheelDown:
			if m.mouseOverRightPane(ms.X) || (shift && m.rightPaneActive()) {
				m.scrollRightPane(3)
				return m, nil
			}
			return m.enqueueWheel(3)
		}
	}
	if _, ok := msg.(tea.MouseClickMsg); ok && ms.Button == tea.MouseLeft {
		m.pendingWheel = 0 // a click halts any in-flight wheel momentum
		if ms.Y == 0 {     // the tab strip
			if md, ok := m.tabHitTest(ms.X); ok {
				return m, m.switchMode(md)
			}
			return m, nil
		}
		now := time.Now()
		isDouble := ms.Y == m.lastClickY && now.Sub(m.lastClickAt) < doubleClickWindow
		m.lastClickY = ms.Y
		m.lastClickAt = now

		before := m.activeCursorState()
		suppressDouble := m.handleClick(ms.X, ms.Y)
		if before != m.activeCursorState() {
			m.viewportDetached = false
			switch m.mode {
			case modeHex:
				m.byteViews.PinCurrentSectionStart(m.viewContextPtr(), hexraw.Hex)
			case modeRaw:
				m.byteViews.PinCurrentSectionStart(m.viewContextPtr(), hexraw.Raw)
			}
		}
		if isDouble && !suppressDouble {
			// Double-clicking a member loads it (the new model must propagate).
			if m.mode == modeInfo && m.isArchive() && m.infoMembers {
				return m.loadArchiveMember(m.memberSel)
			}
			m.handleDoubleClick()
		}
	}
	return m, nil
}

// scrollableOverlay returns the open text overlay's scroller. Only modalHeader
// and modalHelp reach it.
func (m *Model) scrollableOverlay(kind modalKind) *textoverlay.Scroller {
	if kind == modalHeader {
		return &m.header.Scroller
	}
	return &m.help.Scroller
}

func (m *Model) mouseOverRightPane(x int) bool {
	return m.rightPaneActive() && x >= m.width/2
}

// modalList returns the open modal's selection pointer, rendered scroll top, item
// count and whether the selection wraps (settings cycles). ok is false for
// overlays with no list — they still capture the mouse, they just ignore it.
func (m *Model) modalList() (sel *int, top, n int, wrap, ok bool) {
	switch m.activeModal() {
	case modalXref:
		return m.xref.List()
	case modalSyscall:
		return m.syscalls.List()
	case modalCPUFeat:
		return m.cpufeat.List()
	case modalGoto:
		return m.palette.List()
	case modalSettings:
		return m.settings.List()
	case modalJump:
		return m.jump.List()
	case modalFind:
		return m.find.List()
	case modalFindResults:
		return m.findResults.List()
	}
	return nil, 0, 0, false, false
}

// modalScrollSel moves the open modal's selection by d (wheel scrolling).
func (m *Model) modalScrollSel(d int) {
	sel, _, n, wrap, ok := m.modalList()
	if !ok || n == 0 {
		return
	}
	if wrap {
		*sel = (*sel + d%n + n) % n
	} else {
		*sel = layout.Clamp(*sel+d, 0, n-1)
	}
}

// modalClick maps a click to an item in the open modal's list and selects it,
// returning whether it hit one. It re-renders the modal to recompute its centred
// geometry and the list's starting row (modalListRow).
func (m *Model) modalClick(y int) bool {
	box := m.renderActiveModal()
	if box == "" {
		return false
	}
	mtop := (m.height - lipgloss.Height(box)) / 2
	// content row = y - modalTop - border(1) - padding-top(1), then minus where the
	// list begins within the modal content.
	listRow := (y - mtop - 2) - m.modalListRow
	if listRow < 0 {
		return false
	}
	// Extracted modals own their row→item mapping: settings interleaves group
	// headers and separators, so a rendered line does not correspond to a list
	// index the way the flat result lists do.
	switch m.activeModal() {
	case modalSettings:
		return m.settings.ClickRow(listRow)
	case modalCPUFeat:
		return m.cpufeat.ClickRow(listRow)
	case modalJump:
		return m.jump.ClickRow(listRow)
	case modalFind:
		return m.find.ClickRow(listRow)
	case modalGoto:
		return m.palette.ClickRow(listRow)
	case modalXref:
		return m.xref.ClickRow(listRow)
	case modalFindResults:
		return m.findResults.ClickRow(listRow)
	case modalSyscall:
		return m.syscalls.ClickRow(listRow)
	}
	sel, top, n, _, ok := m.modalList()
	if !ok {
		return false
	}
	return modal.ClickIndex(sel, top, n, listRow)
}

// modalActivate runs the open modal's Enter action (mouse double-click).
func (m *Model) modalActivate() (tea.Model, tea.Cmd) {
	switch m.activeModal() {
	case modalXref:
		return m, m.xref.Activate(m)
	case modalSyscall:
		return m, m.syscalls.Activate(m)
	case modalCPUFeat:
		return m, m.cpufeat.Activate(m)
	case modalGoto:
		m.palette.Activate(m)
		return m, nil
	case modalSettings:
		return m, m.settings.Activate(m)
	case modalJump:
		return m, m.jump.Activate(m)
	case modalFind:
		return m, m.find.Activate(m)
	case modalFindResults:
		return m, m.findResults.Activate(m)
	}
	return m, nil
}

func (m *Model) enqueueWheel(delta int) (tea.Model, tea.Cmd) {
	now := time.Now()
	if now.Before(m.wheelSuppressUntil) {
		m.wheelSuppressUntil = now.Add(wheelQuietInterval)
		m.viewDirty = false // dropped: nothing changed, reuse the last frame
		return m, nil
	}

	if !m.viewportDetached {
		m.captureViewportTop()
		m.viewportDetached = true
	}
	m.pendingWheel += delta
	// While a coalescing tick is in flight, just accumulate — this keeps a flood
	// of momentum events nearly free (no scroll, no re-render) so the message
	// queue (and any click/key behind it) drains immediately.
	if m.wheelTicking {
		m.viewDirty = false
		return m, nil
	}
	m.wheelTicking = true
	return m.flushWheel()
}

// flushWheel applies the accumulated scroll delta and schedules the next tick.
func (m *Model) flushWheel() (tea.Model, tea.Cmd) {
	if m.pendingWheel != 0 {
		d := m.pendingWheel
		m.pendingWheel = 0
		m.routeScroll(d)
	}
	return m, tea.Tick(wheelCoalesceInterval, func(time.Time) tea.Msg { return wheelTickMsg{} })
}

// handleWheelTick applies any scroll accumulated since the last tick, stopping
// the ticker once the burst has drained.
func (m *Model) handleWheelTick() (tea.Model, tea.Cmd) {
	if m.pendingWheel == 0 {
		m.wheelTicking = false
		return m, nil
	}
	return m.flushWheel()
}

// listGeometry captures everything the scroll, viewport-capture and click math
// need for a simple list-style view — one whose body is `headerRows` fixed rows
// (filter/header) followed by variable-height data rows. Centralising it here is
// the single source of truth for each view's geometry, which previously had to be
// kept in sync by hand across routeScroll, captureViewportTop and handleClick.
// The byte dumps, disasm and Info view don't fit this shape and stay bespoke.
type listGeometry struct {
	n           int           // number of items
	headerRows  int           // non-data rows above the data (filter/header)
	rowHeight   func(int) int // rendered height of item i
	cur         *int          // cursor field
	top         *int          // viewport-top field
	renderedTop int           // last rendered top (for re-attaching a detached viewport)
}

// visible is the number of body rows available for data at terminal height bodyH.
func (g listGeometry) visible(bodyH int) int { return max(1, bodyH-g.headerRows) }

// oneRow is the rowHeight function for views with fixed single-row items.
func oneRow(int) int { return 1 }

// listGeometryFor returns the geometry for the current list-style view, running
// any lazy load it needs first, or ok=false for views that aren't list-style.
func (m *Model) listGeometryFor() (listGeometry, bool) {
	switch m.mode {
	case modeInfo:
		if m.isArchive() && m.infoMembers { // the archive members list scrolls/clicks like any list
			return listGeometry{len(m.archiveMembers), 2, oneRow, &m.memberSel, &m.memberTop, m.memberTop}, true
		}
	case modeSections:
		return listGeometry{len(m.sections.Filtered), 2, m.sections.RowHeightFn(m.viewContext()), &m.sections.Cur, &m.sections.Top, m.sections.RenderedTop}, true
	case modeSymbols:
		return listGeometry{len(m.symbols.Rows), 2, m.symbols.RowHeightFn(m.viewContext()), &m.symbols.Cur, &m.symbols.Top, m.symbols.RenderedTop}, true
	case modeStrings:
		m.strs.Ensure(m.viewContext())
		if m.strs.Compact {
			return listGeometry{}, false // the · flow has its own line-based scroll
		}
		return listGeometry{len(m.strs.Filtered), 2, m.strs.RowHeightFn(m.viewContext()), &m.strs.Cur, &m.strs.Top, m.strs.RenderedTop}, true
	case modeSources:
		ctx := m.viewContext()
		m.sources.Ensure(ctx)
		return listGeometry{len(m.sources.Rows), 1, oneRow, &m.sources.Cur, &m.sources.Top, m.sources.RenderedTop}, true
	case modeRelocs:
		m.relocs.Recompute(m.viewContext())
		return listGeometry{len(m.relocs.Filtered), 2, oneRow, &m.relocs.Cur, &m.relocs.Top, m.relocs.Top}, true
	case modeLibs:
		if m.file.Info == nil {
			return listGeometry{}, false
		}
		ctx := m.viewContext()
		m.libs.BuildRows(ctx)
		return listGeometry{len(m.libs.Rows), m.libs.HeaderRows(ctx), m.libs.RowHeightFn(ctx), &m.libs.Cur, &m.libs.Top, m.libs.RenderedTop}, true
	}
	return listGeometry{}, false
}

func (m *Model) routeScroll(delta int) (tea.Model, tea.Cmd) {
	if delta == 0 {
		return m, nil
	}
	if g, ok := m.listGeometryFor(); ok {
		*g.top = scrollViewportTop(*g.top, g.n, g.visible(m.bodyHeight()), delta, g.rowHeight)
		return m, nil
	}
	switch m.mode {
	case modeStrings: // compact · flow (the table is handled via listGeometry above)
		m.strs.ScrollFlow(m.viewContext(), delta)
	case modeDisasm:
		m.scrollDisasmViewport(delta)
	case modeHex:
		m.byteViews.Scroll(m.viewContextPtr(), hexraw.Hex, delta)
	case modeRaw:
		m.byteViews.Scroll(m.viewContextPtr(), hexraw.Raw, delta)
	case modeInfo:
		m.info.Scroll(delta)
	}
	return m, nil
}

func (m *Model) captureViewportTop() {
	if g, ok := m.listGeometryFor(); ok {
		*g.top = layout.ViewportTop(g.renderedTop, g.n, g.visible(m.bodyHeight()), g.rowHeight)
		return
	}
	switch m.mode {
	case modeDisasm:
		m.captureDisasmViewportTop()
	case modeHex:
		m.byteViews.CaptureViewportTop(m.viewContextPtr(), hexraw.Hex)
	case modeRaw:
		m.byteViews.CaptureViewportTop(m.viewContextPtr(), hexraw.Raw)
	}
}

func (m *Model) captureDisasmViewportTop() {
	if m.sourceFirst && m.srcFile != "" {
		src := m.file.SourceLines(m.srcFile)
		if len(src) == 0 {
			return
		}
		contentH := max(1, m.bodyHeight()-1)
		top := layout.ViewportTop(m.renderedSrcTop, len(src), contentH, m.sourceRowHeight(m.sourcePaneWidth()))
		m.srcTop = top + 1
		return
	}
	if len(m.dasm.Inst) == 0 {
		return
	}
	visible := m.disasmViewportHeight()
	m.dasm.Top = layout.ViewportTop(m.dasm.RenderedTop, len(m.dasm.Inst), visible, m.disasmRowHeight(m.disasmRenderWidth()))
}

func (m *Model) scrollDisasmViewport(delta int) {
	if delta == 0 {
		return
	}
	if m.sourceFirst && m.srcFile != "" {
		src := m.file.SourceLines(m.srcFile)
		if len(src) == 0 {
			return
		}
		contentH := max(1, m.bodyHeight()-1)
		top := scrollViewportTop(max(0, m.srcTop-1), len(src), contentH, delta, m.sourceRowHeight(m.sourcePaneWidth()))
		m.srcTop = top + 1
		return
	}
	if len(m.dasm.Inst) == 0 {
		return
	}
	w := m.disasmRenderWidth()
	visible := m.disasmViewportHeight()
	rowHeight := m.disasmRowHeight(w)
	next := scrollViewportTop(m.dasm.Top, len(m.dasm.Inst), visible, delta, rowHeight)
	if next == m.dasm.Top && delta < 0 && m.dasm.Top == 0 && m.dasm.PosLo > 0 {
		if m.loadDisasmWindowAboveForScroll(delta, visible) {
			return
		}
	}
	m.dasm.Top = next
}

func (m *Model) loadDisasmWindowAboveForScroll(delta, visible int) bool {
	if len(m.dasm.Inst) == 0 || m.dasm.PosLo <= 0 {
		return false
	}
	img := m.file.ExecImage()
	oldFirst := m.dasm.Inst[0].Addr
	curAddr := m.dasm.Inst[m.dasm.Cur].Addr
	if !m.loadDisasmWindow(img.AddrAt(m.dasm.PosLo-1), m.disasmMaxBytes-m.disasmOverlapBytes()) {
		return false
	}
	m.dasm.Cur = m.dasm.IndexAtOrAfter(curAddr)
	top := m.dasm.Cur + delta
	if idx, found := m.dasm.IndexForAddr(oldFirst); found {
		top = idx + delta
	}
	w := m.disasmRenderWidth()
	rowHeight := func(i int) int { return m.disasmInstVisualHeight(i, w) }
	m.dasm.Top = layout.ViewportTop(top, len(m.dasm.Inst), visible, rowHeight)
	return true
}

func scrollViewportTop(top, n, visible, delta int, rowHeight func(int) int) int {
	if n <= 0 {
		return 0
	}
	return layout.ViewportTop(top+delta, n, visible, rowHeight)
}

// handleSearchPopupClick toggles a switch in the search prompt's strip. The
// overlay is re-rendered to recover its centred geometry, then the click's
// content column is mapped through the same Switches() the render used.
func (m *Model) handleSearchPopupClick(x, y int) {
	box := m.search.Render(m.modalContext(), m)
	left := (m.width - lipgloss.Width(box)) / 2
	top := (m.height - lipgloss.Height(box)) / 2
	// Translate to content coordinates inside the frame's border (1) + padding
	// (1,2): x offset 3, y offset 2.
	cx := x - (left + 3)
	cy := y - (top + 2)
	if cy != searchmodal.SwitchLine {
		return
	}
	m.search.ClickAt(m, cx)
}

// handleDoubleClick activates the item under a double-click: follow the address
// in the disasm view, or perform the view's Enter action (open / jump) in the
// list-style views. The preceding single click already moved the cursor onto the
// clicked row, so this just opens whatever is now selected.
func (m *Model) handleDoubleClick() {
	switch m.mode {
	case modeDisasm:
		m.followCurrentDisasm()
	case modeSections, modeSymbols, modeStrings, modeSources, modeLibs, modeRelocs:
		m.dispatchViewKey(nil, "enter")
	}
}

// followCurrentDisasm follows the first in-file address on the current disasm
// line — the mouse equivalent of pressing Enter in the disasm view.
func (m *Model) followCurrentDisasm() {
	if len(m.dasm.Inst) == 0 {
		return
	}
	inst := m.dasm.Inst[m.dasm.Cur]
	if target, ok := m.followableAddr(inst.Text); ok {
		m.loadDisasmAt(target)
	} else {
		m.setStatus("no in-file address to follow", true)
	}
}

// handleClick selects the item under the pointer. y == 0 is the tab row; the
// body starts at y == 1, and the footer occupies the final row.
func (m *Model) handleClick(x, y int) bool {
	bodyRow := y - 1 // strip the tab row
	if bodyRow < 0 || y >= m.height-1 {
		return false
	}
	// The Symbols status line (first body row) carries clickable toggle buttons.
	if m.mode == modeSymbols && bodyRow == 0 && !m.symbols.Filter.Focused() {
		if m.symbols.ClickFacet(m.viewContext(), m, x) {
			return true
		}
	}
	if m.isTableHeaderRow(bodyRow) {
		m.handleSortableHeaderClick(x, bodyRow)
		return true
	}
	// List-style views (sections/symbols/strings/sources/libs) all map a click the
	// same way: find the rendered top, then the item at (bodyRow - headerRows).
	if g, ok := m.listGeometryFor(); ok {
		top := m.visualTopForView(*g.cur, *g.top, g.n, g.visible(m.bodyHeight()), g.rowHeight)
		if idx, ok := layout.VisualItemAtRow(top, g.n, bodyRow-g.headerRows, g.rowHeight); ok {
			*g.cur = idx
			// Clicking a tree group toggles it (collapse/expand the lines below).
			switch {
			case m.mode == modeSymbols && idx < len(m.symbols.Rows) && m.symbols.Rows[idx].Node.Leaf < 0:
				m.symbols.ToggleNode()
			case m.mode == modeSources && idx < len(m.sources.Rows) && m.sources.Rows[idx].Node.Leaf < 0:
				m.sources.ToggleNode(m.viewContext())
			case m.mode == modeLibs && idx < len(m.libs.Rows) && m.libs.Rows[idx].Node.Leaf < 0:
				m.libs.ToggleNode(m.viewContext())
			}
		}
		return false
	}
	switch m.mode {
	case modeStrings: // compact · flow: map the click to the string under it
		if idx, ok := m.strs.FlowStringAt(m.viewContext(), m.strs.RenderedTop, bodyRow-1, x); ok {
			m.strs.Cur = idx
		}
	case modeHex:
		m.byteViews.Click(m.viewContextPtr(), hexraw.Hex, x, bodyRow)
	case modeRaw:
		m.byteViews.Click(m.viewContextPtr(), hexraw.Raw, x, bodyRow)
	case modeDisasm:
		if m.sourceFirst && m.srcFile != "" && m.clickInSourcePane(x) {
			if ln, ok := m.sourceLineAtBodyRow(bodyRow, m.sourcePaneWidth()); ok {
				m.srcCur = ln
				m.syncSourceAsm()
			}
		} else if i, ok := m.instAtBodyRow(bodyRow); ok {
			m.dasm.Cur = i
		}
	}
	return false
}

func (m *Model) clickInSourcePane(x int) bool {
	// In the disasm view's source-first split, the source pane is on the left.
	return x < m.width/2
}

func (m *Model) sourcePaneWidth() int {
	if m.width <= 1 {
		return m.width
	}
	return m.width / 2
}

func (m *Model) sourceLineAtBodyRow(bodyRow, paneW int) (int, bool) {
	r := bodyRow - 1 // strip source header row
	if r < 0 {
		return 0, false
	}
	src := m.file.SourceLines(m.srcFile)
	contentH := max(1, m.bodyHeight()-1)
	idx, ok := layout.VisualItemAtRow(m.sourceTextTop(paneW, contentH), len(src), r, m.sourceRowHeight(paneW))
	return idx + 1, ok
}

// instAtBodyRow maps a click in the disasm scroller to an instruction index.
// It replays renderDisasmScroll's emit order: a symbol-start instruction is
// preceded by a "<name>:" label line, so rows aren't 1:1 with instructions.
func (m *Model) instAtBodyRow(bodyRow int) (int, bool) {
	r := bodyRow - 1 // strip the sticky-symbol row
	if r < 0 {
		return 0, false
	}
	visible := max(1, m.bodyHeight()-1)
	rowHeight := m.disasmRowHeight(m.disasmRenderWidth())
	top := m.visualTopForView(m.dasm.Cur, m.dasm.Top, len(m.dasm.Inst), visible, rowHeight)
	return layout.VisualItemAtRow(top, len(m.dasm.Inst), r, rowHeight)
}
