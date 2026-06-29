package ui

// Mouse support: the wheel scrolls the active view and a left click selects
// whatever the pointer is over —
// a row in the list views, a byte in the hex/raw dumps, or an instruction in
// the disassembly.

import (
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
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

// wheelTickMsg fires after wheelCoalesceInterval to apply any accumulated scroll.
type wheelTickMsg struct{}

func (m *Model) handleMouse(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
	ms := msg.Mouse()
	shift := ms.Mod&tea.ModShift != 0
	if shift && ms.Button == tea.MouseLeft {
		return m, nil
	}
	if _, ok := msg.(tea.MouseClickMsg); ok && m.searchActive && ms.Button == tea.MouseLeft {
		m.handleSearchPopupClick(ms.X, ms.Y)
		return m, nil
	}
	// A list/field overlay modal (xref, goto, settings) captures the mouse so it
	// drives the modal, not the view behind it: wheel moves the selection, a click
	// selects an item, a double-click activates it.
	if m.modalActive() {
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
			if m.modalClick(ms.X, ms.Y) && isDouble {
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
			m.pinCurrentByteSectionStart()
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

func (m *Model) mouseOverRightPane(x int) bool {
	return m.rightPaneActive() && x >= m.width/2
}

// modalActive reports whether a list/field overlay modal (not the search prompt,
// which handles its own clicks) is open.
func (m *Model) modalActive() bool {
	return m.xrefActive || m.syscallActive || m.cpufeatActive || m.gotoActive || m.settingsActive
}

// modalList returns the open modal's selection pointer, rendered scroll top, item
// count and whether the selection wraps (settings cycles).
func (m *Model) modalList() (sel *int, top, n int, wrap, ok bool) {
	switch {
	case m.xrefActive:
		return &m.xrefSel, m.xrefTop, len(m.xrefShown), false, true
	case m.syscallActive:
		return &m.syscallSel, m.syscallTop, len(m.syscallShown), false, true
	case m.cpufeatActive:
		return &m.cpufeatSel, m.cpufeatTop, len(m.cpufeatFeats), false, true
	case m.gotoActive:
		return &m.gotoSel, m.gotoTop, len(m.gotoResults), false, true
	case m.settingsActive:
		return &m.settingsCur, m.settingsTop, settingsFieldCount, true, true
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
		*sel = clamp(*sel+d, 0, n-1)
	}
}

// modalClick maps a click to an item in the open modal's list and selects it,
// returning whether it hit one. It re-renders the modal to recompute its centred
// geometry and the list's starting row (modalListRow).
func (m *Model) modalClick(x, y int) bool {
	var modal string
	switch {
	case m.xrefActive:
		modal = m.renderXrefModal()
	case m.syscallActive:
		modal = m.renderSyscallModal()
	case m.cpufeatActive:
		modal = m.renderCPUFeatModal()
	case m.gotoActive:
		modal = m.renderGotoModal()
	case m.settingsActive:
		modal = m.renderSettingsModal()
	default:
		return false
	}
	mtop := (m.height - lipgloss.Height(modal)) / 2
	// content row = y - modalTop - border(1) - padding-top(1), then minus where the
	// list begins within the modal content.
	listRow := (y - mtop - 2) - m.modalListRow
	if listRow < 0 {
		return false
	}
	sel, top, n, _, ok := m.modalList()
	if !ok {
		return false
	}
	if idx := top + listRow; idx >= 0 && idx < n {
		*sel = idx
		return true
	}
	return false
}

// modalActivate runs the open modal's Enter action (mouse double-click).
func (m *Model) modalActivate() (tea.Model, tea.Cmd) {
	switch {
	case m.xrefActive:
		return m.xrefJump()
	case m.syscallActive:
		return m.syscallJump()
	case m.cpufeatActive:
		return m.cpufeatJump()
	case m.gotoActive:
		m.activateGoto()
		m.closeGoto()
		return m, nil
	case m.settingsActive:
		m.cycleSetting(1)
		return m, nil
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
		return listGeometry{len(m.sectionsFiltered), 2, m.sectionRowHeight, &m.sectionsCur, &m.sectionsTop, m.renderedSectionsTop}, true
	case modeSymbols:
		return listGeometry{len(m.symbolsRows), 2, m.symbolRowHeight, &m.symbolsCur, &m.symbolsTop, m.renderedSymbolsTop}, true
	case modeStrings:
		m.ensureStrings()
		if m.stringsCompact {
			return listGeometry{}, false // the · flow has its own line-based scroll
		}
		return listGeometry{len(m.stringsFiltered), 2, m.stringRowHeight, &m.stringsCur, &m.stringsTop, m.renderedStringsTop}, true
	case modeSources:
		m.ensureSources()
		return listGeometry{len(m.sourcesRows), 1, oneRow, &m.sourcesCur, &m.sourcesTop, m.renderedSourcesTop}, true
	case modeRelocs:
		m.recomputeRelocs()
		return listGeometry{len(m.relocFiltered), 2, oneRow, &m.relocCur, &m.relocTop, m.relocTop}, true
	case modeLibs:
		if m.file.Info == nil {
			return listGeometry{}, false
		}
		m.buildLibRows()
		return listGeometry{len(m.libsRows), m.libsHeaderRows(), m.libRowHeight, &m.libsCur, &m.libsTop, m.renderedLibsTop}, true
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
		m.scrollStringsFlow(delta)
	case modeDisasm:
		m.scrollDisasmViewport(delta)
	case modeHex:
		m.ensureHex()
		m.clearByteSectionPin(modeHex)
		m.hexTop = m.scrollByteViewportTop(modeHex, m.hexImg, m.hexTop, max(1, m.bodyHeight()-1), delta, m.hexImg.AddrAt)
	case modeRaw:
		m.ensureRaw()
		m.clearByteSectionPin(modeRaw)
		m.rawTop = m.scrollByteViewportTop(modeRaw, rawBytes(m.rawData), m.rawTop, max(1, m.bodyHeight()-1), delta, identityAddr)
	case modeInfo:
		if delta < 0 {
			m.headerVP.ScrollUp(-delta)
		} else {
			m.headerVP.ScrollDown(delta)
		}
	}
	return m, nil
}

func (m *Model) captureViewportTop() {
	if g, ok := m.listGeometryFor(); ok {
		*g.top = viewportTop(g.renderedTop, g.n, g.visible(m.bodyHeight()), g.rowHeight)
		return
	}
	switch m.mode {
	case modeDisasm:
		m.captureDisasmViewportTop()
	case modeHex:
		m.ensureHex()
		m.hexTop = m.scrollByteViewportTop(modeHex, m.hexImg, m.renderedHexTop, max(1, m.bodyHeight()-1), 0, m.hexImg.AddrAt)
	case modeRaw:
		m.ensureRaw()
		m.rawTop = m.scrollByteViewportTop(modeRaw, rawBytes(m.rawData), m.renderedRawTop, max(1, m.bodyHeight()-1), 0, identityAddr)
	}
}

func (m *Model) captureDisasmViewportTop() {
	if m.sourceFirst && m.srcFile != "" {
		src := m.file.SourceLines(m.srcFile)
		if len(src) == 0 {
			return
		}
		contentH := max(1, m.bodyHeight()-1)
		top := viewportTop(m.renderedSrcTop, len(src), contentH, m.sourceRowHeight(m.sourcePaneWidth()))
		m.srcTop = top + 1
		return
	}
	if len(m.disasmInst) == 0 {
		return
	}
	visible := m.disasmViewportHeight()
	m.disasmTop = viewportTop(m.renderedDisasmTop, len(m.disasmInst), visible, m.disasmRowHeight(m.disasmRenderWidth()))
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
	if len(m.disasmInst) == 0 {
		return
	}
	w := m.disasmRenderWidth()
	visible := m.disasmViewportHeight()
	rowHeight := m.disasmRowHeight(w)
	next := scrollViewportTop(m.disasmTop, len(m.disasmInst), visible, delta, rowHeight)
	if next == m.disasmTop && delta < 0 && m.disasmTop == 0 && m.disasmPosLo > 0 {
		if m.loadDisasmWindowAboveForScroll(delta, visible) {
			return
		}
	}
	m.disasmTop = next
}

func (m *Model) loadDisasmWindowAboveForScroll(delta, visible int) bool {
	if len(m.disasmInst) == 0 || m.disasmPosLo <= 0 {
		return false
	}
	img := m.file.ExecImage()
	oldFirst := m.disasmInst[0].Addr
	curAddr := m.disasmInst[m.disasmCur].Addr
	if !m.loadDisasmWindow(img.AddrAt(m.disasmPosLo-1), m.disasmMaxBytes-m.disasmOverlapBytes()) {
		return false
	}
	m.disasmCur = m.instIndexAtOrAfterAddr(curAddr)
	top := m.disasmCur + delta
	if idx, found := m.instIndexForAddr(oldFirst); found {
		top = idx + delta
	}
	w := m.disasmRenderWidth()
	rowHeight := func(i int) int { return m.disasmInstVisualHeight(i, w) }
	m.disasmTop = viewportTop(top, len(m.disasmInst), visible, rowHeight)
	return true
}

func scrollViewportTop(top, n, visible, delta int, rowHeight func(int) int) int {
	if n <= 0 {
		return 0
	}
	return viewportTop(top+delta, n, visible, rowHeight)
}

// scrollByteViewportTop scrolls a byte view's top by delta rows, stepping along
// the address-aware row grid (see view_hex.go) and clamping so the last screen
// stays full. delta == 0 just normalizes top to a valid row-start.
func (m *Model) scrollByteViewportTop(md mode, data byteSource, top, visibleRows, delta int, addrAt func(pos int) uint64) int {
	n := data.Len()
	if n <= 0 {
		return 0
	}
	top = m.hexRowTop(md, top, addrAt)
	for ; delta > 0 && top < n; delta-- {
		next := m.hexRowSpan(md, data, top, addrAt).end
		if next >= n || next <= top {
			break
		}
		top = next
	}
	for ; delta < 0 && top > 0; delta++ {
		top = m.hexPrevRowTop(md, top, addrAt)
	}
	if maxTop := m.hexMaxTop(md, data, visibleRows, addrAt); top > maxTop {
		top = maxTop
	}
	return top
}

func (m *Model) handleSearchPopupClick(x, y int) {
	modal := m.renderSearchModal()
	mw := lipgloss.Width(modal)
	mh := lipgloss.Height(modal)
	left := (m.width - mw) / 2
	top := (m.height - mh) / 2
	// Translate to content coordinates inside modalStyle's RoundedBorder (1) +
	// Padding(1,2): x offset 3, y offset 2.
	cx := x - (left + 3)
	cy := y - (top + 2)
	if cy != searchSwitchLine || cx < 0 {
		return
	}
	pos := 0
	sepW := lipgloss.Width(searchSwitchSep)
	for _, sw := range m.searchSwitches() {
		w := lipgloss.Width(sw.label())
		if cx >= pos && cx < pos+w {
			sw.toggle()
			return
		}
		pos += w + sepW
	}
}

// handleDoubleClick activates the item under a double-click: follow the address
// in the disasm view, or perform the view's Enter action (open / jump) in the
// list-style views. The preceding single click already moved the cursor onto the
// clicked row, so this just opens whatever is now selected.
func (m *Model) handleDoubleClick() {
	switch m.mode {
	case modeDisasm:
		m.followCurrentDisasm()
	case modeSections, modeSymbols, modeStrings, modeSources, modeLibs:
		m.dispatchViewKey(nil, "enter")
	}
}

// followCurrentDisasm follows the first in-file address on the current disasm
// line — the mouse equivalent of pressing Enter in the disasm view.
func (m *Model) followCurrentDisasm() {
	if len(m.disasmInst) == 0 {
		return
	}
	inst := m.disasmInst[m.disasmCur]
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
	if m.mode == modeSymbols && bodyRow == 0 && !m.symbolsFilter.Focused() {
		if m.clickSymbolFacet(x) {
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
		if idx, ok := visualItemAtRow(top, g.n, bodyRow-g.headerRows, g.rowHeight); ok {
			*g.cur = idx
			// Clicking a tree group toggles it (collapse/expand the lines below).
			switch {
			case m.mode == modeSymbols && idx < len(m.symbolsRows) && m.symbolsRows[idx].node.leaf < 0:
				m.toggleSymbolNode()
			case m.mode == modeSources && idx < len(m.sourcesRows) && m.sourcesRows[idx].node.leaf < 0:
				m.toggleSourceNode()
			case m.mode == modeLibs && idx < len(m.libsRows) && m.libsRows[idx].node.leaf < 0:
				m.toggleLibNode()
			}
		}
		return false
	}
	switch m.mode {
	case modeStrings: // compact · flow: map the click to the string under it
		if idx, ok := m.flowStringAt(m.renderedStringsTop, bodyRow-1, x); ok {
			m.stringsCur = idx
		}
	case modeHex:
		m.ensureHex()
		top := m.hexVisibleTop(modeHex, m.hexCur, m.hexTop, max(1, m.bodyHeight()-1), m.hexImg.AddrAt)
		if m.viewportDetached {
			top = m.scrollByteViewportTop(modeHex, m.hexImg, m.hexTop, max(1, m.bodyHeight()-1), 0, m.hexImg.AddrAt)
		}
		m.hexCur = m.clickByte(modeHex, m.hexImg, top, m.hexCur, x, bodyRow, m.hexImg.AddrAt)
	case modeRaw:
		m.ensureRaw()
		top := m.hexVisibleTop(modeRaw, m.rawCur, m.rawTop, max(1, m.bodyHeight()-1), identityAddr)
		if m.viewportDetached {
			top = m.scrollByteViewportTop(modeRaw, rawBytes(m.rawData), m.rawTop, max(1, m.bodyHeight()-1), 0, identityAddr)
		}
		m.rawCur = m.clickByte(modeRaw, rawBytes(m.rawData), top, m.rawCur, x, bodyRow, identityAddr)
	case modeDisasm:
		if m.sourceFirst && m.srcFile != "" && m.clickInSourcePane(x) {
			if ln, ok := m.sourceLineAtBodyRow(bodyRow, m.sourcePaneWidth()); ok {
				m.srcCur = ln
				m.syncSourceAsm()
			}
		} else if i, ok := m.instAtBodyRow(bodyRow); ok {
			m.disasmCur = i
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
	idx, ok := visualItemAtRow(m.sourceTextTop(paneW, contentH), len(src), r, m.sourceRowHeight(paneW))
	return idx + 1, ok
}

// clickByte maps a click at (x, bodyRow) onto a byte position in a hex dump.
// Body layout: row 0 is the banner, byte rows follow with bytesPerHexRow bytes
// each. The column→byte mapping lives in view_hex.go so it stays in sync with
// the renderer.
func (m *Model) clickByte(md mode, data byteSource, top, cur, x, bodyRow int, addrAt func(pos int) uint64) int {
	r := bodyRow - 1 // strip the banner row
	if r < 0 {
		return cur
	}
	emitted := 0
	prevSec := ""
	if top >= bytesPerHexRow {
		prevSec = m.hexSectionName(md, top-bytesPerHexRow, addrAt)
	}
	for rowStart := top; rowStart < data.Len(); {
		if sec := m.hexSectionName(md, rowStart, addrAt); sec != "" && sec != prevSec {
			if emitted == r {
				return cur // clicked a section-separator row
			}
			emitted++
			prevSec = sec
		} else {
			prevSec = sec
		}
		if emitted == r {
			span := m.hexRowSpan(md, data, rowStart, addrAt)
			slot := hexColumnToByte(m.file.AddrHexWidth(), x)
			if slot < span.lead {
				return cur
			}
			pos := rowStart + slot - span.lead
			if pos < rowStart || pos >= span.end {
				return cur
			}
			if pos >= data.Len() {
				pos = data.Len() - 1
			}
			return pos
		}
		emitted++
		rowStart = m.hexRowSpan(md, data, rowStart, addrAt).end
	}
	return cur
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
	top := m.visualTopForView(m.disasmCur, m.disasmTop, len(m.disasmInst), visible, rowHeight)
	return visualItemAtRow(top, len(m.disasmInst), r, rowHeight)
}
