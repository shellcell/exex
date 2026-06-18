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
		isDouble := m.mode == modeDisasm && ms.Y == m.lastClickY &&
			now.Sub(m.lastClickAt) < doubleClickWindow
		m.lastClickY = ms.Y
		m.lastClickAt = now

		before := m.activeCursorState()
		m.handleClick(ms.X, ms.Y)
		if before != m.activeCursorState() {
			m.viewportDetached = false
			m.pinCurrentByteSectionStart()
		}
		if isDouble {
			m.followCurrentDisasm()
		}
	}
	return m, nil
}

func (m *Model) mouseOverRightPane(x int) bool {
	return m.rightPaneActive() && x >= m.width/2
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

func (m *Model) routeScroll(delta int) (tea.Model, tea.Cmd) {
	if delta == 0 {
		return m, nil
	}
	switch m.mode {
	case modeSections:
		visible := max(1, m.bodyHeight()-2)
		m.sectionsTop = scrollViewportTop(m.sectionsTop, len(m.sectionsFiltered), visible, delta, m.sectionRowHeight)
	case modeSymbols:
		visible := max(1, m.bodyHeight()-2)
		m.symbolsTop = scrollViewportTop(m.symbolsTop, len(m.symbolsFiltered), visible, delta, m.symbolRowHeight)
	case modeDisasm:
		m.scrollDisasmViewport(delta)
	case modeHex:
		m.ensureHex()
		m.clearByteSectionPin(modeHex)
		m.hexTop = m.scrollByteViewportTop(modeHex, m.hexImg.Data, m.hexTop, max(1, m.bodyHeight()-1), delta, m.hexImg.AddrAt)
	case modeRaw:
		m.ensureRaw()
		m.clearByteSectionPin(modeRaw)
		m.rawTop = m.scrollByteViewportTop(modeRaw, m.rawData, m.rawTop, max(1, m.bodyHeight()-1), delta, identityAddr)
	case modeStrings:
		m.ensureStrings()
		visible := max(1, m.bodyHeight()-1)
		m.stringsTop = scrollViewportTop(m.stringsTop, len(m.stringsList), visible, delta, m.stringRowHeight)
	case modeSources:
		m.ensureSources()
		visible := max(1, m.bodyHeight()-1)
		m.sourcesTop = scrollViewportTop(m.sourcesTop, len(m.sourcesFiltered), visible, delta, func(int) int { return 1 })
	case modeLibs:
		if m.file.Info != nil {
			visible := max(1, m.bodyHeight()-m.libsHeaderRows())
			m.libsTop = scrollViewportTop(m.libsTop, len(m.file.Info.DynamicLibs), visible, delta, m.libRowHeight)
		}
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
	switch m.mode {
	case modeSections:
		visible := max(1, m.bodyHeight()-2)
		m.sectionsTop = viewportTop(m.renderedSectionsTop, len(m.sectionsFiltered), visible, m.sectionRowHeight)
	case modeSymbols:
		visible := max(1, m.bodyHeight()-2)
		m.symbolsTop = viewportTop(m.renderedSymbolsTop, len(m.symbolsFiltered), visible, m.symbolRowHeight)
	case modeDisasm:
		m.captureDisasmViewportTop()
	case modeHex:
		m.ensureHex()
		visible := max(1, m.bodyHeight()-1)
		m.hexTop = m.scrollByteViewportTop(modeHex, m.hexImg.Data, m.renderedHexTop, visible, 0, m.hexImg.AddrAt)
	case modeRaw:
		m.ensureRaw()
		visible := max(1, m.bodyHeight()-1)
		m.rawTop = m.scrollByteViewportTop(modeRaw, m.rawData, m.renderedRawTop, visible, 0, identityAddr)
	case modeStrings:
		m.ensureStrings()
		visible := max(1, m.bodyHeight()-1)
		m.stringsTop = viewportTop(m.renderedStringsTop, len(m.stringsList), visible, m.stringRowHeight)
	case modeSources:
		m.ensureSources()
		visible := max(1, m.bodyHeight()-1)
		m.sourcesTop = viewportTop(m.renderedSourcesTop, len(m.sourcesFiltered), visible, func(int) int { return 1 })
	case modeLibs:
		if m.file.Info != nil {
			visible := max(1, m.bodyHeight()-m.libsHeaderRows())
			m.libsTop = viewportTop(m.renderedLibsTop, len(m.file.Info.DynamicLibs), visible, m.libRowHeight)
		}
	}
}

func (m *Model) captureDisasmViewportTop() {
	if m.sourceFirst && m.srcFile != "" {
		src := m.file.SourceLines(m.srcFile)
		if len(src) == 0 {
			return
		}
		contentH := max(1, m.bodyHeight()-1)
		paneW := m.sourcePaneWidth()
		rowHeight := func(i int) int {
			ln := i + 1
			h := m.sourceLineHeight(ln, paneW)
			if ln == m.srcCur && len(m.sourceLineColumns(m.srcFile, ln)) > 0 {
				h++
			}
			return h
		}
		top := viewportTop(m.renderedSrcTop, len(src), contentH, rowHeight)
		m.srcTop = top + 1
		return
	}
	if len(m.disasmInst) == 0 {
		return
	}
	w := m.disasmRenderWidth()
	visible := m.disasmViewportHeight()
	rowHeight := func(i int) int { return m.disasmInstVisualHeight(i, w) }
	m.disasmTop = viewportTop(m.renderedDisasmTop, len(m.disasmInst), visible, rowHeight)
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
		paneW := m.sourcePaneWidth()
		rowHeight := func(i int) int {
			ln := i + 1
			h := m.sourceLineHeight(ln, paneW)
			if ln == m.srcCur && len(m.sourceLineColumns(m.srcFile, ln)) > 0 {
				h++
			}
			return h
		}
		top := scrollViewportTop(max(0, m.srcTop-1), len(src), contentH, delta, rowHeight)
		m.srcTop = top + 1
		return
	}
	if len(m.disasmInst) == 0 {
		return
	}
	w := m.disasmRenderWidth()
	visible := m.disasmViewportHeight()
	rowHeight := func(i int) int { return m.disasmInstVisualHeight(i, w) }
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
func (m *Model) scrollByteViewportTop(md mode, data []byte, top, visibleRows, delta int, addrAt func(pos int) uint64) int {
	n := len(data)
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
		w := lipgloss.Width(sw.label)
		if cx >= pos && cx < pos+w {
			sw.toggle()
			return
		}
		pos += w + sepW
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
func (m *Model) handleClick(x, y int) {
	bodyRow := y - 1 // strip the tab row
	if bodyRow < 0 || y >= m.height-1 {
		return
	}
	switch m.mode {
	case modeSections:
		// Body layout: row 0 filter, row 1 header, data follows.
		visible := max(1, m.bodyHeight()-2)
		top := m.visualTopForView(m.sectionsCur, m.sectionsTop, len(m.sectionsFiltered), visible, m.sectionRowHeight)
		if idx, ok := visualItemAtRow(top, len(m.sectionsFiltered), bodyRow-2, m.sectionRowHeight); ok {
			m.sectionsCur = idx
		}
	case modeSymbols:
		// Body layout: row 0 filter, row 1 header, data follows.
		visible := max(1, m.bodyHeight()-2)
		top := m.visualTopForView(m.symbolsCur, m.symbolsTop, len(m.symbolsFiltered), visible, m.symbolRowHeight)
		if idx, ok := visualItemAtRow(top, len(m.symbolsFiltered), bodyRow-2, m.symbolRowHeight); ok {
			m.symbolsCur = idx
		}
	case modeHex:
		m.ensureHex()
		top := m.hexVisibleTop(modeHex, m.hexCur, m.hexTop, max(1, m.bodyHeight()-1), m.hexImg.AddrAt)
		if m.viewportDetached {
			top = m.scrollByteViewportTop(modeHex, m.hexImg.Data, m.hexTop, max(1, m.bodyHeight()-1), 0, m.hexImg.AddrAt)
		}
		m.hexCur = m.clickByte(modeHex, m.hexImg.Data, top, m.hexCur, x, bodyRow, m.hexImg.AddrAt)
	case modeRaw:
		m.ensureRaw()
		top := m.hexVisibleTop(modeRaw, m.rawCur, m.rawTop, max(1, m.bodyHeight()-1), identityAddr)
		if m.viewportDetached {
			top = m.scrollByteViewportTop(modeRaw, m.rawData, m.rawTop, max(1, m.bodyHeight()-1), 0, identityAddr)
		}
		m.rawCur = m.clickByte(modeRaw, m.rawData, top, m.rawCur, x, bodyRow, identityAddr)
	case modeStrings:
		// Body layout: row 0 is the column header, data follows.
		visible := max(1, m.bodyHeight()-1)
		top := m.visualTopForView(m.stringsCur, m.stringsTop, len(m.stringsList), visible, m.stringRowHeight)
		if idx, ok := visualItemAtRow(top, len(m.stringsList), bodyRow-1, m.stringRowHeight); ok {
			m.stringsCur = idx
		}
	case modeSources:
		// File list only: row 0 is the filter, files follow.
		visible := max(1, m.bodyHeight()-1)
		top := m.visualTopForView(m.sourcesCur, m.sourcesTop, len(m.sourcesFiltered), visible, func(int) int { return 1 })
		if idx := top + bodyRow - 1; idx >= 0 && idx < len(m.sourcesFiltered) {
			m.sourcesCur = idx
		}
	case modeDisasm:
		if m.sourceFirst && m.srcFile != "" && m.clickInSourcePane(x) {
			if ln, ok := m.sourceLineAtBodyRow(bodyRow, m.sourcePaneWidth()); ok {
				m.srcCur = ln
				m.syncSourceAsm()
			}
		} else if i, ok := m.instAtBodyRow(bodyRow); ok {
			m.disasmCur = i
		}
	case modeLibs:
		headerRows := m.libsHeaderRows()
		if m.file.Info != nil {
			visible := max(1, m.bodyHeight()-headerRows)
			top := m.visualTopForView(m.libsCur, m.libsTop, len(m.file.Info.DynamicLibs), visible, m.libRowHeight)
			if idx, ok := visualItemAtRow(top, len(m.file.Info.DynamicLibs), bodyRow-headerRows, m.libRowHeight); ok {
				m.libsCur = idx
			}
		}
	}
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
	rowHeight := func(i int) int {
		ln := i + 1
		h := m.sourceLineHeight(ln, paneW)
		if ln == m.srcCur && len(m.sourceLineColumns(m.srcFile, ln)) > 0 {
			h++
		}
		return h
	}
	idx, ok := visualItemAtRow(m.sourceTextTop(paneW, contentH), len(src), r, rowHeight)
	return idx + 1, ok
}

// clickByte maps a click at (x, bodyRow) onto a byte position in a hex dump.
// Body layout: row 0 is the banner, byte rows follow with bytesPerHexRow bytes
// each. The column→byte mapping lives in view_hex.go so it stays in sync with
// the renderer.
func (m *Model) clickByte(md mode, data []byte, top, cur, x, bodyRow int, addrAt func(pos int) uint64) int {
	r := bodyRow - 1 // strip the banner row
	if r < 0 {
		return cur
	}
	emitted := 0
	prevSec := ""
	if top >= bytesPerHexRow {
		prevSec = m.hexSectionName(md, top-bytesPerHexRow, addrAt)
	}
	for rowStart := top; rowStart < len(data); {
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
			if pos >= len(data) {
				pos = len(data) - 1
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
	rowHeight := func(i int) int {
		return m.disasmInstVisualHeight(i, m.disasmRenderWidth())
	}
	top := m.visualTopForView(m.disasmCur, m.disasmTop, len(m.disasmInst), visible, rowHeight)
	return visualItemAtRow(top, len(m.disasmInst), r, rowHeight)
}
