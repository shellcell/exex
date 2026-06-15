package ui

// Mouse support: the wheel scrolls the active view (reusing each view's
// up/down navigation) and a left click selects whatever the pointer is over —
// a row in the list views, a byte in the hex/raw dumps, or an instruction in
// the disassembly.

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// doubleClickWindow is how close two clicks must be (in time, on the same row)
// to count as a double-click.
const doubleClickWindow = 350 * time.Millisecond

func (m *Model) handleMouse(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
	if m.searchActive && msg.Action == tea.MouseActionPress && msg.Button == tea.MouseButtonLeft {
		m.handleSearchPopupClick(msg.X, msg.Y)
		return m, nil
	}
	switch msg.Button {
	case tea.MouseButtonWheelUp:
		return m.wheelScroll("up")
	case tea.MouseButtonWheelDown:
		return m.wheelScroll("down")
	}
	if msg.Action == tea.MouseActionPress && msg.Button == tea.MouseButtonLeft {
		if msg.Y == 0 { // the tab strip
			if md, ok := m.tabHitTest(msg.X); ok {
				return m, m.switchMode(md)
			}
			return m, nil
		}
		now := time.Now()
		isDouble := m.mode == modeDisasm && msg.Y == m.lastClickY &&
			now.Sub(m.lastClickAt) < doubleClickWindow
		m.lastClickY = msg.Y
		m.lastClickAt = now

		m.handleClick(msg.X, msg.Y)
		if isDouble {
			m.followCurrentDisasm()
		}
	}
	return m, nil
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

// wheelScroll moves a few lines per notch, which feels more natural than one.
func (m *Model) wheelScroll(key string) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	for i := 0; i < 3; i++ {
		_, cmd = m.routeNav(key)
	}
	return m, cmd
}

// routeNav feeds a navigation key to whichever view is active, so the wheel
// behaves exactly like the arrow keys for that view.
func (m *Model) routeNav(key string) (tea.Model, tea.Cmd) {
	switch m.mode {
	case modeSections:
		return m.updateSections(key)
	case modeSymbols:
		return m.updateSymbols(key)
	case modeDisasm:
		return m.updateDisasm(key)
	case modeHex:
		return m.updateHex(key)
	case modeRaw:
		return m.updateRaw(key)
	case modeStrings:
		return m.updateStrings(key)
	case modeSources:
		return m.updateSources(key)
	case modeLibs:
		return m.updateLibs(key)
	case modeInfo:
		if key == "up" {
			m.headerVP.LineUp(1)
		} else {
			m.headerVP.LineDown(1)
		}
	}
	return m, nil
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
		if idx, ok := visualItemAtRow(m.sectionsTop, len(m.sectionsFiltered), bodyRow-2, m.sectionRowHeight); ok {
			m.sectionsCur = idx
		}
	case modeSymbols:
		// Body layout: row 0 filter, row 1 header, data follows.
		if idx, ok := visualItemAtRow(m.symbolsTop, len(m.symbolsFiltered), bodyRow-2, m.symbolRowHeight); ok {
			m.symbolsCur = idx
		}
	case modeHex:
		m.ensureHex()
		m.hexCur = m.clickByte(modeHex, m.hexImg.Data, m.hexTop, m.hexCur, x, bodyRow, m.hexImg.AddrAt)
	case modeRaw:
		m.ensureRaw()
		m.rawCur = m.clickByte(modeRaw, m.rawData, m.rawTop, m.rawCur, x, bodyRow, func(pos int) uint64 { return uint64(pos) })
	case modeStrings:
		// Body layout: row 0 is the column header, data follows.
		if idx, ok := visualItemAtRow(m.stringsTop, len(m.stringsList), bodyRow-1, m.stringRowHeight); ok {
			m.stringsCur = idx
		}
	case modeSources:
		if m.srcFile == "" {
			// File list: row 0 is the filter, files follow.
			if idx := m.sourcesTop + bodyRow - 1; idx >= 0 && idx < len(m.sourcesFiltered) {
				m.sourcesCur = idx
			}
		} else if m.clickInSourcePane(x) {
			if ln, ok := m.sourceLineAtBodyRow(bodyRow, m.sourcePaneWidth()); ok {
				m.srcCur = ln
				m.syncSourceAsm()
			}
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
			if idx, ok := visualItemAtRow(m.libsTop, len(m.file.Info.DynamicLibs), bodyRow-headerRows, m.libRowHeight); ok {
				m.libsCur = idx
			}
		}
	}
}

func (m *Model) clickInSourcePane(x int) bool {
	if m.mode == modeDisasm && m.sourceFirst {
		return x < m.width/2
	}
	if m.mode == modeSources && m.srcAsmLeft {
		return x >= m.width/2
	}
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
	rowHeight := func(i int) int {
		ln := i + 1
		h := m.sourceLineHeight(ln, paneW)
		if ln == m.srcCur && len(m.file.LineColumns(m.srcFile, ln)) > 0 {
			h++
		}
		return h
	}
	idx, ok := visualItemAtRow(max(0, m.srcTop-1), len(src), r, rowHeight)
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
	for rowStart := top; rowStart < len(data); rowStart += bytesPerHexRow {
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
			pos := rowStart + hexColumnToByte(m.file.AddrHexWidth(), x)
			if pos >= len(data) {
				pos = len(data) - 1
			}
			return pos
		}
		emitted++
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
	return visualItemAtRow(m.disasmTop, len(m.disasmInst), r, func(i int) int {
		return m.disasmInstVisualHeight(i, m.disasmRenderWidth())
	})
}
