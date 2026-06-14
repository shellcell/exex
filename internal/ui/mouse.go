package ui

// Mouse support: the wheel scrolls the active view (reusing each view's
// up/down navigation) and a left click selects whatever the pointer is over —
// a row in the list views, a byte in the hex/raw dumps, or an instruction in
// the disassembly.

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// doubleClickWindow is how close two clicks must be (in time, on the same row)
// to count as a double-click.
const doubleClickWindow = 350 * time.Millisecond

func (m *Model) handleMouse(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
	switch msg.Button {
	case tea.MouseButtonWheelUp:
		return m.routeNav("up")
	case tea.MouseButtonWheelDown:
		return m.routeNav("down")
	}
	if msg.Action == tea.MouseActionPress && msg.Button == tea.MouseButtonLeft {
		if msg.Y == 0 { // the tab strip
			if md, ok := m.tabHitTest(msg.X); ok {
				m.switchMode(md)
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
		if idx := m.sectionsTop + bodyRow - 2; idx >= 0 && idx < len(m.sectionsFiltered) {
			m.sectionsCur = idx
		}
	case modeSymbols:
		// Body layout: row 0 filter, row 1 header, data follows.
		if idx := m.symbolsTop + bodyRow - 2; idx >= 0 && idx < len(m.symbolsFiltered) {
			m.symbolsCur = idx
		}
	case modeHex:
		m.ensureHex()
		m.hexCur = m.clickByte(m.hexImg.Data, m.hexTop, m.hexCur, x, bodyRow)
	case modeRaw:
		m.ensureRaw()
		m.rawCur = m.clickByte(m.rawData, m.rawTop, m.rawCur, x, bodyRow)
	case modeStrings:
		// Body layout: row 0 is the column header, data follows.
		if idx := m.stringsTop + bodyRow - 1; idx >= 0 && idx < len(m.stringsList) {
			m.stringsCur = idx
		}
	case modeDisasm:
		if i, ok := m.instAtBodyRow(bodyRow); ok {
			m.disasmCur = i
		}
	}
}

// clickByte maps a click at (x, bodyRow) onto a byte position in a hex dump.
// Body layout: row 0 is the banner, byte rows follow with bytesPerHexRow bytes
// each. The column maths mirror renderHexRow's spacing (a single space between
// bytes plus one extra space splitting the row in half).
func (m *Model) clickByte(data []byte, top, cur, x, bodyRow int) int {
	r := bodyRow - 1 // strip the banner row
	if r < 0 {
		return cur
	}
	rowStart := top + r*bytesPerHexRow
	if rowStart >= len(data) {
		return cur
	}
	hexStart := m.file.AddrHexWidth() + 5 // " " + "0x" + addr digits + "  "
	col := 0
	if rel := x - hexStart; rel > 0 {
		col = rel / 3
		if rel >= 25 { // past the mid-row extra space, shift back by one column
			col = (rel - 1) / 3
		}
	}
	if col < 0 {
		col = 0
	}
	if col > bytesPerHexRow-1 {
		col = bytesPerHexRow - 1
	}
	pos := rowStart + col
	if pos >= len(data) {
		pos = len(data) - 1
	}
	return pos
}

// instAtBodyRow maps a click in the disasm scroller to an instruction index.
// It replays renderDisasmScroll's emit order: a symbol-start instruction is
// preceded by a "<name>:" label line, so rows aren't 1:1 with instructions.
func (m *Model) instAtBodyRow(bodyRow int) (int, bool) {
	r := bodyRow - 1 // strip the sticky-symbol row
	if r < 0 {
		return 0, false
	}
	h := m.bodyHeight() - 1
	emitted := 0
	for i := m.disasmTop; i < len(m.disasmInst) && emitted < h; i++ {
		inst := m.disasmInst[i]
		if sym, ok := m.file.SymbolAt(inst.Addr); ok && sym.Addr == inst.Addr {
			if emitted == r {
				return i, true // clicked the label → select its instruction
			}
			emitted++
			if emitted >= h {
				break
			}
		}
		if emitted == r {
			return i, true
		}
		emitted++
	}
	return 0, false
}
