package ui

// This file owns the two byte-dump views:
//
//   - Hex (modeHex):  a continuous virtual-address dump of *every* mapped
//                     section, stitched together in VA order. Scrolling runs
//                     from the first mapped byte to the last.
//   - Raw (modeRaw):  the entire file, addressed by file offset (0 → EOF).
//
// Both share the same offset|hex|ascii renderer; they differ only in their
// byte source and how a row's leading address is computed.

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/rabarbra/exex/internal/binfile"
)

const bytesPerHexRow = 16

// Hex row layout, shared by renderHexRow (drawing) and hexColumnToByte
// (hit-testing) so the two never drift. A row is:
//
//	" " + "0x"<addrW digits> + "  " + bytes
//
// where each byte is two hex digits followed by a space, with one extra space
// inserted after the middle byte.

// hexBodyStart is the screen column of the first hex digit.
func hexBodyStart(addrW int) int { return 1 + 2 + addrW + 2 }

// hexColumnToByte maps a screen column x to a byte index [0, bytesPerHexRow).
func hexColumnToByte(addrW, x int) int {
	rel := x - hexBodyStart(addrW)
	if rel < 0 {
		return 0
	}
	col := rel / 3
	// Bytes past the midpoint are shifted right by the extra separating space.
	if rel >= (bytesPerHexRow/2)*3+1 {
		col = (rel - 1) / 3
	}
	if col > bytesPerHexRow-1 {
		col = bytesPerHexRow - 1
	}
	return col
}

// ensureHex builds the virtual-address image lazily.
func (m *Model) ensureHex() {
	if m.hexImg == nil {
		m.hexImg = m.file.VAImage()
	}
}

// ensureRaw grabs the whole-file byte slice lazily.
func (m *Model) ensureRaw() {
	if m.rawData == nil {
		m.rawData = m.file.Raw()
	}
}

// openHexAt switches to the virtual-address hex view with the cursor parked on
// addr. Reports an error if addr isn't inside any mapped section.
func (m *Model) openHexAt(addr uint64) {
	m.ensureHex()
	pos, ok := m.hexImg.PosForAddr(addr)
	if !ok {
		m.setStatus(fmt.Sprintf("0x%x is not in any mapped section", addr), true)
		return
	}
	m.hexCur = pos
	m.hexTop = (pos / bytesPerHexRow) * bytesPerHexRow
	m.mode = modeHex
	m.status = ""
}

// openRawAt switches to the raw file view with the cursor on file offset off.
func (m *Model) openRawAt(off uint64) {
	m.ensureRaw()
	pos := int(off)
	if pos < 0 || pos >= len(m.rawData) {
		pos = 0
	}
	m.rawCur = pos
	m.rawTop = (pos / bytesPerHexRow) * bytesPerHexRow
	m.mode = modeRaw
	m.status = ""
}

// moveByteCursor applies a navigation key to a byte cursor over n bytes.
func (m *Model) moveByteCursor(key string, cur, n int) int {
	row := bytesPerHexRow
	switch key {
	case "left", "h":
		if cur > 0 {
			cur--
		}
	case "right", "l":
		if cur < n-1 {
			cur++
		}
	case "up", "k":
		if cur >= row {
			cur -= row
		}
	case "down", "j":
		if cur+row < n {
			cur += row
		}
	case "pgup":
		cur = max(0, cur-row*m.bodyHeight())
	case "pgdown":
		cur = min(n-1, cur+row*m.bodyHeight())
	case "home", "g g":
		cur = 0
	case "end", "G":
		cur = n - 1
	}
	return cur
}

func (m *Model) updateHex(key string) (tea.Model, tea.Cmd) {
	m.ensureHex()
	data := m.hexImg.Data
	if len(data) == 0 {
		return m, nil
	}
	switch key {
	case "a":
		addr := m.hexImg.AddrAt(m.hexCur)
		m.copyToClipboard(fmt.Sprintf("0x%0*x", m.file.AddrHexWidth(), addr), "address")
	case "s":
		addr := m.hexImg.AddrAt(m.hexCur)
		if sym, ok := m.file.SymbolAt(addr); ok {
			m.copyToClipboard(sym.Name, "symbol")
		} else {
			m.setStatus("no symbol at this address", true)
		}
	case "]":
		m.hexCur = m.seekNonZero(data, m.hexCur, true)
	case "[":
		m.hexCur = m.seekNonZero(data, m.hexCur, false)
	case "/":
		m.openSearch()
	case "n":
		m.runSearch(true, false)
	case "N":
		m.runSearch(false, false)
	default:
		m.hexCur = m.moveByteCursor(key, m.hexCur, len(data))
	}
	return m, nil
}

// seekNonZero moves a byte cursor to the next/previous non-zero byte. It
// reports via the status line when there is no further non-zero byte.
func (m *Model) seekNonZero(data []byte, cur int, forward bool) int {
	if forward {
		for i := cur + 1; i < len(data); i++ {
			if data[i] != 0 {
				return i
			}
		}
	} else {
		for i := cur - 1; i >= 0; i-- {
			if data[i] != 0 {
				return i
			}
		}
	}
	m.setStatus("no more non-zero bytes in this direction", false)
	return cur
}

func (m *Model) updateRaw(key string) (tea.Model, tea.Cmd) {
	m.ensureRaw()
	if len(m.rawData) == 0 {
		return m, nil
	}
	switch key {
	case "a":
		m.copyToClipboard(fmt.Sprintf("0x%x", m.rawCur), "offset")
	case "s":
		if sec := m.sectionAtOffset(uint64(m.rawCur)); sec != nil {
			m.copyToClipboard(sec.Name, "section name")
		} else {
			m.setStatus("offset is not inside any section's file data", true)
		}
	case "]":
		m.rawCur = m.seekNonZero(m.rawData, m.rawCur, true)
	case "[":
		m.rawCur = m.seekNonZero(m.rawData, m.rawCur, false)
	case "/":
		m.openSearch()
	case "n":
		m.runSearch(true, false)
	case "N":
		m.runSearch(false, false)
	default:
		m.rawCur = m.moveByteCursor(key, m.rawCur, len(m.rawData))
	}
	return m, nil
}

// sectionAtOffset returns the section whose file bytes cover off.
func (m *Model) sectionAtOffset(off uint64) *binfile.Section {
	for i := range m.file.Sections {
		s := &m.file.Sections[i]
		if s.FileSize == 0 {
			continue
		}
		if off >= s.Offset && off < s.Offset+s.FileSize {
			return s
		}
	}
	return nil
}

func (m *Model) renderHex() string {
	m.ensureHex()
	if m.hexImg.Len() == 0 {
		return padBody("no mapped sections to display\n", m.width, m.bodyHeight())
	}
	banner := fmt.Sprintf(" virtual-address image · %d bytes · %d mapped sections",
		m.hexImg.Len(), len(m.hexImg.Regions))
	if r := m.hexImg.RegionAt(m.hexCur); r != nil {
		banner = fmt.Sprintf(" %s   @ 0x%0*x   ·   %d bytes across %d mapped sections",
			r.Name, m.file.AddrHexWidth(), m.hexImg.AddrAt(m.hexCur), m.hexImg.Len(), len(m.hexImg.Regions))
	}
	return m.renderHexDump(m.hexImg.Data, m.hexCur, &m.hexTop, m.hexImg.AddrAt, banner)
}

func (m *Model) renderRaw() string {
	m.ensureRaw()
	if len(m.rawData) == 0 {
		return padBody("empty file\n", m.width, m.bodyHeight())
	}
	banner := fmt.Sprintf(" raw file · %d bytes · file offsets", len(m.rawData))
	if sec := m.sectionAtOffset(uint64(m.rawCur)); sec != nil {
		banner = fmt.Sprintf(" raw file · offset 0x%x · in %s · %d bytes total",
			m.rawCur, sec.Name, len(m.rawData))
	}
	return m.renderHexDump(m.rawData, m.rawCur, &m.rawTop, func(pos int) uint64 { return uint64(pos) }, banner)
}

// renderHexDump draws a classic offset|hex|ascii table. addrAt maps a byte
// position to the address shown at the start of its row, so the same renderer
// serves both the VA image and the raw file view.
func (m *Model) renderHexDump(data []byte, cur int, topPtr *int, addrAt func(pos int) uint64, banner string) string {
	bodyH := m.bodyHeight()
	row := bytesPerHexRow
	addrW := m.file.AddrHexWidth()

	curRow := cur / row
	visible := bodyH - 1
	if visible < 1 {
		visible = 1
	}
	topRow := *topPtr / row
	if curRow < topRow {
		topRow = curRow
	} else if curRow >= topRow+visible {
		topRow = curRow - visible + 1
	}
	*topPtr = topRow * row

	out := stickySymStyle.Render(padRight(banner, m.width)) + "\n"
	end := *topPtr + visible*row
	if end > len(data) {
		end = len(data)
	}
	for off := *topPtr; off < end; off += row {
		out += m.renderHexRow(data, cur, off, addrW, addrAt) + "\n"
	}
	return padBody(out, m.width, bodyH)
}

func (m *Model) renderHexRow(data []byte, cur, off, addrW int, addrAt func(pos int) uint64) string {
	row := bytesPerHexRow
	end := off + row
	if end > len(data) {
		end = len(data)
	}
	addr := addrAt(off)
	var hexCol, asciiCol strings.Builder
	for i := off; i < off+row; i++ {
		if i > off {
			hexCol.WriteByte(' ')
			if i == off+row/2 {
				hexCol.WriteByte(' ')
			}
		}
		if i >= end {
			hexCol.WriteString("  ")
			asciiCol.WriteByte(' ')
			continue
		}
		b := data[i]
		ascii := byte('.')
		if b >= 0x20 && b < 0x7f {
			ascii = b
		}
		if i == cur {
			hexCol.WriteString(tableSelStyle.Render(hex2(b)))
			asciiCol.WriteString(tableSelStyle.Render(string(ascii)))
		} else {
			hexCol.WriteString(byteHex[b])
			asciiCol.WriteString(byteFG[b].Render(string(ascii)))
		}
	}
	line := fmt.Sprintf(" %s  %s  %s",
		addrStyle.Render(fmt.Sprintf("0x%0*x", addrW, addr)),
		hexCol.String(),
		"|"+asciiCol.String()+"|",
	)
	return padRight(line, m.width)
}
