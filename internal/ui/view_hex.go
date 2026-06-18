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

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/rabarbra/exex/internal/binfile"
)

const bytesPerHexRow = 16

// identityAddr is the addrAt mapping for the raw file view, where a byte's
// "address" is just its file offset.
func identityAddr(pos int) uint64 { return uint64(pos) }

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
	if sec := m.file.SectionAt(addr); sec != nil && sec.Addr == addr {
		m.hexTop = pos
	}
	m.renderedHexTop = m.hexTop
	m.viewportDetached = false
	m.setMode(modeHex)
	m.pinCurrentByteSectionStart()
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
	if sec := m.sectionAtOffset(off); sec != nil && sec.Offset == off {
		m.rawTop = pos
	}
	m.renderedRawTop = m.rawTop
	m.viewportDetached = false
	m.setMode(modeRaw)
	m.pinCurrentByteSectionStart()
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
	case "d":
		addr := m.hexImg.AddrAt(m.hexCur)
		if _, ok := m.file.ExecImage().PosForAddr(addr); ok && m.dis != nil {
			m.loadDisasmAt(addr)
		} else {
			m.setStatus("address is not executable", true)
		}
	case "w":
		m.toggleWrap()
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
		m.jumpByteCursor(modeHex, m.seekHexSection(true))
	case "[":
		m.jumpByteCursor(modeHex, m.seekHexSection(false))
	case "}", "shift+]":
		m.hexCur = m.seekNonZero(data, m.hexCur, true)
	case "{", "shift+[":
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

// jumpByteCursor parks both the cursor and the viewport top on pos, reattaches
// the viewport and pins the section separator at the top. It is the shared tail
// of the hex/raw section-seek keys; a no-op when pos is already the cursor (the
// seek helpers return the current position when there is nowhere to go).
func (m *Model) jumpByteCursor(md mode, pos int) {
	switch md {
	case modeHex:
		if pos == m.hexCur {
			return
		}
		m.hexCur, m.hexTop, m.renderedHexTop = pos, pos, pos
	case modeRaw:
		if pos == m.rawCur {
			return
		}
		m.rawCur, m.rawTop, m.renderedRawTop = pos, pos, pos
	default:
		return
	}
	m.viewportDetached = false
	m.pinCurrentByteSectionStart()
}

// seekHexSection moves the byte cursor to the start of the next/previous mapped
// section (by virtual address), reporting when there is none in that direction.
func (m *Model) seekHexSection(forward bool) int {
	curAddr := m.hexImg.AddrAt(m.hexCur)
	best := uint64(0)
	found := false
	for i := range m.file.Sections {
		s := &m.file.Sections[i]
		if !s.Alloc || s.Size == 0 {
			continue
		}
		if forward {
			if s.Addr > curAddr && (!found || s.Addr < best) {
				best, found = s.Addr, true
			}
		} else {
			if s.Addr < curAddr && (!found || s.Addr > best) {
				best, found = s.Addr, true
			}
		}
	}
	if !found {
		m.setStatus("no more sections in this direction", false)
		return m.hexCur
	}
	if pos, ok := m.hexImg.PosForAddr(best); ok {
		return pos
	}
	return m.hexCur
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
	case "w":
		m.toggleWrap()
	case "a":
		m.copyToClipboard(fmt.Sprintf("0x%x", m.rawCur), "offset")
	case "s":
		if sec := m.sectionAtOffset(uint64(m.rawCur)); sec != nil {
			m.copyToClipboard(sec.Name, "section name")
		} else {
			m.setStatus("offset is not inside any section's file data", true)
		}
	case "]":
		m.jumpByteCursor(modeRaw, m.seekRawSection(true))
	case "[":
		m.jumpByteCursor(modeRaw, m.seekRawSection(false))
	case "}", "shift+]":
		m.rawCur = m.seekNonZero(m.rawData, m.rawCur, true)
	case "{", "shift+[":
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

// seekRawSection moves the raw cursor to the start of the next/previous
// section's file bytes (by file offset).
func (m *Model) seekRawSection(forward bool) int {
	cur := uint64(m.rawCur)
	best := uint64(0)
	found := false
	for i := range m.file.Sections {
		s := &m.file.Sections[i]
		if s.FileSize == 0 {
			continue
		}
		if forward {
			if s.Offset > cur && (!found || s.Offset < best) {
				best, found = s.Offset, true
			}
		} else {
			if s.Offset < cur && (!found || s.Offset > best) {
				best, found = s.Offset, true
			}
		}
	}
	if !found {
		m.setStatus("no more sections in this direction", false)
		return m.rawCur
	}
	if int(best) < len(m.rawData) {
		return int(best)
	}
	return m.rawCur
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
	return m.renderHexDump(modeHex, m.hexImg.Data, m.hexCur, &m.hexTop, m.hexImg.AddrAt, banner)
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
	return m.renderHexDump(modeRaw, m.rawData, m.rawCur, &m.rawTop, identityAddr, banner)
}

// renderHexDump draws a classic offset|hex|ascii table. addrAt maps a byte
// position to the address shown at the start of its row, so the same renderer
// serves both the VA image and the raw file view.
func (m *Model) renderHexDump(md mode, data []byte, cur int, topPtr *int, addrAt func(pos int) uint64, banner string) string {
	bodyH := m.bodyHeight()
	addrW := m.file.AddrHexWidth()
	visible := max(bodyH-1, 1)
	top := m.hexVisibleTop(md, cur, *topPtr, visible, addrAt)
	if m.viewportDetached {
		top = m.scrollByteViewportTop(md, data, *topPtr, visible, 0, addrAt)
	} else if secStart, ok := m.currentHexSectionStart(md, cur); ok && top < secStart && secStart <= cur {
		top = secStart
	}
	if pinned, ok := m.pinnedByteSectionTop(md); ok && top < pinned && cur >= pinned {
		top = pinned
	}
	*topPtr = top
	if md == modeRaw {
		m.renderedRawTop = top
	} else {
		m.renderedHexTop = top
	}

	rows := []string{m.theme.stickySymStyle.Render(padRight(banner, m.width))}
	for off := top; off < len(data) && len(rows) < bodyH; {
		if sec := m.hexSectionStartName(md, off); sec != "" {
			appendRenderedRows(
				&rows,
				m.theme.sectionStyle.Render(lipgloss.PlaceHorizontal(
					addrW+73,
					lipgloss.Center,
					" "+sec+" ",
					lipgloss.WithWhitespaceChars("="),
				)),
				m.width, m.wrap, addrW+75,
			)
		}
		row := m.hexRowSpan(md, data, off, addrAt)
		if !appendRenderedRowsIndented(
			&rows,
			m.renderHexRow(md, data, cur, row, addrW, addrAt),
			m.width, m.wrap, addrW+75, bodyH,
		) {
			break
		}
		off = row.end
	}
	return padBodyRows(rows, m.width, bodyH)
}

type hexRowSpan struct {
	start    int
	end      int
	lineAddr uint64
	lead     int
}

func (m *Model) hexRowSpan(md mode, data []byte, start int, addrAt func(pos int) uint64) hexRowSpan {
	addr := addrAt(start)
	lead := int(addr % bytesPerHexRow)
	lineAddr := addr - uint64(lead)
	end := min(start+bytesPerHexRow-lead, len(data))
	if next, ok := m.nextHexSectionStart(md, start); ok && next < end {
		end = next
	}
	if end <= start {
		end = min(start+1, len(data))
	}
	return hexRowSpan{start: start, end: end, lineAddr: lineAddr, lead: lead}
}

// Row geometry note: a row's leading address is aligned to bytesPerHexRow on
// the *address* grid (addr % bytesPerHexRow), not the data-position grid. The
// two differ whenever a section's start address isn't row-aligned, so all of
// the scroll math below is expressed in terms of these address-aware helpers
// rather than raw data offsets. Otherwise the top visible row of an unaligned
// section would render a spurious leading gap (only a section's first and last
// rows may be partial).

// hexRowTop returns the byte position of the start of the row containing pos.
// The start is aligned to the address grid but never crosses below the start of
// pos's own section, so a section's first row begins exactly at the section even
// when its address is unaligned.
func (m *Model) hexRowTop(md mode, pos int, addrAt func(pos int) uint64) int {
	if pos <= 0 {
		return 0
	}
	start := pos - int(addrAt(pos)%bytesPerHexRow)
	if secStart, ok := m.currentHexSectionStart(md, pos); ok && start < secStart {
		start = secStart
	}
	if start < 0 {
		return 0
	}
	return start
}

// hexPrevRowTop returns the start of the row immediately above pos's row.
func (m *Model) hexPrevRowTop(md mode, pos int, addrAt func(pos int) uint64) int {
	rs := m.hexRowTop(md, pos, addrAt)
	if rs <= 0 {
		return 0
	}
	return m.hexRowTop(md, rs-1, addrAt)
}

// hexMaxTop returns the highest row-start that still fills the last screen.
func (m *Model) hexMaxTop(md mode, data []byte, visibleRows int, addrAt func(pos int) uint64) int {
	if len(data) == 0 {
		return 0
	}
	top := m.hexRowTop(md, len(data)-1, addrAt)
	for i := 0; i < visibleRows-1 && top > 0; i++ {
		top = m.hexPrevRowTop(md, top, addrAt)
	}
	return top
}

// hexVisibleTop returns the row-start to render from so the cursor stays on
// screen, scrolling the viewport by whole rows only as far as needed.
func (m *Model) hexVisibleTop(md mode, cur, top, visibleRows int, addrAt func(pos int) uint64) int {
	if visibleRows < 1 {
		visibleRows = 1
	}
	top = m.hexRowTop(md, top, addrAt)
	curStart := m.hexRowTop(md, cur, addrAt)
	if curStart <= top {
		return curStart
	}
	// The highest top that still keeps curStart on screen is curStart walked up
	// (visibleRows-1) rows; if our current top sits above it, the cursor has
	// scrolled past the bottom, so jump down to that limit.
	limit := curStart
	for i := 0; i < visibleRows-1 && limit > 0; i++ {
		limit = m.hexPrevRowTop(md, limit, addrAt)
	}
	if top < limit {
		return limit
	}
	return top
}

// hexSectionName returns the name of the section covering the byte at off (a VA
// for the hex view, a file offset for the raw view), or "" if none.
func (m *Model) hexSectionName(md mode, off int, addrAt func(pos int) uint64) string {
	if md == modeHex {
		if sec := m.file.SectionAt(addrAt(off)); sec != nil {
			return sec.Name
		}
		return ""
	}
	if sec := m.sectionAtOffset(uint64(off)); sec != nil {
		return sec.Name
	}
	return ""
}

func (m *Model) hexSectionStartName(md mode, off int) string {
	if off < 0 {
		return ""
	}
	if md == modeHex {
		if r := m.hexImg.RegionAt(off); r != nil && r.Off == off {
			return r.Name
		}
		return ""
	}
	for i := range m.file.Sections {
		s := &m.file.Sections[i]
		if s.FileSize > 0 && s.Offset == uint64(off) {
			return s.Name
		}
	}
	return ""
}

func (m *Model) currentHexSectionStart(md mode, cur int) (int, bool) {
	if cur < 0 {
		return 0, false
	}
	if md == modeHex {
		if r := m.hexImg.RegionAt(cur); r != nil {
			return r.Off, true
		}
		return 0, false
	}
	sec := m.sectionAtOffset(uint64(cur))
	if sec == nil || sec.Offset > uint64(int(^uint(0)>>1)) {
		return 0, false
	}
	return int(sec.Offset), true
}

func (m *Model) pinCurrentByteSectionStart() {
	switch m.mode {
	case modeHex:
		if start, ok := m.currentHexSectionStart(modeHex, m.hexCur); ok && start == m.hexCur {
			m.hexPinnedTop = start
			m.hexPinned = true
			return
		}
		m.hexPinned = false
	case modeRaw:
		if start, ok := m.currentHexSectionStart(modeRaw, m.rawCur); ok && start == m.rawCur {
			m.rawPinnedTop = start
			m.rawPinned = true
			return
		}
		m.rawPinned = false
	}
}

func (m *Model) clearByteSectionPin(md mode) {
	switch md {
	case modeHex:
		m.hexPinned = false
	case modeRaw:
		m.rawPinned = false
	}
}

func (m *Model) pinnedByteSectionTop(md mode) (int, bool) {
	switch md {
	case modeHex:
		return m.hexPinnedTop, m.hexPinned
	case modeRaw:
		return m.rawPinnedTop, m.rawPinned
	}
	return 0, false
}

func (m *Model) nextHexSectionStart(md mode, off int) (int, bool) {
	best := 0
	found := false
	if md == modeHex {
		for _, r := range m.hexImg.Regions {
			if r.Off > off && (!found || r.Off < best) {
				best, found = r.Off, true
			}
		}
		return best, found
	}
	for i := range m.file.Sections {
		s := &m.file.Sections[i]
		if s.FileSize == 0 || s.Offset > uint64(int(^uint(0)>>1)) {
			continue
		}
		start := int(s.Offset)
		if start > off && (!found || start < best) {
			best, found = start, true
		}
	}
	return best, found
}

func (m *Model) renderHexRow(md mode, data []byte, cur int, span hexRowSpan, addrW int, addrAt func(pos int) uint64) string {
	var hexCol, asciiCol strings.Builder
	for slot := 0; slot < bytesPerHexRow; slot++ {
		if slot > 0 {
			hexCol.WriteByte(' ')
			if slot == bytesPerHexRow/2 {
				hexCol.WriteByte(' ')
			}
		}
		i := span.start + slot - span.lead
		if slot < span.lead || i < span.start || i >= span.end {
			hexCol.WriteString("  ")
			asciiCol.WriteByte(' ')
			continue
		}
		b := data[i]
		if i == cur {
			ascii := byte('.')
			if b >= 0x20 && b < 0x7f {
				ascii = b
			}
			hexCol.WriteString(m.theme.tableSelStyle.Render(hex2(b)))
			asciiCol.WriteString(m.theme.tableSelStyle.Render(string(ascii)))
		} else {
			hexCol.WriteString(byteHex[b])
			asciiCol.WriteString(byteASCII[b])
		}
	}
	var line strings.Builder
	fmt.Fprintf(&line, " %s  %s  |%s|",
		m.theme.addrStyle.Render(fmt.Sprintf("0x%0*x", addrW, span.lineAddr)),
		hexCol.String(),
		asciiCol.String(),
	)
	if md == modeHex {
		addr := addrAt(span.start)
		endAddr := addr + uint64(span.end-span.start)
		if syms := m.file.SymbolsInRange(addr, endAddr); len(syms) != 0 {
			for _, sym := range syms {
				line.WriteString(" [")
				line.WriteString(m.theme.addrStyle.Render(sym.Display()))
				line.WriteString("]")
			}
		} else if sec := m.file.SectionAt(addr); sec != nil && sec.Addr == addr {
			line.WriteString("  ")
			line.WriteString(m.theme.addrStyle.Render(sec.Name))
		}
	}
	return line.String()
}
