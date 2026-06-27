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
	"math"
	"sort"
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

// hexGridWidth is the on-screen width of the hex-byte column: bytesPerHexRow
// pairs (2 each), a single space between them, and one extra space at the
// midpoint.
const hexGridWidth = bytesPerHexRow*2 + (bytesPerHexRow - 1) + 1

// hexWrapIndent is the hanging-indent column for wrapped hex/raw rows, aligned
// with where the trailing content begins so a wrapped annotation lines up under
// it: the decoded-word column in pointer mode, or past the |ascii| column (where
// the symbol annotations sit) in ascii mode.
func (m *Model) hexWrapIndent(addrW int) int {
	col := hexBodyStart(addrW) + hexGridWidth + 2 // start of the ascii / word column
	if !m.hexWords {
		col += bytesPerHexRow + 2 // skip the |ascii| column to the symbol annotations
	}
	return col
}

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

// inspectorBanner decodes the bytes at pos as integers of every width (signed
// and unsigned), floats, a char, and a pointer (resolved to its symbol/section),
// for the data-inspector banner. prefix is the cursor's location label.
func (m *Model) inspectorBanner(data byteSource, pos int, prefix string) string {
	if pos < 0 || pos >= data.Len() {
		return prefix + "  inspect: (no byte under cursor)"
	}
	be := m.file.Info != nil && m.file.Info.ByteOrder == "big-endian"
	readU := func(n int) (uint64, bool) {
		if pos+n > data.Len() {
			return 0, false
		}
		var v uint64
		if be {
			for k := 0; k < n; k++ {
				v = v<<8 | uint64(data.At(pos+k))
			}
		} else {
			for k := n - 1; k >= 0; k-- {
				v = v<<8 | uint64(data.At(pos+k))
			}
		}
		return v, true
	}

	u8, _ := readU(1)
	parts := []string{fmt.Sprintf("u8 0x%02x (%d)", u8, u8)}
	if v, ok := readU(2); ok {
		parts = append(parts, fmt.Sprintf("u16 0x%04x", v))
	}
	if v, ok := readU(4); ok {
		parts = append(parts,
			fmt.Sprintf("u32 0x%08x", v),
			fmt.Sprintf("i32 %d", int32(v)),
			fmt.Sprintf("f32 %g", math.Float32frombits(uint32(v))))
	}
	if v, ok := readU(8); ok {
		parts = append(parts,
			fmt.Sprintf("u64 0x%016x", v),
			fmt.Sprintf("i64 %d", int64(v)),
			fmt.Sprintf("f64 %g", math.Float64frombits(v)))
	}
	ch := "·"
	if u8 >= 0x20 && u8 < 0x7f {
		ch = string(rune(u8))
	}
	parts = append(parts, "char '"+ch+"'")
	if pv, ok := m.readPointer(data, pos); ok && pv != 0 && m.file.IsMapped(pv) {
		if name := m.targetAnnotation(pv); name != "" {
			parts = append(parts, "ptr→ "+name)
		}
	}
	return prefix + "  " + strings.Join(parts, "  ")
}

// toggleHexWords flips the hex/raw trailing column between ASCII and the
// pointer-word decode, reporting the new mode in the footer.
func (m *Model) toggleHexWords() {
	m.hexWords = !m.hexWords
	col := "ascii"
	if m.hexWords {
		col = "pointers"
	}
	m.setStatus("hex column: "+col, false)
}

// toggleHexInspect flips the data-inspector banner on/off.
func (m *Model) toggleHexInspect() {
	m.hexInspect = !m.hexInspect
	state := "off"
	if m.hexInspect {
		state = "on"
	}
	m.setStatus("data inspector: "+state, false)
}

// copyPointerAt copies the pointer-sized word at byte position pos to the
// clipboard as 0x… (the value the pointer-decode column shows), mirroring the
// address/symbol copy keys.
func (m *Model) copyPointerAt(data byteSource, pos int) {
	v, ok := m.readPointer(data, pos)
	if !ok {
		m.setStatus("not enough bytes for a pointer here", true)
		return
	}
	m.copyToClipboard(fmt.Sprintf("0x%x", v), "pointer")
}

// followPointerAt reads the pointer-sized word at pos and navigates to the
// address it points to (disasm when executable, else the hex view), so GOT/data
// pointer tables can be walked. Reports when the word isn't a mapped pointer.
func (m *Model) followPointerAt(data byteSource, pos int) {
	v, ok := m.readPointer(data, pos)
	if !ok {
		m.setStatus("not enough bytes for a pointer here", true)
		return
	}
	if v == 0 || !m.file.IsMapped(v) {
		m.setStatus(fmt.Sprintf("0x%x is not a mapped address", v), true)
		return
	}
	m.gotoAddr(v)
}

// byteViewportRows is the number of byte rows visible in the hex/raw view (the
// body minus the one sticky title row).
func (m *Model) byteViewportRows() int {
	return max(1, m.bodyHeight()-1)
}

// bytePageRows is how many rows pgup/pgdown advance the hex/raw view: one screen
// minus a row, so a line of context carries over between pages.
func (m *Model) bytePageRows() int {
	return max(1, m.byteViewportRows()-1)
}

// moveByteCursor applies a navigation key to a byte cursor over n bytes.
func (m *Model) moveByteCursor(key string, cur, n int) int {
	row := bytesPerHexRow
	switch key {
	case "left":
		if cur > 0 {
			cur--
		}
	case "right":
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
		cur = max(0, cur-row*m.bytePageRows())
	case "pgdown":
		cur = min(n-1, cur+row*m.bytePageRows())
	case "home", "g g":
		cur = 0
	case "end", "G":
		cur = n - 1
	}
	return cur
}

func (m *Model) updateHex(key string) (tea.Model, tea.Cmd) {
	m.ensureHex()
	data := byteSource(m.hexImg)
	if data.Len() == 0 {
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
	case "m":
		m.jumpRawAtAddr(m.hexImg.AddrAt(m.hexCur))
	case "w":
		m.toggleWrap()
	case "t":
		m.toggleHexWords()
	case "i":
		m.toggleHexInspect()
	case "P":
		m.copyPointerAt(data, m.pointerWordStart(m.hexImg.AddrAt(m.hexCur), m.hexCur))
	case "enter":
		m.followPointerAt(data, m.pointerWordStart(m.hexImg.AddrAt(m.hexCur), m.hexCur))
	case "A":
		addr := m.hexImg.AddrAt(m.hexCur)
		m.copyToClipboard(fmt.Sprintf("0x%0*x", m.file.AddrHexWidth(), addr), "address")
	case "S":
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
	case "e":
		m.toggleSymbolAbbrevAll()
	default:
		m.hexCur = m.moveByteCursor(key, m.hexCur, data.Len())
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
// region (by virtual address), reporting when there is none in that direction.
// The VA image's Regions are the mapped sections sorted by address, so this is a
// binary search; a region's Off is exactly the byte position of its start.
func (m *Model) seekHexSection(forward bool) int {
	curAddr := m.hexImg.AddrAt(m.hexCur)
	regs := m.hexImg.Regions
	if forward {
		i := sort.Search(len(regs), func(i int) bool { return regs[i].Addr > curAddr })
		if i < len(regs) {
			return regs[i].Off
		}
	} else {
		i := sort.Search(len(regs), func(i int) bool { return regs[i].Addr >= curAddr })
		if i > 0 {
			return regs[i-1].Off
		}
	}
	m.setStatus("no more sections in this direction", false)
	return m.hexCur
}

// seekNonZero moves a byte cursor to the next/previous non-zero byte. It
// reports via the status line when there is no further non-zero byte.
func (m *Model) seekNonZero(data byteSource, cur int, forward bool) int {
	runs := data.Runs() // native region slices: the inner loop indexes them directly
	if forward {
		for _, r := range runs {
			if r.Off+len(r.B) <= cur+1 {
				continue
			}
			from := max(cur+1-r.Off, 0)
			for i := from; i < len(r.B); i++ {
				if r.B[i] != 0 {
					return r.Off + i
				}
			}
		}
	} else {
		for i := len(runs) - 1; i >= 0; i-- {
			r := runs[i]
			if r.Off > cur-1 {
				continue
			}
			hi := min(cur-1-r.Off, len(r.B)-1)
			for j := hi; j >= 0; j-- {
				if r.B[j] != 0 {
					return r.Off + j
				}
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
	case "d":
		if addr, ok := m.addrForOffset(uint64(m.rawCur)); ok {
			m.jumpDisasmAtAddr(addr)
		} else {
			m.setStatus("offset has no mapped address", true)
		}
	case "h":
		if addr, ok := m.addrForOffset(uint64(m.rawCur)); ok {
			m.jumpHexAtAddr(addr)
		} else {
			m.setStatus("offset has no mapped address", true)
		}
	case "w":
		m.toggleWrap()
	case "t":
		m.toggleHexWords()
	case "i":
		m.toggleHexInspect()
	case "P":
		m.copyPointerAt(rawBytes(m.rawData), m.pointerWordStart(uint64(m.rawCur), m.rawCur))
	case "enter":
		m.followPointerAt(rawBytes(m.rawData), m.pointerWordStart(uint64(m.rawCur), m.rawCur))
	case "A":
		m.copyToClipboard(fmt.Sprintf("0x%x", m.rawCur), "offset")
	case "S":
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
		m.rawCur = m.seekNonZero(rawBytes(m.rawData), m.rawCur, true)
	case "{", "shift+[":
		m.rawCur = m.seekNonZero(rawBytes(m.rawData), m.rawCur, false)
	case "/":
		m.openSearch()
	case "n":
		m.runSearch(true, false)
	case "N":
		m.runSearch(false, false)
	case "e":
		m.toggleSymbolAbbrevAll()
	default:
		m.rawCur = m.moveByteCursor(key, m.rawCur, len(m.rawData))
	}
	return m, nil
}

// seekRawSection moves the raw cursor to the start of the next/previous
// section's file bytes (by file offset), via the offset-sorted index.
func (m *Model) seekRawSection(forward bool) int {
	cur := uint64(m.rawCur)
	secs := m.rawSectionsByOffset()
	best := uint64(0)
	found := false
	if forward {
		i := sort.Search(len(secs), func(i int) bool { return secs[i].Offset > cur })
		if i < len(secs) {
			best, found = secs[i].Offset, true
		}
	} else {
		i := sort.Search(len(secs), func(i int) bool { return secs[i].Offset >= cur })
		if i > 0 {
			best, found = secs[i-1].Offset, true
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

// rawSectionsByOffset returns the file-backed sections sorted by file offset,
// built once and cached (sections are immutable), so the raw view's per-row
// section lookups binary-search instead of scanning all sections each render.
func (m *Model) rawSectionsByOffset() []*binfile.Section {
	if m.rawSecByOff == nil {
		var secs []*binfile.Section
		for i := range m.file.Sections {
			if m.file.Sections[i].FileSize > 0 {
				secs = append(secs, &m.file.Sections[i])
			}
		}
		sort.Slice(secs, func(i, j int) bool { return secs[i].Offset < secs[j].Offset })
		if secs == nil {
			secs = []*binfile.Section{} // cache the "none" result too
		}
		m.rawSecByOff = secs
	}
	return m.rawSecByOff
}

// sectionAtOffset returns the section whose file bytes cover off (binary search
// over the offset-sorted index; well-formed section file ranges don't overlap).
func (m *Model) sectionAtOffset(off uint64) *binfile.Section {
	secs := m.rawSectionsByOffset()
	i := sort.Search(len(secs), func(i int) bool { return secs[i].Offset > off })
	if i == 0 {
		return nil
	}
	s := secs[i-1]
	if off < s.Offset+s.FileSize {
		return s
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
	if m.hexInspect {
		banner = m.inspectorBanner(m.hexImg, m.hexCur,
			fmt.Sprintf(" 0x%0*x", m.file.AddrHexWidth(), m.hexImg.AddrAt(m.hexCur)))
	}
	return m.renderHexDump(modeHex, m.hexImg, m.hexCur, &m.hexTop, m.hexImg.AddrAt, banner)
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
	if m.hexInspect {
		banner = m.inspectorBanner(rawBytes(m.rawData), m.rawCur, fmt.Sprintf(" +0x%x", m.rawCur))
	}
	return m.renderHexDump(modeRaw, rawBytes(m.rawData), m.rawCur, &m.rawTop, identityAddr, banner)
}

// renderHexDump draws a classic offset|hex|ascii table. addrAt maps a byte
// position to the address shown at the start of its row, so the same renderer
// serves both the VA image and the raw file view.
func (m *Model) renderHexDump(md mode, data byteSource, cur int, topPtr *int, addrAt func(pos int) uint64, banner string) string {
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

	// When wrap is on, a wide row (pointer decode, inspector, long trailing
	// symbols) reflows under a hanging indent aligned with the annotation column.
	// That indent is clamped to always leave a usable continuation width, so it
	// can't collapse to 1-char lines on a narrow terminal. The section-separator
	// divider is decorative and always truncates.
	rowIndent := m.hexWrapIndent(addrW)
	if lim := m.width - 24; rowIndent > lim {
		rowIndent = max(0, lim)
	}
	rows := []string{m.theme.stickyTitleLine(banner, m.width)}
	for off := top; off < data.Len() && len(rows) < bodyH; {
		if sec := m.hexSectionStartName(md, off); sec != "" {
			appendRenderedRows(
				&rows,
				m.theme.sectionStyle.Render(lipgloss.PlaceHorizontal(
					addrW+73,
					lipgloss.Center,
					" "+sec+" ",
					lipgloss.WithWhitespaceChars("="),
				)),
				m.width, false, bodyH,
			)
		}
		row := m.hexRowSpan(md, data, off, addrAt)
		if !appendRenderedRowsIndented(
			&rows,
			m.renderHexRow(md, data, cur, row, addrW, addrAt),
			m.width, m.wrap, rowIndent, bodyH,
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

func (m *Model) hexRowSpan(md mode, data byteSource, start int, addrAt func(pos int) uint64) hexRowSpan {
	addr := addrAt(start)
	lead := int(addr % bytesPerHexRow)
	lineAddr := addr - uint64(lead)
	end := min(start+bytesPerHexRow-lead, data.Len())
	if next, ok := m.nextHexSectionStart(md, start); ok && next < end {
		end = next
	}
	if end <= start {
		end = min(start+1, data.Len())
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
func (m *Model) hexMaxTop(md mode, data byteSource, visibleRows int, addrAt func(pos int) uint64) int {
	if data.Len() == 0 {
		return 0
	}
	top := m.hexRowTop(md, data.Len()-1, addrAt)
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
	secs := m.rawSectionsByOffset()
	i := sort.Search(len(secs), func(i int) bool { return secs[i].Offset >= uint64(off) })
	if i < len(secs) && secs[i].Offset == uint64(off) {
		return secs[i].Name
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
	if md == modeHex {
		// Regions are sorted by Off, so binary-search the first one past off.
		regs := m.hexImg.Regions
		i := sort.Search(len(regs), func(i int) bool { return regs[i].Off > off })
		if i < len(regs) {
			return regs[i].Off, true
		}
		return 0, false
	}
	// Raw: file-section offsets, indexed sorted once (see rawSectionsByOffset).
	secs := m.rawSectionsByOffset()
	i := sort.Search(len(secs), func(i int) bool { return secs[i].Offset > uint64(off) })
	if i < len(secs) {
		return int(secs[i].Offset), true
	}
	return 0, false
}

// hexWordDecode renders a row's pointer-sized little-/big-endian words (per the
// binary's word size and byte order), resolving each word that points into a
// mapped region to the symbol or section it targets. Only whole words present in
// the row are shown; partial words at a section edge are skipped.
// pointerSize is the binary's pointer width in bytes (8 for 64-bit, 4 for 32).
func (m *Model) pointerSize() int {
	if size := m.file.AddrHexWidth() / 2; size >= 4 {
		return size
	}
	return 4
}

// readPointer reads a pointer-sized word at data[pos:] in the binary's byte
// order, reporting false when the word doesn't fully fit.
func (m *Model) readPointer(data byteSource, pos int) (uint64, bool) {
	size := m.pointerSize()
	if pos < 0 || pos+size > data.Len() {
		return 0, false
	}
	var v uint64
	if m.file.Info != nil && m.file.Info.ByteOrder == "big-endian" {
		for k := 0; k < size; k++ {
			v = v<<8 | uint64(data.At(pos+k))
		}
	} else {
		for k := size - 1; k >= 0; k-- {
			v = v<<8 | uint64(data.At(pos+k))
		}
	}
	return v, true
}

func (m *Model) hexWordDecode(data byteSource, span hexRowSpan, cur int) string {
	size := m.pointerSize()
	var words, notes []string
	for slot := 0; slot+size <= bytesPerHexRow; slot += size {
		i := span.start + slot - span.lead
		if slot < span.lead || i < span.start || i+size > span.end {
			continue
		}
		v, ok := m.readPointer(data, i)
		if !ok {
			continue
		}
		// Three tiers: plain data keeps the muted number colour; a word that points
		// into the binary gets the mapped-pointer colour; and the word under the
		// cursor — the one Enter follows / v copies — the brighter link colour. Each
		// word's → target is drawn in the same colour so they read as a pair.
		onCursor := cur >= i && cur < i+size
		style := m.theme.asmNumberStyle
		if v != 0 && m.file.IsMapped(v) {
			style = m.theme.hexPointerStyle
			if onCursor {
				style = m.theme.linkAddrInterStyle
			}
			if name := m.targetAnnotation(v); name != "" && !m.cfg.Behavior.HideAnnotations {
				notes = append(notes, style.Render(name))
			}
		}
		words = append(words, style.Render(fmt.Sprintf("0x%0*x", size*2, v)))
	}
	out := strings.Join(words, " ")
	if len(notes) > 0 {
		out += "  " + m.theme.addrStyle.Render("→ ") + strings.Join(notes, m.theme.addrStyle.Render(", "))
	}
	return out
}

// pointerWordStart aligns a byte position down to the pointer-word boundary on
// the address grid — matching the decode columns — so follow/copy act on the
// same aligned word the cursor highlights, not a word read mid-cursor.
func (m *Model) pointerWordStart(addr uint64, pos int) int {
	off := int(addr % uint64(m.pointerSize()))
	if off > pos {
		return pos
	}
	return pos - off
}

func (m *Model) renderHexRow(md mode, data byteSource, cur int, span hexRowSpan, addrW int, addrAt func(pos int) uint64) string {
	row := data.Bytes(span.start, span.end) // one zero-copy fetch; indexed natively below
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
		b := row[i-span.start]
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
	fmt.Fprintf(&line, " %s  %s  ",
		m.theme.addrStyle.Render(fmt.Sprintf("0x%0*x", addrW, span.lineAddr)),
		hexCol.String(),
	)
	if m.hexWords {
		line.WriteString(m.hexWordDecode(data, span, cur))
	} else {
		line.WriteString("|")
		line.WriteString(asciiCol.String())
		line.WriteString("|")
	}
	// The trailing symbol/section annotation is only useful in the ASCII view; in
	// pointer mode the row already carries the word decode and its → targets, so
	// the extra annotation just adds noise and width.
	if md == modeHex && !m.hexWords && !m.cfg.Behavior.HideAnnotations {
		addr := addrAt(span.start)
		endAddr := addr + uint64(span.end-span.start)
		if syms := m.file.SymbolsInRange(addr, endAddr); len(syms) != 0 {
			for _, sym := range syms {
				line.WriteString(" [")
				line.WriteString(m.theme.addrStyle.Render(m.displaySymbolName(sym)))
				line.WriteString("]")
			}
		} else if sec := m.file.SectionAt(addr); sec != nil && sec.Addr == addr {
			line.WriteString("  ")
			line.WriteString(m.theme.addrStyle.Render(sec.Name))
		}
	}
	return line.String()
}
