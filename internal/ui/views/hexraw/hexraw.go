// Package hexraw implements the Hex and Raw byte-dump views. Hex renders a
// continuous virtual-address image of mapped sections; Raw renders the complete
// file by file offset. They share row layout, pointer decoding, navigation,
// section pinning and mouse geometry.
package hexraw

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/shellcell/exex/internal/binfile"
	"github.com/shellcell/exex/internal/ui/layout"
	"github.com/shellcell/exex/internal/ui/view"
)

// Mode selects which byte source a method operates on.
type Mode uint8

const (
	Hex Mode = iota
	Raw
)

// ByteSource is the random-access byte stream the hex/raw views read from. It
// abstracts over the raw file bytes (a flat slice) and the virtual-address Image
// (region-backed, zero-copy slices into the file).
type ByteSource interface {
	Len() int
	At(i int) byte
	Bytes(start, end int) []byte
	Runs() []binfile.Run
}

// RawBytes adapts a flat byte slice (the raw-file view) to ByteSource. It is a
// single run spanning the whole slice.
type RawBytes []byte

func (r RawBytes) Len() int                    { return len(r) }
func (r RawBytes) At(i int) byte               { return r[i] }
func (r RawBytes) Bytes(start, end int) []byte { return r[start:end] }
func (r RawBytes) Runs() []binfile.Run         { return []binfile.Run{{Off: 0, B: r}} }

// State stores Hex/Raw cursors, lazy byte sources, section indexes, and shared
// display toggles.
type State struct {
	HexImg         *binfile.Image
	HexCur         int
	HexTop         int
	HexRenderedTop int
	HexPinnedTop   int
	HexPinned      bool

	RawData        []byte
	RawCur         int
	RawTop         int
	RawRenderedTop int
	RawPinnedTop   int
	RawPinned      bool
	rawSecByOff    []*binfile.Section

	Numeric bool // trailing column: numeric interpretation instead of ASCII
	Interp  int  // index into hexInterps; -1 means pointer-width hex
	Inspect bool // show the data inspector banner

	// rowCache memoizes rendered rows (see rowKey). A row is a fair amount of
	// work — the address, the cursor cell, the pointer/symbol annotations — and
	// Bubble Tea redraws every row on every message, though moving the caret
	// changes only the two rows it left and entered. Colour-bearing: dropped by
	// DropCaches on a theme change.
	rowCache layout.RowMemo[rowKey, string]
}

// rowKey identifies a rendered row: its position, plus every input that changes
// how it draws. cursor is the caret's offset within the row, or -1 when the
// caret is elsewhere — so moving the caret invalidates only the rows it touches,
// not the screen.
type rowKey struct {
	pos     int
	mode    Mode
	addrW   int
	bpr     int
	cursor  int
	interp  int
	numeric bool
	ann     bool
}

// DropCaches discards the memoised rows (a theme change restyles them all).
func (st *State) DropCaches() { st.rowCache = nil }

// NewState returns a State with the numeric interpretation lazily resolved to
// the binary pointer width on first use.
func NewState() State { return State{Interp: -1} }

// BytesPerRow is how many bytes each Hex/Raw row shows, from the preference (8,
// 16 or 32; anything else falls back to the default).
func BytesPerRow(ctx *view.Context) int {
	switch ctx.HexBytesPerRow {
	case 8, 16, 32:
		return ctx.HexBytesPerRow
	}
	return bytesPerHexRow
}

// SnapTops realigns scroll anchors after a bytes-per-row setting change.
func (st *State) SnapTops(bpr int) {
	if bpr <= 0 {
		bpr = bytesPerHexRow
	}
	st.HexTop = (st.HexTop / bpr) * bpr
	st.RawTop = (st.RawTop / bpr) * bpr
}

// EnsureHex builds the virtual-address image lazily.
func (st *State) EnsureHex(ctx *view.Context) {
	if st.HexImg == nil {
		st.HexImg = ctx.File.VAImage()
	}
}

// EnsureRaw grabs the whole-file byte slice lazily.
func (st *State) EnsureRaw(ctx *view.Context) {
	if st.RawData == nil {
		st.RawData = ctx.File.Raw()
	}
}

// PositionHexAt parks the Hex cursor on addr. It reports false when addr is not
// inside any mapped section.
func (st *State) PositionHexAt(ctx *view.Context, host view.Host, addr uint64) bool {
	st.EnsureHex(ctx)
	pos, ok := st.HexImg.PosForAddr(addr)
	if !ok {
		host.SetStatus(fmt.Sprintf("0x%x is not in any mapped section", addr), true)
		return false
	}
	st.HexCur = pos
	bpr := BytesPerRow(ctx)
	st.HexTop = (pos / bpr) * bpr
	if sec := ctx.File.SectionAt(addr); sec != nil && sec.Addr == addr {
		st.HexTop = pos
	}
	st.HexRenderedTop = st.HexTop
	st.PinCurrentSectionStart(ctx, Hex)
	return true
}

// PositionRawAt parks the Raw cursor on file offset off, clamping invalid offsets
// to the start of the file.
func (st *State) PositionRawAt(ctx *view.Context, off uint64) {
	st.EnsureRaw(ctx)
	pos := int(off)
	if pos < 0 || pos >= len(st.RawData) {
		pos = 0
	}
	st.RawCur = pos
	bpr := BytesPerRow(ctx)
	st.RawTop = (pos / bpr) * bpr
	if sec := st.SectionAtOffset(ctx.File, off); sec != nil && sec.Offset == off {
		st.RawTop = pos
	}
	st.RawRenderedTop = st.RawTop
	st.PinCurrentSectionStart(ctx, Raw)
}

// HexCaretAddr returns the virtual address under the Hex cursor, for the shell's
// cross-view "open caret in…" jump. ok is false before the image is built.
func (st *State) HexCaretAddr() (uint64, bool) {
	if st.HexImg == nil {
		return 0, false
	}
	return st.HexImg.AddrAt(st.HexCur), true
}

// RawCaretOffset returns the file offset under the Raw cursor (RawCur indexes the
// file bytes directly).
func (st *State) RawCaretOffset() uint64 { return uint64(st.RawCur) }

// CaretPointer returns the pointer-width word under the caret of the given mode,
// aligned to the pointer-word boundary exactly like the follow-pointer action —
// so pressing f mid-pointer searches for the same value Enter would follow. ok is
// false when the word is out of range (the value need not be a mapped address:
// any word is searchable).
func (st *State) CaretPointer(ctx *view.Context, md Mode) (uint64, bool) {
	data, cur, ok := st.activeData(ctx, md)
	if !ok || data.Len() == 0 {
		return 0, false
	}
	var addr uint64
	if md == Hex {
		addr = st.HexImg.AddrAt(cur)
	} else {
		addr = uint64(cur)
	}
	return st.readPointer(ctx, data, st.pointerWordStart(ctx, addr, cur))
}

// Update handles keys local to the Hex/Raw byte views. Shell-owned search keys
// and symbol-name abbreviation are intercepted by the shell adapter.
func (st *State) Update(ctx *view.Context, host view.Host, md Mode, key string) {
	data, cur, ok := st.activeData(ctx, md)
	if !ok || data.Len() == 0 {
		return
	}
	switch md {
	case Hex:
		st.updateHex(ctx, host, data, key)
	case Raw:
		st.updateRaw(ctx, host, data, key)
	default:
		_ = cur
	}
}

func (st *State) updateHex(ctx *view.Context, host view.Host, data ByteSource, key string) {
	switch key {
	case "d":
		host.JumpDisasmAtAddr(st.HexImg.AddrAt(st.HexCur))
	case "m":
		host.JumpRawAtAddr(st.HexImg.AddrAt(st.HexCur))
	case "w":
		host.ToggleWrap()
	case "t":
		st.toggleWords(ctx, host)
	case "T":
		st.cycleInterp(ctx, host)
	case "i":
		st.toggleInspect(host)
	case "P":
		st.copyPointerAt(ctx, host, data, st.pointerWordStart(ctx, st.HexImg.AddrAt(st.HexCur), st.HexCur))
	case "enter":
		st.followPointerAt(ctx, host, data, st.pointerWordStart(ctx, st.HexImg.AddrAt(st.HexCur), st.HexCur))
	case "A":
		addr := st.HexImg.AddrAt(st.HexCur)
		host.CopyToClipboard(fmt.Sprintf("0x%0*x", ctx.File.AddrHexWidth(), addr), "address")
	case "S":
		addr := st.HexImg.AddrAt(st.HexCur)
		if sym, ok := ctx.File.SymbolAt(addr); ok {
			host.CopyToClipboard(sym.Name, "symbol")
		} else {
			host.SetStatus("no symbol at this address", true)
		}
	case "]":
		st.jumpCursor(ctx, Hex, st.seekHexSection(ctx, host, true))
	case "[":
		st.jumpCursor(ctx, Hex, st.seekHexSection(ctx, host, false))
	case "}", "shift+]":
		st.HexCur = st.seekNonZero(host, data, st.HexCur, true)
	case "{", "shift+[":
		st.HexCur = st.seekNonZero(host, data, st.HexCur, false)
	default:
		st.HexCur = st.moveCursor(ctx, key, st.HexCur, data.Len())
	}
}

func (st *State) updateRaw(ctx *view.Context, host view.Host, data ByteSource, key string) {
	switch key {
	case "d":
		if ctx.AddrForOffset != nil {
			if addr, ok := ctx.AddrForOffset(uint64(st.RawCur)); ok {
				host.JumpDisasmAtAddr(addr)
			} else {
				host.SetStatus("offset has no mapped address", true)
			}
		}
	case "h":
		if ctx.AddrForOffset != nil {
			if addr, ok := ctx.AddrForOffset(uint64(st.RawCur)); ok {
				host.JumpHexAtAddr(addr)
			} else {
				host.SetStatus("offset has no mapped address", true)
			}
		}
	case "w":
		host.ToggleWrap()
	case "t":
		st.toggleWords(ctx, host)
	case "T":
		st.cycleInterp(ctx, host)
	case "i":
		st.toggleInspect(host)
	case "P":
		st.copyPointerAt(ctx, host, data, st.pointerWordStart(ctx, uint64(st.RawCur), st.RawCur))
	case "enter":
		st.followPointerAt(ctx, host, data, st.pointerWordStart(ctx, uint64(st.RawCur), st.RawCur))
	case "A":
		host.CopyToClipboard(fmt.Sprintf("0x%x", st.RawCur), "offset")
	case "S":
		if sec := st.SectionAtOffset(ctx.File, uint64(st.RawCur)); sec != nil {
			host.CopyToClipboard(sec.Name, "section name")
		} else {
			host.SetStatus("offset is not inside any section's file data", true)
		}
	case "]":
		st.jumpCursor(ctx, Raw, st.seekRawSection(ctx, host, true))
	case "[":
		st.jumpCursor(ctx, Raw, st.seekRawSection(ctx, host, false))
	case "}", "shift+]":
		st.RawCur = st.seekNonZero(host, data, st.RawCur, true)
	case "{", "shift+[":
		st.RawCur = st.seekNonZero(host, data, st.RawCur, false)
	default:
		st.RawCur = st.moveCursor(ctx, key, st.RawCur, data.Len())
	}
}

// Render draws either byte view.
func (st *State) Render(ctx *view.Context, md Mode) string {
	switch md {
	case Hex:
		return st.renderHex(ctx)
	case Raw:
		return st.renderRaw(ctx)
	}
	return ""
}

func (st *State) renderHex(ctx *view.Context) string {
	st.EnsureHex(ctx)
	if st.HexImg.Len() == 0 {
		return ctx.EmptyBody("no mapped sections to display")
	}
	banner := fmt.Sprintf(" virtual-address image · %d bytes · %d mapped sections",
		st.HexImg.Len(), len(st.HexImg.Regions))
	if r := st.HexImg.RegionAt(st.HexCur); r != nil {
		banner = fmt.Sprintf(" %s   @ 0x%0*x   ·   %d bytes across %d mapped sections",
			r.Name, ctx.File.AddrHexWidth(), st.HexImg.AddrAt(st.HexCur), st.HexImg.Len(), len(st.HexImg.Regions))
	}
	if st.Inspect {
		banner = st.inspectorBanner(ctx, st.HexImg, st.HexCur,
			fmt.Sprintf(" 0x%0*x", ctx.File.AddrHexWidth(), st.HexImg.AddrAt(st.HexCur)))
	} else if ctx.File.SyntheticAddrs() {
		banner += "  ·  ~synthetic (real = section+offset)"
	}
	return st.renderDump(ctx, Hex, st.HexImg, st.HexCur, &st.HexTop, st.HexImg.AddrAt, banner)
}

func (st *State) renderRaw(ctx *view.Context) string {
	st.EnsureRaw(ctx)
	if len(st.RawData) == 0 {
		return layout.PadBody("empty file\n", ctx.Width, ctx.BodyH)
	}
	banner := fmt.Sprintf(" raw file · %d bytes · file offsets", len(st.RawData))
	if sec := st.SectionAtOffset(ctx.File, uint64(st.RawCur)); sec != nil {
		banner = fmt.Sprintf(" raw file · offset 0x%x · in %s · %d bytes total",
			st.RawCur, sec.Name, len(st.RawData))
	}
	if st.Inspect {
		banner = st.inspectorBanner(ctx, RawBytes(st.RawData), st.RawCur, fmt.Sprintf(" +0x%x", st.RawCur))
	}
	return st.renderDump(ctx, Raw, RawBytes(st.RawData), st.RawCur, &st.RawTop, IdentityAddr, banner)
}

// RowText returns the plain text for the current byte row (copy-line action).
func (st *State) RowText(ctx *view.Context, md Mode) string {
	data, cur, ok := st.activeData(ctx, md)
	if !ok || data.Len() == 0 {
		return ""
	}
	addrAt := IdentityAddr
	if md == Hex {
		addrAt = st.HexImg.AddrAt
	}
	start := st.rowTop(ctx, md, cur, addrAt)
	span := st.rowSpan(ctx, md, data, start, addrAt)
	return ansi.Strip(st.renderRow(ctx, md, data, cur, span, ctx.File.AddrHexWidth(), addrAt))
}

// Scroll moves the active byte viewport by delta rows.
func (st *State) Scroll(ctx *view.Context, md Mode, delta int) {
	if delta == 0 {
		return
	}
	switch md {
	case Hex:
		st.EnsureHex(ctx)
		st.clearPin(Hex)
		st.HexTop = st.scrollViewportTop(ctx, Hex, st.HexImg, st.HexTop, max(1, ctx.BodyH-1), delta, st.HexImg.AddrAt)
	case Raw:
		st.EnsureRaw(ctx)
		st.clearPin(Raw)
		st.RawTop = st.scrollViewportTop(ctx, Raw, RawBytes(st.RawData), st.RawTop, max(1, ctx.BodyH-1), delta, IdentityAddr)
	}
}

// CaptureViewportTop normalizes the active viewport top to the last rendered top
// before independent wheel scrolling starts.
func (st *State) CaptureViewportTop(ctx *view.Context, md Mode) {
	switch md {
	case Hex:
		st.EnsureHex(ctx)
		st.HexTop = st.scrollViewportTop(ctx, Hex, st.HexImg, st.HexRenderedTop, max(1, ctx.BodyH-1), 0, st.HexImg.AddrAt)
	case Raw:
		st.EnsureRaw(ctx)
		st.RawTop = st.scrollViewportTop(ctx, Raw, RawBytes(st.RawData), st.RawRenderedTop, max(1, ctx.BodyH-1), 0, IdentityAddr)
	}
}

// Click maps a click in a byte view onto the byte cursor.
func (st *State) Click(ctx *view.Context, md Mode, x, bodyRow int) {
	switch md {
	case Hex:
		st.EnsureHex(ctx)
		top := st.visibleTop(ctx, Hex, st.HexCur, st.HexTop, max(1, ctx.BodyH-1), st.HexImg.AddrAt)
		if ctx.Detached {
			top = st.scrollViewportTop(ctx, Hex, st.HexImg, st.HexTop, max(1, ctx.BodyH-1), 0, st.HexImg.AddrAt)
		}
		st.HexCur = st.clickByte(ctx, Hex, st.HexImg, top, st.HexCur, x, bodyRow, st.HexImg.AddrAt)
	case Raw:
		st.EnsureRaw(ctx)
		top := st.visibleTop(ctx, Raw, st.RawCur, st.RawTop, max(1, ctx.BodyH-1), IdentityAddr)
		if ctx.Detached {
			top = st.scrollViewportTop(ctx, Raw, RawBytes(st.RawData), st.RawTop, max(1, ctx.BodyH-1), 0, IdentityAddr)
		}
		st.RawCur = st.clickByte(ctx, Raw, RawBytes(st.RawData), top, st.RawCur, x, bodyRow, IdentityAddr)
	}
}

// Data returns the byte source and cursor for search helpers.
func (st *State) Data(ctx *view.Context, md Mode) (ByteSource, int, bool) {
	return st.activeData(ctx, md)
}

// SetCursor updates a byte cursor after a search match.
func (st *State) SetCursor(md Mode, cur int) {
	switch md {
	case Hex:
		st.HexCur = cur
	case Raw:
		st.RawCur = cur
	}
}

func (st *State) activeData(ctx *view.Context, md Mode) (ByteSource, int, bool) {
	switch md {
	case Hex:
		st.EnsureHex(ctx)
		return st.HexImg, st.HexCur, true
	case Raw:
		st.EnsureRaw(ctx)
		return RawBytes(st.RawData), st.RawCur, true
	}
	return nil, 0, false
}

// SectionAtOffset returns the section whose file bytes cover off (binary search
// over the offset-sorted index; well-formed section file ranges don't overlap).
func (st *State) SectionAtOffset(f *binfile.File, off uint64) *binfile.Section {
	secs := st.rawSectionsByOffset(f)
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

// rawSectionsByOffset returns the file-backed sections sorted by file offset,
// built once and cached (sections are immutable), so the raw view's per-row
// section lookups binary-search instead of scanning all sections each render.
func (st *State) rawSectionsByOffset(f *binfile.File) []*binfile.Section {
	if st.rawSecByOff == nil {
		var secs []*binfile.Section
		for i := range f.Sections {
			if f.Sections[i].FileSize > 0 {
				secs = append(secs, &f.Sections[i])
			}
		}
		sort.Slice(secs, func(i, j int) bool { return secs[i].Offset < secs[j].Offset })
		if secs == nil {
			secs = []*binfile.Section{} // cache the "none" result too
		}
		st.rawSecByOff = secs
	}
	return st.rawSecByOff
}

// IdentityAddr is the addrAt mapping for the raw file view, where a byte's
// "address" is just its file offset.
func IdentityAddr(pos int) uint64 { return uint64(pos) }

const bytesPerHexRow = 16

// Hex row layout, shared by renderRow (drawing) and ColumnToByte (hit-testing).
func bodyStart(addrW int) int { return 1 + 2 + addrW + 2 }

func gridWidth(bpr int) int { return bpr*2 + (bpr - 1) + 1 }

func wrapIndent(ctx *view.Context, numeric bool, addrW int) int {
	bpr := BytesPerRow(ctx)
	col := bodyStart(addrW) + gridWidth(bpr) + 2 // start of the ascii / word column
	if !numeric {
		col += bpr + 2 // skip the |ascii| column to the symbol annotations
	}
	return col
}

// ColumnToByte maps a screen column x to a byte index [0, bpr).
func ColumnToByte(addrW, bpr, x int) int {
	rel := x - bodyStart(addrW)
	if rel < 0 {
		return 0
	}
	col := rel / 3
	// Bytes past the midpoint are shifted right by the extra separating space.
	if rel >= (bpr/2)*3+1 {
		col = (rel - 1) / 3
	}
	if col > bpr-1 {
		col = bpr - 1
	}
	return col
}

func (st *State) renderDump(ctx *view.Context, md Mode, data ByteSource, cur int, topPtr *int, addrAt func(pos int) uint64, banner string) string {
	bodyH := ctx.BodyH
	addrW := ctx.File.AddrHexWidth()
	visible := max(bodyH-1, 1)
	top := st.visibleTop(ctx, md, cur, *topPtr, visible, addrAt)
	if ctx.Detached {
		top = st.scrollViewportTop(ctx, md, data, *topPtr, visible, 0, addrAt)
	} else if secStart, ok := st.currentSectionStart(ctx, md, cur); ok && top < secStart && secStart <= cur {
		top = secStart
	}
	if pinned, ok := st.pinnedTop(md); ok && top < pinned && cur >= pinned {
		top = pinned
	}
	*topPtr = top
	if md == Raw {
		st.RawRenderedTop = top
	} else {
		st.HexRenderedTop = top
	}

	// When wrap is on, a wide row (pointer decode, inspector, long trailing
	// symbols) reflows under a hanging indent aligned with the annotation column.
	rowIndent := wrapIndent(ctx, st.Numeric, addrW)
	if lim := ctx.Width - 24; rowIndent > lim {
		rowIndent = max(0, lim)
	}
	rows := []string{renderStyleLine(banner, ctx.Width, ctx.StickyStyle)}
	for off := top; off < data.Len() && len(rows) < bodyH; {
		if sec := st.sectionStartName(ctx, md, off); sec != "" {
			layout.AppendRenderedRows(
				&rows,
				ctx.BannerStyle.Render(lipgloss.PlaceHorizontal(
					addrW+73,
					lipgloss.Center,
					" "+sec+" ",
					lipgloss.WithWhitespaceChars("="),
				)),
				ctx.Width, false, bodyH,
			)
		}
		row := st.rowSpan(ctx, md, data, off, addrAt)
		if !layout.AppendRenderedRowsIndented(
			&rows,
			st.renderRow(ctx, md, data, cur, row, addrW, addrAt),
			ctx.Width, ctx.Wrap, rowIndent, bodyH,
		) {
			break
		}
		off = row.end
	}
	return layout.PadBodyRows(rows, ctx.Width, bodyH)
}

type rowSpan struct {
	start    int
	end      int
	lineAddr uint64
	lead     int
}

func (st *State) rowSpan(ctx *view.Context, md Mode, data ByteSource, start int, addrAt func(pos int) uint64) rowSpan {
	bpr := BytesPerRow(ctx)
	addr := addrAt(start)
	lead := int(addr % uint64(bpr))
	lineAddr := addr - uint64(lead)
	end := min(start+bpr-lead, data.Len())
	if next, ok := st.nextSectionStart(ctx, md, start); ok && next < end {
		end = next
	}
	if end <= start {
		end = min(start+1, data.Len())
	}
	return rowSpan{start: start, end: end, lineAddr: lineAddr, lead: lead}
}

// rowTop returns the byte position of the start of the row containing pos.
func (st *State) rowTop(ctx *view.Context, md Mode, pos int, addrAt func(pos int) uint64) int {
	if pos <= 0 {
		return 0
	}
	start := pos - int(addrAt(pos)%uint64(BytesPerRow(ctx)))
	if secStart, ok := st.currentSectionStart(ctx, md, pos); ok && start < secStart {
		start = secStart
	}
	if start < 0 {
		return 0
	}
	return start
}

func (st *State) prevRowTop(ctx *view.Context, md Mode, pos int, addrAt func(pos int) uint64) int {
	rs := st.rowTop(ctx, md, pos, addrAt)
	if rs <= 0 {
		return 0
	}
	return st.rowTop(ctx, md, rs-1, addrAt)
}

func (st *State) maxTop(ctx *view.Context, md Mode, data ByteSource, visibleRows int, addrAt func(pos int) uint64) int {
	if data.Len() == 0 {
		return 0
	}
	top := st.rowTop(ctx, md, data.Len()-1, addrAt)
	for i := 0; i < visibleRows-1 && top > 0; i++ {
		top = st.prevRowTop(ctx, md, top, addrAt)
	}
	return top
}

func (st *State) visibleTop(ctx *view.Context, md Mode, cur, top, visibleRows int, addrAt func(pos int) uint64) int {
	if visibleRows < 1 {
		visibleRows = 1
	}
	top = st.rowTop(ctx, md, top, addrAt)
	curStart := st.rowTop(ctx, md, cur, addrAt)
	if curStart <= top {
		return curStart
	}
	limit := curStart
	for i := 0; i < visibleRows-1 && limit > 0; i++ {
		limit = st.prevRowTop(ctx, md, limit, addrAt)
	}
	if top < limit {
		return limit
	}
	return top
}

func (st *State) sectionName(ctx *view.Context, md Mode, off int, addrAt func(pos int) uint64) string {
	if md == Hex {
		if sec := ctx.File.SectionAt(addrAt(off)); sec != nil {
			return sec.Name
		}
		return ""
	}
	if sec := st.SectionAtOffset(ctx.File, uint64(off)); sec != nil {
		return sec.Name
	}
	return ""
}

func (st *State) sectionStartName(ctx *view.Context, md Mode, off int) string {
	if off < 0 {
		return ""
	}
	lmaNote := func(phys uint64) string {
		if ctx.LMANote != nil {
			return ctx.LMANote(phys)
		}
		if phys == 0 {
			return ""
		}
		return fmt.Sprintf("   LMA 0x%0*x", ctx.File.AddrHexWidth(), phys)
	}
	if md == Hex {
		if r := st.HexImg.RegionAt(off); r != nil && r.Off == off {
			name := r.Name
			if sec := ctx.File.SectionAt(r.Addr); sec != nil {
				name += lmaNote(sec.PhysAddr)
			}
			return name
		}
		return ""
	}
	secs := st.rawSectionsByOffset(ctx.File)
	i := sort.Search(len(secs), func(i int) bool { return secs[i].Offset >= uint64(off) })
	if i < len(secs) && secs[i].Offset == uint64(off) {
		return secs[i].Name + lmaNote(secs[i].PhysAddr)
	}
	return ""
}

func (st *State) currentSectionStart(ctx *view.Context, md Mode, cur int) (int, bool) {
	if cur < 0 {
		return 0, false
	}
	if md == Hex {
		if r := st.HexImg.RegionAt(cur); r != nil {
			return r.Off, true
		}
		return 0, false
	}
	sec := st.SectionAtOffset(ctx.File, uint64(cur))
	if sec == nil || sec.Offset > uint64(int(^uint(0)>>1)) {
		return 0, false
	}
	return int(sec.Offset), true
}

// PinCurrentSectionStart pins a section separator when the cursor is exactly on a
// section start, preserving the old jump/search landing behavior.
func (st *State) PinCurrentSectionStart(ctx *view.Context, md Mode) {
	switch md {
	case Hex:
		if start, ok := st.currentSectionStart(ctx, Hex, st.HexCur); ok && start == st.HexCur {
			st.HexPinnedTop = start
			st.HexPinned = true
			return
		}
		st.HexPinned = false
	case Raw:
		if start, ok := st.currentSectionStart(ctx, Raw, st.RawCur); ok && start == st.RawCur {
			st.RawPinnedTop = start
			st.RawPinned = true
			return
		}
		st.RawPinned = false
	}
}

func (st *State) clearPin(md Mode) {
	switch md {
	case Hex:
		st.HexPinned = false
	case Raw:
		st.RawPinned = false
	}
}

func (st *State) pinnedTop(md Mode) (int, bool) {
	switch md {
	case Hex:
		return st.HexPinnedTop, st.HexPinned
	case Raw:
		return st.RawPinnedTop, st.RawPinned
	}
	return 0, false
}

func (st *State) nextSectionStart(ctx *view.Context, md Mode, off int) (int, bool) {
	if md == Hex {
		regs := st.HexImg.Regions
		i := sort.Search(len(regs), func(i int) bool { return regs[i].Off > off })
		if i < len(regs) {
			return regs[i].Off, true
		}
		return 0, false
	}
	secs := st.rawSectionsByOffset(ctx.File)
	i := sort.Search(len(secs), func(i int) bool { return secs[i].Offset > uint64(off) })
	if i < len(secs) {
		return int(secs[i].Offset), true
	}
	return 0, false
}

func (st *State) scrollViewportTop(ctx *view.Context, md Mode, data ByteSource, top, visibleRows, delta int, addrAt func(pos int) uint64) int {
	n := data.Len()
	if n <= 0 {
		return 0
	}
	top = st.rowTop(ctx, md, top, addrAt)
	for ; delta > 0 && top < n; delta-- {
		next := st.rowSpan(ctx, md, data, top, addrAt).end
		if next >= n || next <= top {
			break
		}
		top = next
	}
	for ; delta < 0 && top > 0; delta++ {
		top = st.prevRowTop(ctx, md, top, addrAt)
	}
	if maxTop := st.maxTop(ctx, md, data, visibleRows, addrAt); top > maxTop {
		top = maxTop
	}
	return top
}

func (st *State) clickByte(ctx *view.Context, md Mode, data ByteSource, top, cur, x, bodyRow int, addrAt func(pos int) uint64) int {
	r := bodyRow - 1 // strip the banner row
	if r < 0 {
		return cur
	}
	bpr := BytesPerRow(ctx)
	emitted := 0
	prevSec := ""
	if top >= bpr {
		prevSec = st.sectionName(ctx, md, top-bpr, addrAt)
	}
	for rowStart := top; rowStart < data.Len(); {
		if sec := st.sectionName(ctx, md, rowStart, addrAt); sec != "" && sec != prevSec {
			if emitted == r {
				return cur // clicked a section-separator row
			}
			emitted++
			prevSec = sec
		} else {
			prevSec = sec
		}
		if emitted == r {
			span := st.rowSpan(ctx, md, data, rowStart, addrAt)
			slot := ColumnToByte(ctx.File.AddrHexWidth(), bpr, x)
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
		rowStart = st.rowSpan(ctx, md, data, rowStart, addrAt).end
	}
	return cur
}

func (st *State) moveCursor(ctx *view.Context, key string, cur, n int) int {
	row := BytesPerRow(ctx)
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
		cur = max(0, cur-row*bytePageRows(ctx))
	case "pgdown":
		cur = min(n-1, cur+row*bytePageRows(ctx))
	case "home", "g g":
		cur = 0
	case "end", "G":
		cur = n - 1
	}
	return cur
}

func bytePageRows(ctx *view.Context) int { return max(1, max(1, ctx.BodyH-1)-1) }

func (st *State) jumpCursor(ctx *view.Context, md Mode, pos int) {
	switch md {
	case Hex:
		if pos == st.HexCur {
			return
		}
		st.HexCur, st.HexTop, st.HexRenderedTop = pos, pos, pos
	case Raw:
		if pos == st.RawCur {
			return
		}
		st.RawCur, st.RawTop, st.RawRenderedTop = pos, pos, pos
	default:
		return
	}
	st.PinCurrentSectionStart(ctx, md)
}

func (st *State) seekHexSection(ctx *view.Context, host view.Host, forward bool) int {
	curAddr := st.HexImg.AddrAt(st.HexCur)
	regs := st.HexImg.Regions
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
	host.SetStatus("no more sections in this direction", false)
	return st.HexCur
}

func (st *State) seekRawSection(ctx *view.Context, host view.Host, forward bool) int {
	cur := uint64(st.RawCur)
	secs := st.rawSectionsByOffset(ctx.File)
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
		host.SetStatus("no more sections in this direction", false)
		return st.RawCur
	}
	if int(best) < len(st.RawData) {
		return int(best)
	}
	return st.RawCur
}

func (st *State) seekNonZero(host view.Host, data ByteSource, cur int, forward bool) int {
	runs := data.Runs()
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
	host.SetStatus("no more non-zero bytes in this direction", false)
	return cur
}

func (st *State) inspectorBanner(ctx *view.Context, data ByteSource, pos int, prefix string) string {
	if pos < 0 || pos >= data.Len() {
		return prefix + "  inspect: (no byte under cursor)"
	}
	be := ctx.File.Info != nil && ctx.File.Info.ByteOrder == "big-endian"
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
	if pv, ok := st.readPointer(ctx, data, pos); ok && pv != 0 && ctx.File.IsMapped(pv) {
		if name := targetAnnotation(ctx, pv); name != "" {
			parts = append(parts, "ptr→ "+name)
		}
	}
	return prefix + "  " + strings.Join(parts, "  ")
}

func (st *State) copyPointerAt(ctx *view.Context, host view.Host, data ByteSource, pos int) {
	v, ok := st.readPointer(ctx, data, pos)
	if !ok {
		host.SetStatus("not enough bytes for a pointer here", true)
		return
	}
	host.CopyToClipboard(fmt.Sprintf("0x%x", v), "pointer")
}

func (st *State) followPointerAt(ctx *view.Context, host view.Host, data ByteSource, pos int) {
	v, ok := st.readPointer(ctx, data, pos)
	if !ok {
		host.SetStatus("not enough bytes for a pointer here", true)
		return
	}
	if v == 0 || !ctx.File.IsMapped(v) {
		host.SetStatus(fmt.Sprintf("0x%x is not a mapped address", v), true)
		return
	}
	host.GotoAddr(v)
}

type interpKind uint8

const (
	interpHex interpKind = iota
	interpUint
	interpSint
	interpFloat
)

type interpDef struct {
	name string
	size int
	kind interpKind
}

var interps = []interpDef{
	{"u8", 1, interpUint}, {"i8", 1, interpSint},
	{"x16", 2, interpHex}, {"u16", 2, interpUint}, {"i16", 2, interpSint},
	{"x32", 4, interpHex}, {"u32", 4, interpUint}, {"i32", 4, interpSint}, {"f32", 4, interpFloat},
	{"x64", 8, interpHex}, {"u64", 8, interpUint}, {"i64", 8, interpSint}, {"f64", 8, interpFloat},
}

func (st *State) curInterp(ctx *view.Context) interpDef {
	if st.Interp < 0 || st.Interp >= len(interps) {
		ps := st.pointerSize(ctx)
		st.Interp = 0
		for i, in := range interps {
			if in.kind == interpHex && in.size == ps {
				st.Interp = i
				break
			}
		}
	}
	return interps[st.Interp]
}

func (st *State) toggleWords(ctx *view.Context, host view.Host) {
	st.Numeric = !st.Numeric
	col := "ascii"
	if st.Numeric {
		col = st.curInterp(ctx).name
	}
	host.SetStatus("hex column: "+col, false)
}

func (st *State) cycleInterp(ctx *view.Context, host view.Host) {
	_ = st.curInterp(ctx)
	st.Numeric = true
	st.Interp = (st.Interp + 1) % len(interps)
	host.SetStatus("hex column: "+interps[st.Interp].name, false)
}

func (st *State) toggleInspect(host view.Host) {
	st.Inspect = !st.Inspect
	state := "off"
	if st.Inspect {
		state = "on"
	}
	host.SetStatus("data inspector: "+state, false)
}

func (st *State) pointerSize(ctx *view.Context) int {
	if size := ctx.File.PointerBytes(); size >= 4 {
		return size
	}
	return 4
}

// ReadPointer reads a pointer-sized word at data[pos:] in the binary's byte order,
// reporting false when the word doesn't fully fit.
func (st *State) ReadPointer(ctx *view.Context, data ByteSource, pos int) (uint64, bool) {
	return st.readPointer(ctx, data, pos)
}

func (st *State) readPointer(ctx *view.Context, data ByteSource, pos int) (uint64, bool) {
	return st.readWord(ctx, data, pos, st.pointerSize(ctx))
}

func (st *State) wordDecode(ctx *view.Context, data ByteSource, span rowSpan, cur int) string {
	in := st.curInterp(ctx)
	size := in.size
	colW := colWidth(in)
	ptr := in.kind == interpHex && size == st.pointerSize(ctx)
	var words, notes []string
	bpr := BytesPerRow(ctx)
	for slot := 0; slot+size <= bpr; slot += size {
		i := span.start + slot - span.lead
		if slot < span.lead || i < span.start || i+size > span.end {
			continue
		}
		v, ok := st.readWord(ctx, data, i, size)
		if !ok {
			continue
		}
		onCursor := cur >= i && cur < i+size
		style := ctx.NumberStyle
		if ptr && v != 0 && ctx.File.IsMapped(v) {
			style = ctx.PtrStyle
			if onCursor {
				style = ctx.LinkStyle
			}
			if name := targetAnnotation(ctx, v); name != "" && !ctx.HideAnnotations {
				notes = append(notes, style.Render(name))
			}
		}
		text := formatWord(in, v)
		if pad := colW - len(text); pad > 0 {
			text = padSpaces[:pad] + text
		}
		words = append(words, style.Render(text))
	}
	out := strings.Join(words, " ")
	if len(notes) > 0 {
		out += "  " + ctx.AddrStyle.Render("→ ") + strings.Join(notes, ctx.AddrStyle.Render(", "))
	}
	return out
}

func (st *State) readWord(ctx *view.Context, data ByteSource, pos, size int) (uint64, bool) {
	if pos < 0 || pos+size > data.Len() {
		return 0, false
	}
	var v uint64
	if ctx.File.Info != nil && ctx.File.Info.ByteOrder == "big-endian" {
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

const padSpaces = "                    "

func colWidth(in interpDef) int {
	switch in.kind {
	case interpHex:
		return in.size*2 + 2
	case interpFloat:
		return 12
	}
	w := 20
	switch in.size {
	case 1:
		w = 3
	case 2:
		w = 5
	case 4:
		w = 10
	}
	if in.kind == interpSint {
		w++
	}
	return w
}

func formatWord(in interpDef, v uint64) string {
	switch in.kind {
	case interpUint:
		return strconv.FormatUint(v, 10)
	case interpSint:
		return strconv.FormatInt(signExtend(v, in.size), 10)
	case interpFloat:
		if in.size == 4 {
			return fmt.Sprintf("%g", math.Float32frombits(uint32(v)))
		}
		return fmt.Sprintf("%g", math.Float64frombits(v))
	default:
		return fmt.Sprintf("0x%0*x", in.size*2, v)
	}
}

func signExtend(v uint64, size int) int64 {
	if size >= 8 {
		return int64(v)
	}
	shift := uint(64 - size*8)
	return int64(v<<shift) >> shift
}

// PointerWordStart aligns a byte position down to the pointer-word boundary on
// the address grid.
func (st *State) PointerWordStart(ctx *view.Context, addr uint64, pos int) int {
	return st.pointerWordStart(ctx, addr, pos)
}

func (st *State) pointerWordStart(ctx *view.Context, addr uint64, pos int) int {
	off := int(addr % uint64(st.pointerSize(ctx)))
	if off > pos {
		return pos
	}
	return pos - off
}

// renderRow returns the rendered row, from the memo when this exact row was
// drawn last frame — which, on a scroll or a caret move, is nearly all of them.
func (st *State) renderRow(ctx *view.Context, md Mode, data ByteSource, cur int, span rowSpan, addrW int, addrAt func(pos int) uint64) string {
	cursor := -1
	if cur >= span.start && cur < span.end {
		cursor = cur - span.start
	}
	key := rowKey{
		pos: span.start, mode: md, addrW: addrW, bpr: BytesPerRow(ctx),
		cursor: cursor, interp: st.Interp, numeric: st.Numeric, ann: ctx.HideAnnotations,
	}
	return st.rowCache.Get(key, func() string {
		return st.buildRow(ctx, md, data, cur, span, addrW, addrAt)
	})
}

func (st *State) buildRow(ctx *view.Context, md Mode, data ByteSource, cur int, span rowSpan, addrW int, addrAt func(pos int) uint64) string {
	row := data.Bytes(span.start, span.end)
	var hexCol, asciiCol strings.Builder
	bpr := BytesPerRow(ctx)
	hexCol.Grow(bpr * 24)
	asciiCol.Grow(bpr * 20)
	for slot := 0; slot < bpr; slot++ {
		if slot > 0 {
			hexCol.WriteByte(' ')
			if slot == bpr/2 {
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
			hexCol.WriteString(ctx.SelStyle.Render(hex2(b)))
			asciiCol.WriteString(ctx.SelStyle.Render(string(ascii)))
		} else {
			hexCol.WriteString(byteHex(ctx, b))
			asciiCol.WriteString(byteASCII(ctx, b))
		}
	}
	var line strings.Builder
	line.Grow(hexCol.Len() + asciiCol.Len() + 48)
	line.WriteByte(' ')
	var addrBuf [18]byte // "0x" + 16 hex digits
	line.WriteString(ctx.AddrStyle.Render(string(layout.AppendAddr(addrBuf[:0], span.lineAddr, addrW))))
	line.WriteString("  ")
	line.WriteString(hexCol.String())
	line.WriteString("  ")
	if st.Numeric {
		line.WriteString(st.wordDecode(ctx, data, span, cur))
	} else {
		line.WriteString("|")
		line.WriteString(asciiCol.String())
		line.WriteString("|")
	}
	if md == Hex && !st.Numeric && !ctx.HideAnnotations {
		addr := addrAt(span.start)
		endAddr := addr + uint64(span.end-span.start)
		if syms := ctx.File.SymbolsInRange(addr, endAddr); len(syms) != 0 {
			for _, sym := range syms {
				line.WriteString(" [")
				line.WriteString(ctx.AddrStyle.Render(symbolDisplay(ctx, sym)))
				line.WriteString("]")
			}
		} else if sec := ctx.File.SectionAt(addr); sec != nil && sec.Addr == addr {
			line.WriteString("  ")
			line.WriteString(ctx.AddrStyle.Render(sec.Name))
		}
	}
	return line.String()
}

func renderStyleLine(s string, w int, st lipgloss.Style) string {
	return layout.RenderStyle(layout.PadRight(layout.FitANSIWidth(s, w), w), w, st)
}

func byteHex(ctx *view.Context, b byte) string {
	if ctx.ByteHex != nil {
		return (*ctx.ByteHex)[b]
	}
	return hex2(b)
}

func byteASCII(ctx *view.Context, b byte) string {
	if ctx.ByteASCII != nil {
		return (*ctx.ByteASCII)[b]
	}
	if b >= 0x20 && b < 0x7f {
		return string(b)
	}
	return "."
}

func hex2(b byte) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[b>>4], digits[b&0xf]})
}

func symbolDisplay(ctx *view.Context, sym binfile.Symbol) string {
	if ctx.SymbolDisplay != nil {
		return ctx.SymbolDisplay(sym)
	}
	return sym.Display()
}

func targetAnnotation(ctx *view.Context, addr uint64) string {
	if ctx.TargetAnnotation != nil {
		return ctx.TargetAnnotation(addr)
	}
	if sym, ok := ctx.File.SymbolAt(addr); ok {
		if addr == sym.Addr {
			return symbolDisplay(ctx, sym)
		}
		return fmt.Sprintf("%s+0x%x", symbolDisplay(ctx, sym), addr-sym.Addr)
	}
	if sec := ctx.File.SectionAt(addr); sec != nil {
		return sec.Name
	}
	return ""
}
