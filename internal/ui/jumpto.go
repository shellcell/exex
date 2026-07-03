package ui

// The "open caret position in…" modal: from any address-bearing view, take the
// address under the cursor and offer to reopen it in each of the other views —
// Disasm, Hex, Raw, Symbols, Sections, Strings, Relocs — each row previewing
// exactly where it would land (the covering function, section, file offset,
// string, or number of relocations there). A header shows what the address *is*
// (its symbol + section, and the pointer it holds when it holds one), turning the
// per-view d/h/m jumps into one discoverable, self-describing menu.

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/ui/layout"
)

// jumpTarget is one row of the modal: a destination view, a preview of where the
// caret address lands there, and whether that landing is possible.
type jumpTarget struct {
	mode    mode
	label   string
	preview string
	enabled bool
}

// modeDigit is the view-switch digit for a mode (matching defaultKeyMap), shown
// as a badge in the modal and usable as a shortcut to jump straight to that view.
func modeDigit(md mode) string {
	switch md {
	case modeInfo:
		return "1"
	case modeSections:
		return "2"
	case modeSymbols:
		return "3"
	case modeDisasm:
		return "4"
	case modeHex:
		return "5"
	case modeRaw:
		return "6"
	case modeStrings:
		return "7"
	case modeLibs:
		return "8"
	case modeSources:
		return "9"
	case modeRelocs:
		return "0"
	}
	return " "
}

// caret is the position under the cursor, expressed as a virtual address, a file
// offset, or both — a string in an unmapped section has only an offset (so it can
// still open in Raw), while a disasm/hex caret has an address (and usually a
// backing offset too).
type caret struct {
	addr    uint64
	hasAddr bool
	off     uint64
	hasOff  bool
}

// fromAddr fills in the file offset backing a virtual address, when it has one.
func (m *Model) caretFromAddr(addr uint64) caret {
	c := caret{addr: addr, hasAddr: true}
	if off, ok := m.fileOffsetForAddr(addr); ok {
		c.off, c.hasOff = off, true
	}
	return c
}

// caretPos returns the position under the cursor of the active view. ok is false
// for views with no address/offset concept (e.g. Info) or an empty selection.
func (m *Model) caretPos() (caret, bool) {
	switch m.mode {
	case modeInfo:
		// Info has no cursor, so open at the binary's natural starting point: its
		// entry point when it has one, else the lowest mapped virtual address.
		if a := m.file.Entry(); a != 0 {
			return m.caretFromAddr(a), true
		}
		if a, ok := m.lowestVirtAddr(); ok {
			return m.caretFromAddr(a), true
		}
	case modeDisasm:
		if len(m.disasmInst) > 0 && m.disasmCur >= 0 && m.disasmCur < len(m.disasmInst) {
			return m.caretFromAddr(m.disasmInst[m.disasmCur].Addr), true
		}
	case modeHex:
		if a, ok := m.byteViews.HexCaretAddr(); ok {
			return m.caretFromAddr(a), true
		}
	case modeRaw:
		off := m.byteViews.RawCaretOffset()
		c := caret{off: off, hasOff: true}
		if a, ok := m.addrForOffset(off); ok {
			c.addr, c.hasAddr = a, true
		}
		return c, true
	case modeSymbols:
		if a, ok := m.symbols.CaretAddr(m.viewContext()); ok {
			return m.caretFromAddr(a), true
		}
	case modeSections:
		if a, ok := m.sections.CaretAddr(); ok {
			return m.caretFromAddr(a), true
		}
	case modeStrings:
		// A string always has a file offset; a virtual address only when it lives in
		// a mapped section (or its offset resolves to one).
		if s, ok := m.strs.Current(); ok {
			c := caret{off: s.Offset, hasOff: true}
			if s.HasAddr && s.Addr != 0 {
				c.addr, c.hasAddr = s.Addr, true
			} else if a, ok := m.addrForOffset(s.Offset); ok {
				c.addr, c.hasAddr = a, true
			}
			return c, true
		}
	case modeRelocs:
		if a, ok := m.relocs.CaretAddr(m.viewContext()); ok {
			return m.caretFromAddr(a), true
		}
	}
	return caret{}, false
}

// openJumpModal builds the target list for the caret position and opens the
// modal, landing the selection on the first reachable target. It reports (without
// opening) when the active view has no position under the cursor, or when nothing
// else can show it.
func (m *Model) openJumpModal() {
	c, ok := m.caretPos()
	if !ok {
		m.setStatus("no address or offset at the caret to open elsewhere", true)
		return
	}
	m.jumpCaret = c
	m.jumpTargets = m.buildJumpTargets(c)
	anyEnabled := false
	m.jumpSel = 0
	for i, t := range m.jumpTargets {
		if t.enabled {
			if !anyEnabled {
				m.jumpSel = i
			}
			anyEnabled = true
		}
	}
	if !anyEnabled {
		m.setStatus("nothing else can open this position", true)
		return
	}
	m.jumpActive = true
}

// buildJumpTargets assembles the destination rows for the caret, skipping the
// view it is already in. Address-keyed targets need c.hasAddr; Raw needs only
// c.hasOff, so an offset-only string can still be opened there. Each row's preview
// and enabled flag come from the same resolution the jump itself will use.
func (m *Model) buildJumpTargets(c caret) []jumpTarget {
	addr := c.addr
	var sym binfile.Symbol
	var hasSym bool
	var sec *binfile.Section
	if c.hasAddr {
		sym, hasSym = m.file.SymbolAt(addr)
		sec = m.file.SectionAt(addr)
	}
	var out []jumpTarget
	add := func(md mode, label, preview string, enabled bool) {
		if md == m.mode {
			return
		}
		out = append(out, jumpTarget{mode: md, label: label, preview: preview, enabled: enabled})
	}

	canDis := c.hasAddr && m.canDisasmAt(addr)
	disEnabled := canDis || (c.hasAddr && m.file.AddrDisassemblable(addr))
	disPrev := "not executable"
	switch {
	case canDis:
		if s := m.symbolDisplayAt(addr); s != "" {
			disPrev = s
		} else if sec != nil {
			disPrev = sec.Name
		} else {
			disPrev = "code"
		}
	case disEnabled:
		disPrev = "decode bytes here" // a non-exec section, via disasm-all
	case !c.hasAddr:
		disPrev = "no virtual address"
	}
	add(modeDisasm, "Disasm", disPrev, disEnabled)

	hexPrev := "no virtual address"
	if sec != nil {
		hexPrev = fmt.Sprintf("0x%x  %s", addr, sec.Name)
	} else if c.hasAddr {
		hexPrev = "unmapped"
	}
	add(modeHex, "Hex", hexPrev, c.hasAddr && addr != 0 && sec != nil)

	rawPrev := "no file bytes"
	if c.hasOff {
		rawPrev = fmt.Sprintf("offset 0x%x", c.off)
	}
	add(modeRaw, "Raw", rawPrev, c.hasOff)

	symPrev := "no symbol here"
	if !c.hasAddr {
		symPrev = "no virtual address"
	} else if hasSym && sym.Name != "" {
		symPrev = m.displaySymbolName(sym)
	}
	add(modeSymbols, "Symbols", symPrev, hasSym && sym.Name != "")

	secPrev := "no section"
	if !c.hasAddr {
		secPrev = "no virtual address"
	} else if sec != nil {
		secPrev = sec.Name
	}
	add(modeSections, "Sections", secPrev, sec != nil)

	// A string can be found by virtual address or — when the caret has only an
	// offset (a Raw caret over an unmapped region) — by file offset, so the Strings
	// target works from either.
	strPrev := "no string here"
	strOK := false
	if s, ok := m.stringAtCaret(c); ok {
		strPrev = strconvQuote(m.file.StringText(s), 40)
		strOK = true
	}
	add(modeStrings, "Strings", strPrev, strOK)

	relPrev := "no relocations"
	relOK := false
	if !c.hasAddr {
		relPrev = "no virtual address"
	} else if m.file.HasRelocs() {
		if prev, ok := m.relocPreviewAt(addr); ok {
			relPrev, relOK = prev, true
		} else {
			relPrev = "none patch here"
		}
	}
	add(modeRelocs, "Relocs", relPrev, relOK)

	return out
}

// stringAtCaret finds the string covering the caret, by virtual address when it
// has one, else by file offset — so a Raw caret over an unmapped string still
// resolves.
func (m *Model) stringAtCaret(c caret) (binfile.StringEntry, bool) {
	if c.hasAddr {
		if s, ok := m.strs.StringAt(m.viewContext(), c.addr); ok {
			return s, true
		}
	}
	if c.hasOff {
		return m.strs.StringAtOffset(m.viewContext(), c.off)
	}
	return binfile.StringEntry{}, false
}

// strconvQuote renders s as a compact quoted preview truncated to max runes.
func strconvQuote(s string, max int) string {
	if len(s) > max {
		s = s[:max] + "…"
	}
	return "“" + s + "”"
}

// relocPreviewAt describes the relocations patching exactly addr (forcing the
// lazy reloc build, which the user's action justifies): the type + bound symbol
// for a single one, else a count. ok is false when none patch addr.
func (m *Model) relocPreviewAt(addr uint64) (string, bool) {
	var hit []string
	for _, r := range m.file.RelocsInRange(addr, addr+1) {
		if r.Offset != addr {
			continue
		}
		if r.Sym != "" {
			hit = append(hit, r.Type+" "+r.Sym)
		} else {
			hit = append(hit, r.Type)
		}
	}
	switch len(hit) {
	case 0:
		return "", false
	case 1:
		return hit[0], true
	default:
		return fmt.Sprintf("%d relocations", len(hit)), true
	}
}

// caretContextLine describes what the caret *is*: the covering symbol (demangled,
// with any offset) and the section it lives in, for the modal header. Without a
// virtual address it falls back to the section that owns the file offset.
func (m *Model) caretContextLine(c caret) string {
	var parts []string
	if c.hasAddr {
		if sym, ok := m.file.SymbolAt(c.addr); ok && sym.Name != "" {
			if off := c.addr - sym.Addr; off > 0 {
				parts = append(parts, fmt.Sprintf("%s+0x%x", m.displaySymbolName(sym), off))
			} else {
				parts = append(parts, m.displaySymbolName(sym))
			}
		}
		if sec := m.file.SectionAt(c.addr); sec != nil {
			parts = append(parts, sec.Name)
		}
	} else if c.hasOff {
		if sec := m.sectionAtOffset(c.off); sec != nil {
			parts = append(parts, sec.Name)
		}
	}
	return strings.Join(parts, "  ·  ")
}

// caretPointerValue reads the pointer-sized little-endian word at addr, returning
// it when it is itself a mapped address (a GOT slot, a vtable entry, a relocated
// pointer). ok is false when there are no bytes there or the word isn't a mapped
// address.
func (m *Model) caretPointerValue(addr uint64) (uint64, bool) {
	img := m.file.VAImage()
	if img == nil {
		return 0, false
	}
	pos, ok := img.PosForAddr(addr)
	if !ok {
		return 0, false
	}
	ps := m.file.PointerBytes()
	b := img.Bytes(pos, pos+ps)
	if len(b) < ps {
		return 0, false
	}
	var v uint64
	for i := ps - 1; i >= 0; i-- { // little-endian word
		v = v<<8 | uint64(b[i])
	}
	if v == 0 || !m.file.IsMapped(v) {
		return 0, false
	}
	return v, true
}

// caretPointerAt reads the pointer-width little-endian word at the caret — by
// virtual address when it has one, else straight from the raw bytes at its file
// offset — returning it when it is itself a mapped address. This lets a Raw caret
// over an unmapped region (a header, padding) still search for the pointer it
// holds.
func (m *Model) caretPointerAt(c caret) (uint64, bool) {
	if c.hasAddr {
		if v, ok := m.caretPointerValue(c.addr); ok {
			return v, true
		}
	}
	if c.hasOff {
		raw := m.file.Raw()
		ps := m.file.PointerBytes()
		if c.off+uint64(ps) <= uint64(len(raw)) {
			var v uint64
			for i := ps - 1; i >= 0; i-- {
				v = v<<8 | uint64(raw[c.off+uint64(i)])
			}
			if v != 0 && m.file.IsMapped(v) {
				return v, true
			}
		}
	}
	return 0, false
}

// caretPointer describes where the pointer at addr points, for the jump modal's
// header — the most useful single fact about a data slot. Empty when there is no
// mapped pointer there.
func (m *Model) caretPointer(addr uint64) string {
	v, ok := m.caretPointerValue(addr)
	if !ok {
		return ""
	}
	if ann := m.targetAnnotation(v); ann != "" {
		return fmt.Sprintf("→ 0x%x  %s", v, ann)
	}
	return fmt.Sprintf("→ 0x%x", v)
}

// activateJump performs the selected jump for the caret address and closes the
// modal. A disabled row reports its reason instead of navigating.
func (m *Model) activateJump() {
	if m.jumpSel < 0 || m.jumpSel >= len(m.jumpTargets) {
		return
	}
	t := m.jumpTargets[m.jumpSel]
	if !t.enabled {
		m.setStatus(t.label+": "+t.preview, true)
		return
	}
	c := m.jumpCaret
	m.jumpActive = false
	switch t.mode {
	case modeRaw:
		// Raw is addressed by file offset, so it works even for an offset-only caret.
		m.openRawAt(c.off)
	case modeDisasm:
		m.jumpDisasmAtAddr(c.addr)
	case modeHex:
		m.jumpHexAtAddr(c.addr)
	case modeSymbols:
		m.jumpSymbolsAtAddr(c.addr)
	case modeSections:
		m.jumpSectionsAtAddr(c.addr)
	case modeStrings:
		if c.hasAddr {
			m.jumpStringsAtAddr(c.addr)
		} else {
			m.jumpStringsAtOffset(c.off)
		}
	case modeRelocs:
		m.jumpRelocsAtAddr(c.addr)
	}
}

// updateJumpModal drives the modal's selection: up/down move, a target's view
// digit jumps straight to it, Enter opens the selection, Esc closes.
func (m *Model) updateJumpModal(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc":
		m.jumpActive = false
	case "up", "k":
		m.jumpMoveSel(-1)
	case "down", "j":
		m.jumpMoveSel(1)
	case "enter", "space":
		m.activateJump()
	default:
		if len(key) == 1 && key[0] >= '0' && key[0] <= '9' {
			for i, t := range m.jumpTargets {
				if t.enabled && modeDigit(t.mode) == key {
					m.jumpSel = i
					m.activateJump()
					break
				}
			}
		}
	}
	return m, nil
}

// jumpMoveSel moves the selection by d, skipping disabled rows so the cursor
// always rests on something actionable.
func (m *Model) jumpMoveSel(d int) {
	n := len(m.jumpTargets)
	if n == 0 {
		return
	}
	for range m.jumpTargets {
		m.jumpSel = (m.jumpSel + d + n) % n
		if m.jumpTargets[m.jumpSel].enabled {
			return
		}
	}
}

func (m *Model) renderJumpModal() string {
	var sb strings.Builder
	rowW := modalListWidth(m.width)

	// Header: the address (or file offset, for an offset-only caret), then what it
	// is (symbol · section) and, for a data slot, the pointer it holds. Count the
	// lines so modalClick maps rows correctly.
	c := m.jumpCaret
	loc := fmt.Sprintf("0x%x", c.addr)
	if !c.hasAddr {
		loc = fmt.Sprintf("file 0x%x", c.off)
	}
	sb.WriteString(m.theme.modalTitle("Open ") + " " + m.theme.addrStyle.Render(loc))
	sb.WriteString("\n")
	headerLines := 1
	if ctx := m.caretContextLine(c); ctx != "" {
		sb.WriteString(" " + m.theme.symbolNameStyle.Render(layout.TruncateANSI(ctx, max(1, rowW-1))) + "\n")
		headerLines++
	}
	if c.hasAddr {
		if ptr := m.caretPointer(c.addr); ptr != "" {
			sb.WriteString(" " + m.theme.srcShadowStyle.Render(layout.TruncateANSI(ptr, max(1, rowW-1))) + "\n")
			headerLines++
		}
	}
	sb.WriteString("\n")
	headerLines++
	m.modalListRow = headerLines

	const labelW = 9
	prevW := max(4, rowW-3-2-labelW-3)
	faint := lipgloss.NewStyle().Faint(true)
	for i, t := range m.jumpTargets {
		glyph, gStyle := "▸", m.theme.headerKey
		if !t.enabled {
			glyph, gStyle = "·", m.theme.srcShadowStyle
		}
		digit := m.theme.helpKeyStyle.Render(modeDigit(t.mode))
		label := layout.PadVisual(t.label, labelW)
		preview := m.theme.srcShadowStyle.Render(layout.TruncateMiddle(t.preview, prevW))
		line := fmt.Sprintf(" %s %s  %s  %s", gStyle.Render(glyph), digit, label, preview)
		line = layout.PadRight(line, rowW)
		switch {
		case i == m.jumpSel:
			line = m.theme.tableSelStyle.Render(ansi.Strip(line))
		case !t.enabled:
			line = faint.Render(ansi.Strip(line))
		}
		sb.WriteString(line + "\n")
	}
	sb.WriteString("\n")
	sb.WriteString(m.theme.modalHint("↑/↓ select · ↵ or digit open · Esc cancel"))
	return m.theme.modalStyle.Render(sb.String())
}
