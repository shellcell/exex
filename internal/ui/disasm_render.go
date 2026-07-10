package ui

// Disassembly rendering, shell side: composing the scroller (which lives in
// internal/ui/views/disasm) with the side-by-side source pane, plus the
// annotation vocabulary (targetAnnotation, lmaNote) shared with other views
// through view.Styles.

import (
	"fmt"

	"charm.land/lipgloss/v2"

	"github.com/rabarbra/exex/internal/ui/layout"
	disasmview "github.com/rabarbra/exex/internal/ui/views/disasm"
)

// targetAnnotation labels a follow-able address with whatever the reader is
// most likely to want as context: the symbol name (with offset when not at
// the symbol's start), or the containing section name when no symbol covers
// it. Returns "" when neither is known.
func (m *Model) targetAnnotation(addr uint64) string {
	if sym, ok := m.file.SymbolAt(addr); ok {
		if addr == sym.Addr {
			return m.displaySymbolName(sym)
		}
		return fmt.Sprintf("%s+0x%x", m.displaySymbolName(sym), addr-sym.Addr)
	}
	if sec := m.file.SectionAt(addr); sec != nil {
		return sec.Name
	}
	return ""
}

func (m *Model) renderDisasm() string {
	bodyH := m.bodyHeight()
	if m.dasm.Decoding {
		return m.emptyBody("decoding instructions…")
	}
	if len(m.dasm.Inst) == 0 {
		return m.emptyBody("no disassembly loaded — press g to go to an address, or pick a symbol from view 3")
	}
	// The source pane only makes sense when the binary actually carries debug
	// info; otherwise keep the disasm full-width instead of opening an empty
	// "no source" pane.
	showSrc := m.showSource && m.file.HasDWARF()
	if !showSrc && m.sourceFirst && m.hasOpenSourceFile() {
		return m.renderSourceText(m.width, bodyH)
	}
	if showSrc && m.sourceFirst && m.hasOpenSourceFile() {
		leftW := m.width / 2
		rightW := m.width - leftW
		left := m.renderSourceText(leftW, bodyH)
		right := m.theme.leftBorderPane(m.renderSourceAsm(rightW-1, bodyH))
		return lipgloss.JoinHorizontal(lipgloss.Top, left, right)
	}
	leftW := m.width
	rightW := 0
	if showSrc {
		leftW = m.width / 2
		rightW = m.width - leftW
	}

	sticky := m.dasm.RenderSticky(m.viewContextPtr(), leftW)
	left := sticky + "\n" + m.renderDisasmScroll(leftW, bodyH-1)

	if rightW == 0 {
		return left
	}
	right := m.renderSourcePane(rightW, bodyH)
	return lipgloss.JoinHorizontal(lipgloss.Top, left, right)
}

// renderDisasmScroll renders the instruction scroller, choosing the per-row
// address colouring: when the source pane is open (disasm-first), addresses
// are coloured by their source mapping — identical to the source-first disasm
// pane — instead of the intra-function jump-target highlight used in the pure
// disasm view (the view still gives the jump targets priority).
func (m *Model) renderDisasmScroll(w, h int) string {
	var addrMap func(addr uint64) *lipgloss.Style
	if m.rightPaneActive() && !m.sourceFirst && len(m.dasm.Inst) > 0 {
		curFile, curLine, _ := m.file.LookupAddrCol(m.dasm.Inst[m.dasm.Cur].Addr)
		addrMap = func(addr uint64) *lipgloss.Style {
			st := m.addrMapStyle(addr, curFile, curLine)
			return &st
		}
	}
	return m.dasm.RenderScroll(m.viewContextPtr(), w, h, addrMap)
}

// disasmRowHeight returns the per-instruction rendered-height function for the
// disasm scroller at render width w. Shared by every place that runs the
// scroll math.
func (m *Model) disasmRowHeight(w int) func(int) int {
	return m.dasm.RowHeight(m.viewContextPtr(), w)
}

func (m *Model) disasmRenderWidth() int {
	if m.mode == modeDisasm && m.showSource && m.file.HasDWARF() && !m.sourceFirst {
		return m.width / 2
	}
	return m.width
}

// disasmColumns is the row geometry for the current file and byte-column
// settings.
func (m *Model) disasmColumns() disasmview.Columns {
	return disasmview.ColumnsFor(m.viewContextPtr())
}

func (m *Model) ensureSourceForDisasmCursor() bool {
	// In source-first mode the source cursor is authoritative — the asm pane
	// follows it via syncSourceAsm. Re-deriving srcCur from the disasm cursor
	// here would snap the cursor back whenever it moved onto an unmapped
	// (shadow) line, which is why "up" sometimes appeared stuck.
	if m.sourceFirst && m.srcFile != "" && m.file.SourceLines(m.srcFile) != nil {
		return true
	}
	if len(m.dasm.Inst) == 0 || m.dasm.Cur < 0 || m.dasm.Cur >= len(m.dasm.Inst) {
		return false
	}
	file, line := m.file.LookupAddr(m.dasm.Inst[m.dasm.Cur].Addr)
	if file == "" || line == 0 || m.file.SourceLines(file) == nil {
		return false
	}
	if m.srcFile != file {
		m.srcFile = file
		m.srcCodeLines = m.mappedSourceLines(file)
	}
	m.srcCur = line
	return true
}

func (m *Model) hasOpenSourceFile() bool {
	return m.srcFile != "" && m.file.SourceLines(m.srcFile) != nil
}

// lmaNote formats a section's load address (LMA) as a banner suffix, or "" when
// it matches the virtual address. Shown once per section (the offset is constant
// across the section) in the disasm and hex/raw section banners.
func (m *Model) lmaNote(phys uint64) string {
	if phys == 0 {
		return ""
	}
	return fmt.Sprintf("   LMA 0x%0*x", m.file.AddrHexWidth(), phys)
}

func (m *Model) renderSourcePane(w, h int) string {
	border := m.theme.paneBorderStyle
	inner := w - 1
	if inner < 8 {
		inner = w
	}

	if len(m.dasm.Inst) == 0 {
		return border.Render(layout.PadBody("", inner, h))
	}
	addr := m.dasm.Inst[m.dasm.Cur].Addr
	file, line, col := m.file.LookupAddrCol(addr)
	if file == "" {
		body := "no source mapping for 0x" + fmt.Sprintf("%x", addr)
		return border.Render(layout.PadBody(body+"\n", inner, h))
	}
	src := m.file.SourceLines(file)
	if src == nil {
		suffix := fmt.Sprintf(":%d (source file not found)", line)
		body := m.theme.viewTitleLine(layout.TruncateMiddle(file, max(1, inner-lipgloss.Width(suffix)))+suffix, inner) + "\n"
		return border.Render(layout.PadBody(body, inner, h))
	}

	hl := m.highlightedSource(file, src)
	mapped := m.mappedSourceLines(file)

	suffix := fmt.Sprintf(":%d", line)
	if col > 0 {
		suffix = fmt.Sprintf(":%d:%d", line, col)
	}
	loc := layout.TruncateMiddle(file, max(1, inner-lipgloss.Width(suffix))) + suffix
	half := (h - 1) / 2
	base := line - half
	from := base + m.rightScroll
	if from < 1 {
		from = 1
	}
	to := from + h - 2
	if to > len(src) {
		to = len(src)
		from = to - (h - 2)
		if from < 1 {
			from = 1
		}
	}
	// Build the lines directly (vs accumulating into one Builder then splitting it
	// back apart in layout.PadBody) — fewer per-frame allocations on this hot path.
	rows := make([]string, 0, h)
	rows = append(rows, m.theme.viewTitleLine(loc, inner))
	for i := from; i <= to; i++ {
		var content string
		if i-1 >= 0 && i-1 < len(src) {
			content = src[i-1]
		}
		// The code is always shown syntax-highlighted; only the gutter colour
		// reflects the mapping (shared srcGutter policy — identical to the
		// source-first pane).
		if hl != nil && i-1 >= 0 && i-1 < len(hl) {
			content = hl[i-1]
		}
		prefix := m.srcGutter(i, line, mapped, 5)
		gutterW := lipgloss.Width(prefix)
		rows = append(rows, prefix+layout.FitANSIWidth(content, inner-gutterW))
		// Point carets at every column this source line maps to (a line can map
		// at several positions), each in its column colour — same as the
		// source-first pane.
		if i == line {
			if cols := m.sourceLineColumns(file, line); len(cols) > 0 {
				rows = append(rows, m.theme.coloredCaretRow(cols, gutterW, inner))
			}
		}
	}
	return border.Render(layout.PadBodyRows(rows, inner, h))
}
