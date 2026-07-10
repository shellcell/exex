package ui

// Disassembly rendering, shell side: composing the scroller (which lives in
// internal/ui/views/disasm) with the side-by-side source pane, plus the
// annotation vocabulary (targetAnnotation, lmaNote) shared with other views
// through view.Styles.

import (
	"fmt"

	"charm.land/lipgloss/v2"

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
	showSrc := m.dasm.ShowSource && m.file.HasDWARF()
	if !showSrc && m.dasm.SourceFirst && m.hasOpenSourceFile() {
		return m.renderSourceText(m.width, bodyH)
	}
	if showSrc && m.dasm.SourceFirst && m.hasOpenSourceFile() {
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
	right := m.dasm.RenderSourcePane(m.viewContextPtr(), rightW, bodyH)
	return lipgloss.JoinHorizontal(lipgloss.Top, left, right)
}

// renderDisasmScroll renders the instruction scroller, choosing the per-row
// address colouring: when the source pane is open (disasm-first), addresses
// are coloured by their source mapping — identical to the source-first disasm
// pane — instead of the intra-function jump-target highlight used in the pure
// disasm view (the view still gives the jump targets priority).
func (m *Model) renderDisasmScroll(w, h int) string {
	ctx := m.viewContextPtr()
	var addrMap func(addr uint64) *lipgloss.Style
	if m.rightPaneActive() && !m.dasm.SourceFirst && len(m.dasm.Inst) > 0 {
		curFile, curLine, _ := m.file.LookupAddrCol(m.dasm.Inst[m.dasm.Cur].Addr)
		addrMap = func(addr uint64) *lipgloss.Style {
			st := m.dasm.AddrMapStyle(ctx, addr, curFile, curLine)
			return &st
		}
	}
	return m.dasm.RenderScroll(ctx, w, h, addrMap)
}

// disasmRowHeight returns the per-instruction rendered-height function for the
// disasm scroller at render width w. Shared by every place that runs the
// scroll math.
func (m *Model) disasmRowHeight(w int) func(int) int {
	return m.dasm.RowHeight(m.viewContextPtr(), w)
}

func (m *Model) disasmRenderWidth() int {
	if m.mode == modeDisasm && m.dasm.ShowSource && m.file.HasDWARF() && !m.dasm.SourceFirst {
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
	return m.dasm.EnsureSourceForCursor(m.file)
}

func (m *Model) hasOpenSourceFile() bool {
	return m.dasm.HasOpenSourceFile(m.viewContextPtr())
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
