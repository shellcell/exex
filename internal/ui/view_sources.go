package ui

// This file owns the Sources view (DWARF only): a list of every source file
// referenced by the line table; opening one shows the source on the left with
// the mapped disassembly on the right, following the source cursor. Search
// works within the open file (/) and across all sources (ctrl+f).

import (
	"fmt"
	"path/filepath"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	sourceutil "github.com/rabarbra/exex/internal/sourcefiles"
	"github.com/rabarbra/exex/internal/ui/layout"
)

// srcMatch is one hit from a cross-source grep.
type srcMatch = sourceutil.Match

// columnStyleAt returns the highlight style for the i-th distinct column on a
// source line. The Nth column, its caret, and the instruction addresses mapped
// to it all share columnPalette[N] (drawn from the theme), so carets and
// disassembly line up visually and follow the active colour preset. The view
// consumes it through the ColumnStyleAt closure on view.Styles.
func (t *Theme) columnStyleAt(i int) lipgloss.Style {
	if len(t.columnPalette) == 0 {
		return lipgloss.NewStyle()
	}
	return t.columnPalette[i%len(t.columnPalette)]
}

func (m *Model) ensureSourceBelowDisasmCursor() bool {
	if len(m.dasm.Inst) == 0 || m.dasm.Cur < 0 || m.dasm.Cur >= len(m.dasm.Inst) {
		return false
	}
	start := m.dasm.Cur + 1
	if start >= len(m.dasm.Inst) {
		return false
	}
	if sym, ok := m.file.SymbolAt(m.dasm.Inst[m.dasm.Cur].Addr); ok && sym.Size > 0 {
		end := sym.Addr + sym.Size
		if m.selectSourceFromInstRange(start, func(addr uint64) bool { return addr < end }) {
			return true
		}
		for start < len(m.dasm.Inst) && m.dasm.Inst[start].Addr < end {
			start++
		}
	}
	return m.selectSourceFromInstRange(start, func(uint64) bool { return true })
}

func (m *Model) selectSourceFromInstRange(start int, inRange func(uint64) bool) bool {
	for i := start; i < len(m.dasm.Inst); i++ {
		addr := m.dasm.Inst[i].Addr
		if !inRange(addr) {
			return false
		}
		file, line := m.file.LookupAddr(addr)
		if file == "" || line == 0 || m.file.SourceLines(file) == nil {
			continue
		}
		if m.dasm.SrcFile != file {
			m.dasm.SrcFile = file
			m.dasm.SrcCodeLines = m.dasm.MappedLines(m.viewContextPtr(), file)
		}
		m.dasm.SrcCur = line
		m.dasm.SrcTop = 0
		m.syncSourceAsm()
		return true
	}
	return false
}

// The Sources view is always just the file list; opening a file (Enter) drops
// into the disassembly view in source-first mode. The split source/disasm panes
// live entirely in the disasm view now.
func (m *Model) updateSources(key string) (tea.Model, tea.Cmd) {
	ctx := m.viewContext()
	m.sources.Ensure(ctx)
	if !m.file.HasDWARF() {
		return m, nil
	}
	switch key {
	case "ctrl+f":
		m.srcSearchAll = true
		m.openSearch()
		return m, nil
	}
	m.sources.Update(ctx, m, key)
	return m, nil
}

// updateSourceOpenSrc drives source-first navigation: the source cursor leads
// and the disasm pane follows via syncSourceAsm. Used by the disasm view when
// sourceFirst is active.
func (m *Model) updateSourceOpenSrc(key string) (tea.Model, tea.Cmd) {
	n := len(m.file.SourceLines(m.dasm.SrcFile))
	switch key {
	case "esc", "backspace":
		m.dasm.SrcFile = "" // back to the file list
		return m, nil
	case "/":
		m.srcSearchAll = false
		m.openSearch()
		return m, nil
	case "ctrl+f":
		m.srcSearchAll = true
		m.openSearch()
		return m, nil
	case "S":
		m.copyToClipboard(m.dasm.SrcFile, "source path")
		return m, nil
	case "w":
		m.toggleWrap()
		return m, nil
	case "n":
		m.runSearch(true, false)
	case "N":
		m.runSearch(false, false)
	case "]":
		m.gotoMappedLine(true)
	case "[":
		m.gotoMappedLine(false)
	case "up", "k":
		if m.dasm.SrcCur > 1 {
			m.dasm.SrcCur--
			m.syncSourceAsm()
		}
	case "down", "j":
		if m.dasm.SrcCur < n {
			m.dasm.SrcCur++
			m.syncSourceAsm()
		}
	case "pgup":
		m.dasm.SrcCur = max(1, m.dasm.SrcCur-m.listPage())
		m.syncSourceAsm()
	case "pgdown":
		m.dasm.SrcCur = min(n, m.dasm.SrcCur+m.listPage())
		m.syncSourceAsm()
	case "home":
		m.dasm.SrcCur = 1
		m.syncSourceAsm()
	case "end", "G":
		m.dasm.SrcCur = n
		m.syncSourceAsm()
	case "enter":
		// Jump into the main disasm view at the mapped address.
		if addr, ok := m.file.LineToAddr(m.dasm.SrcFile, m.dasm.SrcCur); ok {
			m.loadDisasmAt(addr)
			m.dasm.SourceFirst = false
		} else {
			m.setStatus("no code maps to this line", true)
		}
	}
	return m, nil
}

// gotoMappedLine moves the cursor to the next/previous source line that has
// machine code mapped to it, skipping the shadowed (unmapped) lines.
func (m *Model) gotoMappedLine(forward bool) {
	n := len(m.file.SourceLines(m.dasm.SrcFile))
	if forward {
		for ln := m.dasm.SrcCur + 1; ln <= n; ln++ {
			if m.dasm.SrcCodeLines[ln] {
				m.dasm.SrcCur = ln
				m.syncSourceAsm()
				return
			}
		}
	} else {
		for ln := m.dasm.SrcCur - 1; ln >= 1; ln-- {
			if m.dasm.SrcCodeLines[ln] {
				m.dasm.SrcCur = ln
				m.syncSourceAsm()
				return
			}
		}
	}
	m.setStatus("no more mapped lines", false)
}

// openSourceFile switches the source-first pane to file at the given 1-based
// line. It leaves mode selection to the caller.
func (m *Model) openSourceFile(file string, line int) bool {
	src := m.file.SourceLines(file)
	if src == nil {
		m.setStatus("source file not found: "+filepath.Base(file), true)
		return false
	}
	m.dasm.SrcFile = file
	m.dasm.SrcCodeLines = m.dasm.MappedLines(m.viewContextPtr(), file)
	if line < 1 {
		line = 1
	}
	if line > len(src) {
		line = len(src)
	}
	m.dasm.SrcCur = line
	m.dasm.SrcTop = 0
	m.syncSourceAsm()
	return true
}

func (m *Model) openSourceFileInDisasm(file string, line int) {
	m.openSourceFile(file, line)
	m.setMode(modeDisasm)
	m.dasm.ShowSource = true
	m.dasm.SourceFirst = true
}

// syncSourceAsm points the disasm cursor at the address mapped from the current
// source line, so the right-hand pane tracks the source cursor.
func (m *Model) syncSourceAsm() {
	if m.dis == nil {
		return
	}
	addr, ok := m.file.LineToAddr(m.dasm.SrcFile, m.dasm.SrcCur)
	if !ok {
		return
	}
	if _, mapped := m.file.ExecImage().PosForAddr(addr); !mapped {
		return
	}
	// The disasm is windowed; load the span around this line's address if it
	// isn't already loaded. setDisasmSpan leaves m.mode alone (we're in the
	// Sources view), it just refreshes the instruction window the right pane
	// renders.
	if !m.disasmLoadedAddr(addr) {
		m.dasm.SetSpan(m.decodeDisasmAt(addr, m.disasmLeadBytes()))
	}
	m.dasm.Cur = m.dasm.IndexAtOrAfter(addr)
	m.scrollDisasmContext(4)
}

// ---- cross-source / in-file search (called from runSearch) ----

func (m *Model) searchInSourceFile(forward, inclusive bool) {
	if m.dasm.SrcFile == "" {
		return
	}
	src := m.file.SourceLines(m.dasm.SrcFile)
	start := m.dasm.SrcCur
	if !inclusive {
		if forward {
			start++
		} else {
			start--
		}
	}
	if i := sourceutil.FindInLines(src, m.searchQuery, start, forward); i > 0 {
		m.dasm.SrcCur = i
		m.syncSourceAsm()
		return
	}
	m.setStatus("not found in file: "+m.searchQuery, true)
}

func (m *Model) searchAllSources(forward, inclusive bool) {
	if inclusive {
		m.srcMatches = m.grepSources(m.searchQuery)
		m.srcMatchIdx = 0
		if len(m.srcMatches) == 0 {
			m.setStatus("not found in any source: "+m.searchQuery, true)
			return
		}
		m.openSrcMatch(0)
		return
	}
	if len(m.srcMatches) == 0 {
		return
	}
	if forward {
		m.srcMatchIdx = (m.srcMatchIdx + 1) % len(m.srcMatches)
	} else {
		m.srcMatchIdx = (m.srcMatchIdx - 1 + len(m.srcMatches)) % len(m.srcMatches)
	}
	m.openSrcMatch(m.srcMatchIdx)
}

func (m *Model) openSrcMatch(i int) {
	mt := m.srcMatches[i]
	m.openSourceFile(mt.File, mt.Line)
	m.setStatus(fmt.Sprintf("match %d/%d  %s:%d", i+1, len(m.srcMatches), filepath.Base(mt.File), mt.Line), false)
}

// grepSources scans every source file for the query (capped).
func (m *Model) grepSources(query string) []srcMatch {
	const cap = 1000
	return sourceutil.GrepStream(m.sources.Files, func(file string, yield func(string) bool) {
		m.file.ScanSourceLines(file, yield)
	}, query, cap)
}

// ---- rendering ----

func (m *Model) renderSources() string {
	ctx := m.viewContext()
	m.sources.Ensure(ctx)
	if !m.file.HasDWARF() {
		return m.emptyBody("no debug info — the Sources view needs DWARF (build with -g, or place a .dSYM / .debug sidecar next to the binary)")
	}
	// The Sources view is only ever the file list; opening a file switches to the
	// disasm view (source-first), which owns the split panes.
	return m.sources.Render(ctx, m)
}

// leftBorderPane draws a thin divider on the left edge of a pane.
func (t Theme) leftBorderPane(content string) string {
	return t.paneBorderStyle.Render(content)
}

// renderSourceText renders the leading source pane and records its page step
// for the shell's pgup/pgdn keys. The rendering lives on the view state.
func (m *Model) renderSourceText(w, h int) string {
	out := m.dasm.RenderSourceText(m.viewContextPtr(), w, h)
	m.pageRows = m.dasm.SrcPageRows
	return out
}

// renderSourceAsm ensures a decode happened (the follower pane may be the
// first thing to need one), then delegates to the view.
func (m *Model) renderSourceAsm(w, h int) string {
	if m.dis == nil {
		return layout.PadBody("no disassembler for this architecture\n", w, h)
	}
	if !m.ensureDisasm() {
		return layout.PadBody("no executable code\n", w, h)
	}
	return m.dasm.RenderSourceAsm(m.viewContextPtr(), w, h)
}

func (m *Model) sourceRowHeight(w int) func(int) int {
	return m.dasm.SourceRowHeight(m.viewContextPtr(), w)
}

func (m *Model) sourceTextTop(w, contentH int) int {
	return m.dasm.SourceTextTop(m.viewContextPtr(), w, contentH)
}
