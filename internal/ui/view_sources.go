package ui

// This file owns the Sources view (DWARF only): a list of every source file
// referenced by the line table; opening one shows the source on the left with
// the mapped disassembly on the right, following the source cursor. Search
// works within the open file (/) and across all sources (ctrl+f).

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	sourceutil "github.com/rabarbra/exex/internal/sourcefiles"
)

// srcMatch is one hit from a cross-source grep.
type srcMatch = sourceutil.Match

// colColors keys the per-column highlight: the Nth distinct column on a source
// line is drawn in colColors[N], and the instructions mapped to that column get
// the same colour, so carets and disassembly line up visually.
var colColors = []lipgloss.Color{"203", "220", "84", "39", "213", "51", "215", "141"}

// columnColor returns the colour assigned to col among the line's sorted
// distinct columns.
func columnColor(cols []int, col int) (lipgloss.Color, bool) {
	for i, c := range cols {
		if c == col {
			return colColors[i%len(colColors)], true
		}
	}
	return "", false
}

// ensureSources loads the source-file list once.
func (m *Model) ensureSources() {
	if m.sourcesFiles == nil {
		m.sourcesFiles = m.file.SourceFiles()
		if m.sourcesFiles == nil {
			m.sourcesFiles = []string{}
		}
		wd, _ := os.Getwd()
		sourceutil.SortForProject(m.sourcesFiles, m.file.Path, wd)
		m.recomputeSourceFiles()
	}
}

// recomputeSourceFiles rebuilds the filtered file list from the filter text.
func (m *Model) recomputeSourceFiles() {
	needle := strings.ToLower(m.sourcesFilter.Value())
	m.sourcesFiltered = m.sourcesFiltered[:0]
	for i, f := range m.sourcesFiles {
		if needle == "" || strings.Contains(strings.ToLower(f), needle) {
			m.sourcesFiltered = append(m.sourcesFiltered, i)
		}
	}
	if m.sourcesCur >= len(m.sourcesFiltered) {
		m.sourcesCur = max(0, len(m.sourcesFiltered)-1)
	}
}

// The Sources view is always just the file list; opening a file (Enter) drops
// into the disassembly view in source-first mode. The split source/disasm panes
// live entirely in the disasm view now.
func (m *Model) updateSources(key string) (tea.Model, tea.Cmd) {
	m.ensureSources()
	if !m.file.HasDWARF() {
		return m, nil
	}
	return m.updateSourceList(key)
}

func (m *Model) updateSourceList(key string) (tea.Model, tea.Cmd) {
	n := len(m.sourcesFiltered)
	if navKey(&m.sourcesCur, n, m.bodyHeight(), key) {
		return m, nil
	}
	switch key {
	case "/":
		m.sourcesFilter.Focus()
		return m, nil
	case "ctrl+f":
		m.srcSearchAll = true
		m.openSearch()
		return m, nil
	case "c":
		if m.sourcesCur >= 0 && m.sourcesCur < n {
			m.copyToClipboard(m.sourcesFiles[m.sourcesFiltered[m.sourcesCur]], "source path")
		}
	case "w":
		m.toggleWrap()
	case "enter":
		if m.sourcesCur >= 0 && m.sourcesCur < n {
			m.openSourceFile(m.sourcesFiles[m.sourcesFiltered[m.sourcesCur]], 1)
			m.mode = modeDisasm
			m.showSource = true
			m.sourceFirst = true
		}
	}
	return m, nil
}

// updateSourceOpenSrc drives source-first navigation: the source cursor leads
// and the disasm pane follows via syncSourceAsm. Used by the disasm view when
// sourceFirst is active.
func (m *Model) updateSourceOpenSrc(key string) (tea.Model, tea.Cmd) {
	n := len(m.file.SourceLines(m.srcFile))
	switch key {
	case "esc", "backspace":
		m.srcFile = "" // back to the file list
		return m, nil
	case "/":
		m.srcSearchAll = false
		m.openSearch()
		return m, nil
	case "ctrl+f":
		m.srcSearchAll = true
		m.openSearch()
		return m, nil
	case "c":
		m.copyToClipboard(m.srcFile, "source path")
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
		if m.srcCur > 1 {
			m.srcCur--
			m.syncSourceAsm()
		}
	case "down", "j":
		if m.srcCur < n {
			m.srcCur++
			m.syncSourceAsm()
		}
	case "pgup":
		m.srcCur = max(1, m.srcCur-m.bodyHeight())
		m.syncSourceAsm()
	case "pgdown":
		m.srcCur = min(n, m.srcCur+m.bodyHeight())
		m.syncSourceAsm()
	case "home":
		m.srcCur = 1
		m.syncSourceAsm()
	case "end", "G":
		m.srcCur = n
		m.syncSourceAsm()
	case "enter":
		// Jump into the main disasm view at the mapped address.
		if addr, ok := m.file.LineToAddr(m.srcFile, m.srcCur); ok {
			m.loadDisasmAt(addr)
			m.sourceFirst = false
		} else {
			m.setStatus("no code maps to this line", true)
		}
	}
	return m, nil
}

// gotoMappedLine moves the cursor to the next/previous source line that has
// machine code mapped to it, skipping the shadowed (unmapped) lines.
func (m *Model) gotoMappedLine(forward bool) {
	n := len(m.file.SourceLines(m.srcFile))
	if forward {
		for ln := m.srcCur + 1; ln <= n; ln++ {
			if m.srcCodeLines[ln] {
				m.srcCur = ln
				m.syncSourceAsm()
				return
			}
		}
	} else {
		for ln := m.srcCur - 1; ln >= 1; ln-- {
			if m.srcCodeLines[ln] {
				m.srcCur = ln
				m.syncSourceAsm()
				return
			}
		}
	}
	m.setStatus("no more mapped lines", false)
}

// openSourceFile switches to the open-file pane at the given 1-based line.
func (m *Model) openSourceFile(file string, line int) {
	src := m.file.SourceLines(file)
	if src == nil {
		m.setStatus("source file not found: "+filepath.Base(file), true)
		return
	}
	m.srcFile = file
	m.srcCodeLines = m.file.MappedLines(file)
	if line < 1 {
		line = 1
	}
	if line > len(src) {
		line = len(src)
	}
	m.srcCur = line
	m.srcTop = 0
	m.syncSourceAsm()
}

// syncSourceAsm points the disasm cursor at the address mapped from the current
// source line, so the right-hand pane tracks the source cursor.
func (m *Model) syncSourceAsm() {
	if m.dis == nil {
		return
	}
	addr, ok := m.file.LineToAddr(m.srcFile, m.srcCur)
	if !ok {
		return
	}
	if _, mapped := m.file.ExecImage().PosForAddr(addr); !mapped {
		return
	}
	// The disasm is windowed; load the span around this line's address if it
	// isn't already loaded. setDisasmWindow leaves m.mode alone (we're in the
	// Sources view), it just refreshes the instruction window the right pane
	// renders.
	if !m.disasmLoadedAddr(addr) {
		win, insts := m.decodeDisasmAt(addr, m.disasmLeadBytes())
		m.setDisasmWindow(win, insts)
	}
	m.disasmCur = m.instIndexAtOrAfterAddr(addr)
	m.scrollDisasmContext(4)
}

// ---- cross-source / in-file search (called from runSearch) ----

func (m *Model) searchInSourceFile(forward, inclusive bool) {
	if m.srcFile == "" {
		return
	}
	src := m.file.SourceLines(m.srcFile)
	start := m.srcCur
	if !inclusive {
		if forward {
			start++
		} else {
			start--
		}
	}
	if i := sourceutil.FindInLines(src, m.searchQuery, start, forward); i > 0 {
		m.srcCur = i
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
	return sourceutil.Grep(m.sourcesFiles, m.file.SourceLines, query, cap)
}

// ---- rendering ----

func (m *Model) renderSources() string {
	bodyH := m.bodyHeight()
	m.ensureSources()
	if !m.file.HasDWARF() {
		return padBody("no debug info — the Sources view needs DWARF (build with -g, or place a .dSYM / .debug sidecar next to the binary)\n", m.width, bodyH)
	}
	// The Sources view is only ever the file list; opening a file switches to the
	// disasm view (source-first), which owns the split panes.
	return m.renderSourceList(bodyH)
}

// leftBorderPane draws a thin divider on the left edge of a pane.
func leftBorderPane(content string) string {
	return lipgloss.NewStyle().
		BorderStyle(lipgloss.NormalBorder()).
		BorderLeft(true).
		BorderForeground(lipgloss.Color("240")).
		Render(content)
}

func (m *Model) renderSourceList(bodyH int) string {
	if bodyH < 2 {
		bodyH = 2
	}
	filterRow := m.sourcesFilter.View()
	if !m.sourcesFilter.Focused() {
		filterRow = m.theme.footerStyle.Render(fmt.Sprintf("/ %s   (%d / %d source files)",
			m.sourcesFilter.Value(), len(m.sourcesFiltered), len(m.sourcesFiles)))
	}

	visible := bodyH - 1
	if visible < 1 {
		visible = 1
	}
	top := visualTop(m.sourcesCur, m.sourcesTop, len(m.sourcesFiltered), visible, func(int) int { return 1 })
	end := top + visible
	if end > len(m.sourcesFiltered) {
		end = len(m.sourcesFiltered)
	}

	var b strings.Builder
	b.WriteString(filterRow)
	b.WriteString("\n")
	if len(m.sourcesFiltered) == 0 {
		b.WriteString(m.theme.footerStyle.Render(" (no source files)"))
		return padBody(b.String(), m.width, bodyH)
	}
	for i := top; i < end; i++ {
		full := m.sourcesFiles[m.sourcesFiltered[i]]
		name := colorPathByPrefix(full, truncateMiddle(full, max(16, m.width-2)))
		line := padRight(" "+name, m.width)
		if i == m.sourcesCur {
			b.WriteString(m.theme.tableSelStyle.Render(line))
		} else {
			b.WriteString(m.theme.tableRowStyle.Render(line))
		}
		b.WriteString("\n")
	}
	return padBody(b.String(), m.width, bodyH)
}

// gutterWidth is the visible width of the source line-number gutter
// ("12345 ▸ ").
const gutterWidth = 8

func (m *Model) renderSourceText(w, h int) string {
	src := m.file.SourceLines(m.srcFile)
	if len(src) == 0 {
		return padBody("(source file not found on disk)\n", w, h)
	}
	hl := m.highlightedSource(m.srcFile, src)

	contentH := h - 1
	if contentH < 1 {
		contentH = 1
	}
	top := max(0, m.srcTop-1)
	rowHeight := func(i int) int {
		ln := i + 1
		h := m.sourceLineHeight(ln, w)
		if ln == m.srcCur && len(m.file.LineColumns(m.srcFile, ln)) > 0 {
			h++
		}
		return h
	}
	top = visualTop(m.srcCur-1, top, len(src), contentH, rowHeight)

	var b strings.Builder
	b.WriteString(m.theme.infoStyle.Render(truncate(fmt.Sprintf("%s:%d", m.srcFile, m.srcCur), w)))
	b.WriteString("\n")

	rows := 0
	for ln := top + 1; ln <= len(src) && rows < contentH; ln++ {
		// The code is always shown syntax-highlighted; only the gutter colour
		// reflects the mapping (shared srcGutter policy, used by both panes).
		content := src[ln-1]
		if hl != nil && ln-1 < len(hl) {
			content = hl[ln-1]
		}

		prefix := m.srcGutter(ln, m.srcCur, m.srcCodeLines, 5)
		avail := w - lipgloss.Width(stripANSI(prefix))
		line := prefix + fitANSIWidth(content, avail)
		if m.wrap {
			line = prefix + content
		}
		for _, row := range renderLineRowsIndented(line, w, m.wrap, gutterWidth) {
			if rows >= contentH {
				break
			}
			b.WriteString(row)
			b.WriteString("\n")
			rows++
		}

		// Beneath the cursor line, point carets at the exact columns code maps
		// to (a source line can map at several positions).
		if ln == m.srcCur && rows < contentH {
			if caret := coloredCaretRow(m.file.LineColumns(m.srcFile, ln), gutterWidth, w); caret != "" {
				b.WriteString(caret)
				b.WriteString("\n")
				rows++
			}
		}
	}
	return padBody(b.String(), w, h)
}

func (m *Model) sourceTextTop(w, contentH int) int {
	src := m.file.SourceLines(m.srcFile)
	rowHeight := func(i int) int {
		ln := i + 1
		h := m.sourceLineHeight(ln, w)
		if ln == m.srcCur && len(m.file.LineColumns(m.srcFile, ln)) > 0 {
			h++
		}
		return h
	}
	return visualTop(m.srcCur-1, max(0, m.srcTop-1), len(src), contentH, rowHeight)
}

func (m *Model) sourceLineHeight(line, w int) int {
	src := m.file.SourceLines(m.srcFile)
	if line < 1 || line > len(src) {
		return 1
	}
	plainPrefix := fmt.Sprintf("%5d   ", line)
	content := src[line-1]
	if !m.wrap {
		return 1
	}
	return len(renderLineRowsIndented(plainPrefix+content, w, true, gutterWidth))
}

// coloredCaretRow renders a '^' under each mapped column, each in that column's
// assigned colour (so it matches the highlighted instructions in the asm pane).
func coloredCaretRow(cols []int, gutterW, w int) string {
	if len(cols) == 0 {
		return ""
	}
	maxc := cols[len(cols)-1]
	cells := make([]string, maxc)
	for i := range cells {
		cells[i] = " "
	}
	for i, c := range cols {
		if c >= 1 && c <= maxc {
			cells[c-1] = lipgloss.NewStyle().Foreground(colColors[i%len(colColors)]).Bold(true).Render("^")
		}
	}
	row := strings.Repeat(" ", gutterW) + strings.Join(cells, "")
	return fitANSIWidth(row, w)
}

// renderSourceAsm renders the disassembly beside the source. Instructions that
// map to the current source line are highlighted in their column's colour (so
// they correlate with the carets under the line); a line can map to several,
// non-contiguous instructions and they're all shown.
func (m *Model) renderSourceAsm(w, h int) string {
	if m.dis == nil {
		return padBody("no disassembler for this architecture\n", w, h)
	}
	if !m.ensureDisasm() || len(m.disasmInst) == 0 {
		return padBody("no executable code\n", w, h)
	}

	cols := m.file.LineColumns(m.srcFile, m.srcCur)
	mappedToCur := func(addr uint64) bool {
		f, l, _ := m.file.LookupAddrCol(addr)
		return f == m.srcFile && l == m.srcCur
	}

	count := 0
	for _, in := range m.disasmInst {
		if mappedToCur(in.Addr) {
			count++
		}
	}
	head := m.theme.infoStyle.Render(fmt.Sprintf("line %d — %d instruction(s)", m.srcCur, count))
	if len(cols) > 0 {
		head += m.theme.infoStyle.Render("  ·  cols ") + coloredCols(cols)
	}
	head = fitANSIWidth(head, w)

	contentH := h - 1
	if contentH < 1 {
		contentH = 1
	}
	base := m.disasmTop
	if m.disasmCur < base {
		base = m.disasmCur
	} else if m.disasmCur >= base+contentH {
		base = m.disasmCur - contentH + 1
	}
	top := clampScroll(base+m.rightScroll, len(m.disasmInst), contentH)
	end := top + contentH
	if end > len(m.disasmInst) {
		end = len(m.disasmInst)
	}

	var b strings.Builder
	b.WriteString(head)
	b.WriteString("\n")
	addrW := m.file.AddrHexWidth()
	for i := top; i < end; i++ {
		inst := m.disasmInst[i]
		// Colour only the address by mapping (shared addrMapStyle policy); the
		// instruction text keeps its normal class colours so the pane reads like
		// real disassembly.
		addrText := fmt.Sprintf("0x%0*x", addrW, inst.Addr)
		line := fmt.Sprintf(" %s  %s  %s",
			m.addrMapStyle(inst.Addr, m.srcFile, m.srcCur).Render(addrText),
			bytesHex(inst.Bytes, 6),
			m.renderInstText(inst.Text, inst.Class, inst.Addr))
		b.WriteString(fitANSIWidth(line, w))
		b.WriteString("\n")
	}
	return padBody(b.String(), w, h)
}

// clampScroll keeps a viewport top within [0, n-h] so an independent-scroll
// offset can't run the follower pane off either end.
func clampScroll(top, n, h int) int {
	maxTop := n - h
	if maxTop < 0 {
		maxTop = 0
	}
	if top > maxTop {
		top = maxTop
	}
	if top < 0 {
		top = 0
	}
	return top
}

// coloredCols renders the line's column numbers, each in its assigned colour.
func coloredCols(cols []int) string {
	parts := make([]string, len(cols))
	for i, c := range cols {
		parts[i] = lipgloss.NewStyle().Foreground(colColors[i%len(colColors)]).Render(fmt.Sprintf("%d", c))
	}
	return strings.Join(parts, " ")
}
