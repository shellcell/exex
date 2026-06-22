package ui

// This file owns the Sources view (DWARF only): a list of every source file
// referenced by the line table; opening one shows the source on the left with
// the mapped disassembly on the right, following the source cursor. Search
// works within the open file (/) and across all sources (ctrl+f).

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	sourceutil "github.com/rabarbra/exex/internal/sourcefiles"
)

// srcMatch is one hit from a cross-source grep.
type srcMatch = sourceutil.Match

// columnStyleAt returns the highlight style for the i-th distinct column on a
// source line. The Nth column, its caret, and the instruction addresses mapped
// to it all share columnPalette[N] (drawn from the theme), so carets and
// disassembly line up visually and follow the active colour preset.
func (t *Theme) columnStyleAt(i int) lipgloss.Style {
	if len(t.columnPalette) == 0 {
		return lipgloss.NewStyle()
	}
	return t.columnPalette[i%len(t.columnPalette)]
}

// columnStyle returns the style assigned to column value col among the line's
// sorted distinct columns.
func (t *Theme) columnStyle(cols []int, col int) (lipgloss.Style, bool) {
	for i, c := range cols {
		if c == col {
			return t.columnStyleAt(i), true
		}
	}
	return lipgloss.Style{}, false
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

// recomputeSourceFiles rebuilds the filtered file list and visible rows from the
// current filter (and, in tree mode, the directory tree + collapse state).
func (m *Model) recomputeSourceFiles() {
	needle := strings.ToLower(m.sourcesFilter.Value())
	m.sourcesFiltered = m.sourcesFiltered[:0]
	for i, f := range m.sourcesFiles {
		if needle != "" && !containsFold(f, needle) {
			continue
		}
		switch m.sourcesAvail {
		case availPresent:
			if !m.file.SourceExists(f) {
				continue
			}
		case availMissing:
			if m.file.SourceExists(f) {
				continue
			}
		}
		m.sourcesFiltered = append(m.sourcesFiltered, i)
	}
	m.buildSourceRows()
	if m.sourcesCur >= len(m.sourcesRows) {
		m.sourcesCur = max(0, len(m.sourcesRows)-1)
	}
}

// sortedSourceIdxs returns the filtered file indices sorted alphabetically by
// path — needed for the adjacency-based directory tree (the flat list keeps its
// project-first order).
func (m *Model) sortedSourceIdxs() []int {
	idxs := append([]int(nil), m.sourcesFiltered...)
	sort.Slice(idxs, func(a, b int) bool { return m.sourcesFiles[idxs[a]] < m.sourcesFiles[idxs[b]] })
	return idxs
}

// buildSourceRows flattens the filtered files into a directory tree (tree mode) or
// one leaf row per file (flat mode).
func (m *Model) buildSourceRows() {
	if m.sourcesTree {
		roots := buildTree(m.sortedSourceIdxs(), func(i int) string { return m.sourcesFiles[i] }, segPath)
		if !m.sourcesTreeInit {
			m.sourcesTreeInit = true
			if m.treeCollapseDefault {
				m.sourcesCollapsed = map[string]bool{}
				eachInternal(roots, func(p string) { m.sourcesCollapsed[p] = true })
			}
		}
		collapsed := m.sourcesCollapsed
		if m.sourcesFilter.Value() != "" {
			collapsed = nil
		}
		m.sourcesRows = flattenTree(roots, collapsed, 0, m.sourcesRows[:0])
		return
	}
	nodes := make([]treeNode, len(m.sourcesFiltered))
	rows := m.sourcesRows[:0]
	for k, idx := range m.sourcesFiltered {
		nodes[k] = treeNode{label: m.sourcesFiles[idx], leaf: idx, count: 1}
		rows = append(rows, treeRow{node: &nodes[k], depth: 0})
	}
	m.sourcesRows = rows
}

// sourceFileAt returns the file path for the row, when it is a leaf.
func (m *Model) sourceFileAt(rowIdx int) (string, bool) {
	if rowIdx < 0 || rowIdx >= len(m.sourcesRows) {
		return "", false
	}
	n := m.sourcesRows[rowIdx].node
	if n.leaf < 0 {
		return "", false
	}
	return m.sourcesFiles[n.leaf], true
}

// toggleSourceNode collapses/expands the directory node at the current row.
func (m *Model) toggleSourceNode() {
	if m.sourcesCur < 0 || m.sourcesCur >= len(m.sourcesRows) {
		return
	}
	n := m.sourcesRows[m.sourcesCur].node
	if n.leaf >= 0 {
		return
	}
	if m.sourcesCollapsed == nil {
		m.sourcesCollapsed = map[string]bool{}
	}
	m.sourcesCollapsed[n.path] = !m.sourcesCollapsed[n.path]
	m.buildSourceRows()
	if m.sourcesCur >= len(m.sourcesRows) {
		m.sourcesCur = max(0, len(m.sourcesRows)-1)
	}
}

// setAllSourcesCollapsed collapses or expands every directory node.
func (m *Model) setAllSourcesCollapsed(collapsed bool) {
	if !m.sourcesTree {
		return
	}
	if !collapsed {
		m.sourcesCollapsed = nil
	} else {
		m.sourcesCollapsed = map[string]bool{}
		roots := buildTree(m.sortedSourceIdxs(), func(i int) string { return m.sourcesFiles[i] }, segPath)
		eachInternal(roots, func(p string) { m.sourcesCollapsed[p] = true })
	}
	m.buildSourceRows()
	if m.sourcesCur >= len(m.sourcesRows) {
		m.sourcesCur = max(0, len(m.sourcesRows)-1)
	}
}

func (m *Model) mappedSourceLines(file string) map[int]bool {
	if file == "" {
		return nil
	}
	if m.srcCodeLineCache != nil {
		if lines, ok := m.srcCodeLineCache[file]; ok {
			return lines
		}
	}
	lines := m.file.MappedLines(file)
	if m.srcCodeLineCache == nil {
		m.srcCodeLineCache = make(map[string]map[int]bool)
	}
	m.srcCodeLineCache[file] = lines
	return lines
}

func (m *Model) sourceLineColumns(file string, line int) []int {
	if file == "" || line <= 0 {
		return nil
	}
	key := sourceLineCacheKey{file: file, line: line}
	if m.srcColumnCache != nil {
		if cols, ok := m.srcColumnCache[key]; ok {
			return cols
		}
	}
	cols := m.file.LineColumns(file, line)
	if m.srcColumnCache == nil {
		m.srcColumnCache = make(map[sourceLineCacheKey][]int)
	}
	m.srcColumnCache[key] = cols
	return cols
}

func (m *Model) ensureSourceBelowDisasmCursor() bool {
	if len(m.disasmInst) == 0 || m.disasmCur < 0 || m.disasmCur >= len(m.disasmInst) {
		return false
	}
	start := m.disasmCur + 1
	if start >= len(m.disasmInst) {
		return false
	}
	if sym, ok := m.file.SymbolAt(m.disasmInst[m.disasmCur].Addr); ok && sym.Size > 0 {
		end := sym.Addr + sym.Size
		if m.selectSourceFromInstRange(start, func(addr uint64) bool { return addr < end }) {
			return true
		}
		for start < len(m.disasmInst) && m.disasmInst[start].Addr < end {
			start++
		}
	}
	return m.selectSourceFromInstRange(start, func(uint64) bool { return true })
}

func (m *Model) selectSourceFromInstRange(start int, inRange func(uint64) bool) bool {
	for i := start; i < len(m.disasmInst); i++ {
		addr := m.disasmInst[i].Addr
		if !inRange(addr) {
			return false
		}
		file, line := m.file.LookupAddr(addr)
		if file == "" || line == 0 || m.file.SourceLines(file) == nil {
			continue
		}
		if m.srcFile != file {
			m.srcFile = file
			m.srcCodeLines = m.mappedSourceLines(file)
		}
		m.srcCur = line
		m.srcTop = 0
		m.syncSourceAsm()
		return true
	}
	return false
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
	if navKey(&m.sourcesCur, len(m.sourcesRows), m.listPage(), key) {
		return m, nil
	}
	switch key {
	case "/":
		m.sourcesFilter.Focus()
		return m, nil
	case "esc":
		dirty := m.sourcesAvail != availAll || m.sourcesFilter.Value() != "" || m.sourcesFilter.Focused()
		m.sourcesFilter.SetValue("")
		m.sourcesFilter.Blur()
		m.sourcesAvail = availAll
		m.sourcesCur, m.sourcesTop = 0, 0
		m.recomputeSourceFiles()
		if dirty {
			m.setStatus("filters cleared", false)
		}
		return m, nil
	case "ctrl+f":
		m.srcSearchAll = true
		m.openSearch()
		return m, nil
	case "alt+a":
		// cycle availability filter: all → present → missing → all
		switch m.sourcesAvail {
		case availAll:
			m.sourcesAvail = availPresent
		case availPresent:
			m.sourcesAvail = availMissing
		default:
			m.sourcesAvail = availAll
		}
		m.sourcesCur, m.sourcesTop = 0, 0
		m.recomputeSourceFiles()
		m.setStatus("sources: "+availLabel(m.sourcesAvail), false)
		return m, nil
	case "t":
		m.sourcesTree = !m.sourcesTree
		m.sourcesCur, m.sourcesTop = 0, 0
		m.recomputeSourceFiles()
		view := "flat list"
		if m.sourcesTree {
			view = "tree"
		}
		m.setStatus("sources view: "+view, false)
	case "-", "_":
		m.setAllSourcesCollapsed(true)
		m.setStatus("collapsed all", false)
	case "+", "=":
		m.setAllSourcesCollapsed(false)
		m.setStatus("expanded all", false)
	case "right":
		if m.sourcesTree {
			m.ensureSourcesCollapsed()
			if treeExpandOne(m.sourcesRows, &m.sourcesCur, m.sourcesCollapsed) {
				m.buildSourceRows()
			}
		}
	case "left":
		if m.sourcesTree {
			m.ensureSourcesCollapsed()
			if treeCollapseOne(m.sourcesRows, &m.sourcesCur, m.sourcesCollapsed) {
				m.buildSourceRows()
			}
		}
	case "S":
		if f, ok := m.sourceFileAt(m.sourcesCur); ok {
			m.copyToClipboard(f, "source path")
		}
	case "o":
		// Open the selected file in the disasm source-first view (doc #27: `o`
		// opens a source there, mirroring its "open lib as primary" role in Libs).
		if f, ok := m.sourceFileAt(m.sourcesCur); ok {
			m.openSourceFile(f, 1)
			m.setMode(modeDisasm)
			m.showSource = true
			m.sourceFirst = true
		}
	case "w":
		m.toggleWrap()
	case "enter", " ":
		if m.sourcesCur >= 0 && m.sourcesCur < len(m.sourcesRows) && m.sourcesRows[m.sourcesCur].node.leaf < 0 {
			m.ensureSourcesCollapsed()
			if treeToggleSubtree(m.sourcesRows, m.sourcesCur, m.sourcesCollapsed) {
				m.buildSourceRows()
			}
		} else if f, ok := m.sourceFileAt(m.sourcesCur); ok {
			m.openSourceFile(f, 1)
			m.setMode(modeDisasm)
			m.showSource = true
			m.sourceFirst = true
		}
	}
	return m, nil
}

func (m *Model) ensureSourcesCollapsed() {
	if m.sourcesCollapsed == nil {
		m.sourcesCollapsed = map[string]bool{}
	}
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
	case "S":
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
		m.srcCur = max(1, m.srcCur-m.listPage())
		m.syncSourceAsm()
	case "pgdown":
		m.srcCur = min(n, m.srcCur+m.listPage())
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
	m.srcCodeLines = m.mappedSourceLines(file)
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
func (t Theme) leftBorderPane(content string) string {
	return t.paneBorderStyle.Render(content)
}

func (m *Model) renderSourceList(bodyH int) string {
	if bodyH < 2 {
		bodyH = 2
	}
	filterRow := m.sourcesFilter.View()
	if !m.sourcesFilter.Focused() {
		facet := ""
		if m.sourcesTree {
			facet = "  tree"
		}
		if m.sourcesAvail != availAll {
			facet += "  " + m.theme.helpKeyStyle.Render("⌥a") + " " + availLabel(m.sourcesAvail)
		}
		filterRow = m.theme.footerStyle.Render(fmt.Sprintf("/ %s   (%d / %d source files)",
			m.sourcesFilter.Value(), len(m.sourcesFiltered), len(m.sourcesFiles))) + m.theme.footerStyle.Render(facet)
	}

	visible := bodyH - 1
	if visible < 1 {
		visible = 1
	}
	one := func(int) int { return 1 }
	top := m.visualTopForView(m.sourcesCur, m.sourcesTop, len(m.sourcesRows), visible, one)
	m.sourcesTop = top
	m.renderedSourcesTop = top
	m.pageRows = pageStep(top, len(m.sourcesRows), visible, one)
	end := top + visible
	if end > len(m.sourcesRows) {
		end = len(m.sourcesRows)
	}

	var b strings.Builder
	b.WriteString(filterRow)
	b.WriteString("\n")
	if len(m.sourcesRows) == 0 {
		b.WriteString(m.theme.footerStyle.Render(" (no source files)"))
		return padBody(b.String(), m.width, bodyH)
	}
	for i := top; i < end; i++ {
		row := m.sourcesRows[i]
		n := row.node
		selected := i == m.sourcesCur
		if n.leaf < 0 {
			collapsed := m.sourcesCollapsed != nil && m.sourcesCollapsed[n.path]
			b.WriteString(m.treeNodeRow(row.depth, n.label, n.count, collapsed, selected, " ", m.width))
			b.WriteString("\n")
			continue
		}
		full := m.sourcesFiles[n.leaf]
		indent := strings.Repeat(" ", row.depth*treeIndent)
		trunc := truncateMiddle(n.label, max(8, m.width-len(indent)-2))
		name := m.theme.colorPathByPrefix(full, trunc)
		if !m.file.SourceExists(full) { // not on disk: dim it (can't be opened)
			name = m.theme.srcShadowStyle.Render(trunc)
		}
		line := padRight(" "+indent+name, m.width)
		if selected {
			b.WriteString(m.theme.tableSelStyle.Render(ansi.Strip(line)))
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
	top = m.visualTopForView(m.srcCur-1, top, len(src), contentH, m.sourceRowHeight(w))
	m.srcTop = top + 1
	m.renderedSrcTop = top
	m.pageRows = pageStep(top, len(src), contentH, m.sourceRowHeight(w))

	var b strings.Builder
	suffix := fmt.Sprintf(":%d", m.srcCur)
	b.WriteString(m.theme.viewTitleLine(truncateMiddle(m.srcFile, max(1, w-lipgloss.Width(suffix)))+suffix, w))
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
		avail := w - lipgloss.Width(prefix)
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
			if caret := m.theme.coloredCaretRow(m.sourceLineColumns(m.srcFile, ln), gutterWidth, w); caret != "" {
				b.WriteString(caret)
				b.WriteString("\n")
				rows++
			}
		}
	}
	return padBody(b.String(), w, h)
}

// sourceRowHeight returns the per-line rendered-height function for the source
// pane at width w (the cursor line is one taller when it carries a caret row).
// Shared by every place that runs the source-pane scroll math.
func (m *Model) sourceRowHeight(w int) func(int) int {
	return func(i int) int {
		ln := i + 1
		h := m.sourceLineHeight(ln, w)
		if ln == m.srcCur && len(m.sourceLineColumns(m.srcFile, ln)) > 0 {
			h++
		}
		return h
	}
}

func (m *Model) sourceTextTop(w, contentH int) int {
	src := m.file.SourceLines(m.srcFile)
	return m.visualTopForView(m.srcCur-1, max(0, m.srcTop-1), len(src), contentH, m.sourceRowHeight(w))
}

func (m *Model) sourceLineHeight(line, w int) int {
	if !m.wrap {
		return 1
	}
	src := m.file.SourceLines(m.srcFile)
	if line < 1 || line > len(src) {
		return 1
	}
	key := sourceLineHeightKey{file: m.srcFile, line: line, w: w}
	if h, ok := m.srcLineHeightCache[key]; ok {
		return h
	}
	plainPrefix := fmt.Sprintf("%5d   ", line)
	h := len(renderLineRowsIndented(plainPrefix+src[line-1], w, true, gutterWidth))
	if m.srcLineHeightCache == nil {
		m.srcLineHeightCache = make(map[sourceLineHeightKey]int)
	}
	m.srcLineHeightCache[key] = h
	return h
}

// coloredCaretRow renders a '^' under each mapped column, each in that column's
// assigned colour (so it matches the highlighted instructions in the asm pane).
func (t *Theme) coloredCaretRow(cols []int, gutterW, w int) string {
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
			cells[c-1] = t.columnStyleAt(i).Bold(true).Render("^")
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

	anchor := m.sourceAsmAnchorIndex()
	cols := m.sourceLineColumns(m.srcFile, m.srcCur)
	head := m.sourceAsmHeader(anchor, cols, w)

	contentH := h - 1
	if contentH < 1 {
		contentH = 1
	}
	top := clampScroll(anchor-4+m.rightScroll, len(m.disasmInst), contentH)
	end := top + contentH
	if end > len(m.disasmInst) {
		end = len(m.disasmInst)
	}

	var b strings.Builder
	b.WriteString(head)
	b.WriteString("\n")
	addrW := m.file.AddrHexWidth()
	for i := top; i < end; i++ {
		b.WriteString(m.sourceAsmRow(i, addrW, w))
		b.WriteString("\n")
	}
	return padBody(b.String(), w, h)
}

func (m *Model) sourceAsmHeader(anchor int, cols []int, w int) string {
	const minSymbolHeaderWidth = 12
	sep := "  ·  "
	sepW := lipgloss.Width(sep)
	linePlain := fmt.Sprintf("line %d", m.srcCur)
	colsPlain := ""
	if len(cols) > 0 {
		colsPlain = "cols " + intsString(cols)
	}
	origColsPlain := colsPlain
	name := ""
	if anchor >= 0 && anchor < len(m.disasmInst) {
		addr := m.disasmInst[anchor].Addr
		if sym, ok := m.file.SymbolAt(addr); ok {
			name = m.displaySymbolName(sym)
			if off := addr - sym.Addr; off > 0 {
				name = fmt.Sprintf("%s+0x%x", name, off)
			}
		}
	}

	lineW := lipgloss.Width(linePlain)
	if name != "" && colsPlain != "" {
		colsBudget := w - lineW - sepW - sepW - minSymbolHeaderWidth
		colsPlain = truncateMiddle(colsPlain, max(1, colsBudget))
	}
	fixedW := lineW
	if colsPlain != "" {
		fixedW += sepW + lipgloss.Width(colsPlain)
	}

	var parts []string
	if name != "" {
		name = truncateMiddle(name, max(1, w-fixedW-sepW))
		parts = append(parts, m.theme.symbolNameStyle.Render(name))
	}
	parts = append(parts, linePlain)
	if colsPlain != "" {
		if colsPlain == origColsPlain {
			parts = append(parts, "cols "+m.theme.coloredCols(cols))
		} else {
			parts = append(parts, colsPlain)
		}
	}
	return m.theme.viewTitleLine(strings.Join(parts, sep), w)
}

func intsString(v []int) string {
	parts := make([]string, len(v))
	for i, n := range v {
		parts[i] = fmt.Sprintf("%d", n)
	}
	return strings.Join(parts, " ")
}

func (m *Model) sourceAsmAnchorIndex() int {
	if len(m.disasmInst) == 0 {
		return 0
	}
	if addr, ok := m.file.LineToAddr(m.srcFile, m.srcCur); ok {
		idx := m.instIndexAtOrAfterAddr(addr)
		if idx >= 0 && idx < len(m.disasmInst) {
			return idx
		}
	}
	if m.disasmCur < 0 {
		return 0
	}
	if m.disasmCur >= len(m.disasmInst) {
		return len(m.disasmInst) - 1
	}
	return m.disasmCur
}

func (m *Model) sourceAsmRow(i, addrW, w int) string {
	key := sourceAsmRowCacheKey{i: i, w: w, file: m.srcFile, line: m.srcCur}
	if m.sourceAsmRowCache != nil {
		if row, ok := m.sourceAsmRowCache[key]; ok {
			return row
		}
	}
	inst := m.disasmInst[i]
	// Colour only the address by mapping (shared addrMapStyle policy); the
	// instruction text keeps its normal class colours so the pane reads like
	// real disassembly.
	addrText := fmt.Sprintf("0x%0*x", addrW, inst.Addr)
	line := fmt.Sprintf(" %s  %s  %s",
		m.addrMapStyle(inst.Addr, m.srcFile, m.srcCur).Render(addrText),
		bytesHex(inst.Bytes, 6),
		m.renderInstText(inst.Text, inst.Class, inst.Addr))
	row := fitANSIWidth(line, w)
	if m.sourceAsmRowCache == nil {
		m.sourceAsmRowCache = make(map[sourceAsmRowCacheKey]string)
	}
	m.sourceAsmRowCache[key] = row
	return row
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
func (t *Theme) coloredCols(cols []int) string {
	parts := make([]string, len(cols))
	for i, c := range cols {
		parts[i] = t.columnStyleAt(i).Render(fmt.Sprintf("%d", c))
	}
	return strings.Join(parts, " ")
}
