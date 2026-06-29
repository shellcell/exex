package ui

// This file owns the dynamic-libraries view: a list of DT_NEEDED entries
// together with the linkage context (interpreter, libc kind, RPATH, RUNPATH).

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/explorer"
)

// sortedLibIdxs returns the needed-library indices sorted alphabetically by
// path, so both the flat list and the (adjacency-based) tree read in order.
func (m *Model) sortedLibIdxs() ([]int, []string) {
	var libs []string
	if m.file.Info != nil {
		libs = m.file.Info.DynamicLibs
	}
	needle := strings.ToLower(m.libsFilter.Value())
	idxs := make([]int, 0, len(libs))
	for i := range libs {
		switch m.libsAvail {
		case availPresent:
			if m.libAvail(libs[i]) != libOnDisk {
				continue
			}
		case availCache:
			if m.libAvail(libs[i]) != libInCache {
				continue
			}
		}
		if needle != "" && !containsFold(libs[i], needle) {
			continue
		}
		idxs = append(idxs, i)
	}
	sort.Slice(idxs, func(a, b int) bool {
		if m.libsSortDesc {
			return libs[idxs[a]] > libs[idxs[b]]
		}
		return libs[idxs[a]] < libs[idxs[b]]
	})
	return idxs, libs
}

// buildLibRows flattens the needed libraries into a path tree (tree mode) or one
// leaf row per library (flat mode).
func (m *Model) buildLibRows() {
	idxs, libs := m.sortedLibIdxs()
	if m.libsTree {
		roots := buildTree(idxs, func(i int) string { return libs[i] }, segPath)
		if !m.libsTreeInit {
			m.libsTreeInit = true
			if m.treeCollapseDefault {
				m.libsCollapsed = map[string]bool{}
				eachInternal(roots, func(p string) { m.libsCollapsed[p] = true })
			}
		}
		m.libsRows = flattenTree(roots, m.libsCollapsed, 0, m.libsRows[:0])
		return
	}
	nodes := make([]treeNode, len(idxs))
	rows := m.libsRows[:0]
	for k, idx := range idxs {
		nodes[k] = treeNode{label: libs[idx], leaf: idx, count: 1}
		rows = append(rows, treeRow{node: &nodes[k], depth: 0})
	}
	m.libsRows = rows
}

// libAt returns the library string for a leaf row.
func (m *Model) libAt(rowIdx int) (string, bool) {
	if m.file.Info == nil || rowIdx < 0 || rowIdx >= len(m.libsRows) {
		return "", false
	}
	n := m.libsRows[rowIdx].node
	if n.leaf < 0 {
		return "", false
	}
	return m.file.Info.DynamicLibs[n.leaf], true
}

func (m *Model) ensureLibsCollapsed() {
	if m.libsCollapsed == nil {
		m.libsCollapsed = map[string]bool{}
	}
}

func (m *Model) toggleLibNode() {
	if m.libsCur < 0 || m.libsCur >= len(m.libsRows) || m.libsRows[m.libsCur].node.leaf >= 0 {
		return
	}
	if m.libsCollapsed == nil {
		m.libsCollapsed = map[string]bool{}
	}
	p := m.libsRows[m.libsCur].node.path
	m.libsCollapsed[p] = !m.libsCollapsed[p]
	m.buildLibRows()
	if m.libsCur >= len(m.libsRows) {
		m.libsCur = max(0, len(m.libsRows)-1)
	}
}

func (m *Model) setAllLibsCollapsed(collapsed bool) {
	if !m.libsTree || m.file.Info == nil {
		return
	}
	if !collapsed {
		m.libsCollapsed = nil
	} else {
		m.libsCollapsed = map[string]bool{}
		idxs, libs := m.sortedLibIdxs()
		roots := buildTree(idxs, func(i int) string { return libs[i] }, segPath)
		eachInternal(roots, func(p string) { m.libsCollapsed[p] = true })
	}
	m.buildLibRows()
	if m.libsCur >= len(m.libsRows) {
		m.libsCur = max(0, len(m.libsRows)-1)
	}
}

func (m *Model) updateLibs(key string) (tea.Model, tea.Cmd) {
	if m.file.Info == nil || len(m.file.Info.DynamicLibs) == 0 {
		return m, nil
	}
	m.buildLibRows()
	if navKey(&m.libsCur, len(m.libsRows), m.listPage(), key) {
		return m, nil
	}
	switch key {
	case "/":
		m.libsFilter.Focus()
	case "esc":
		dirty := m.libsAvail != availAll || m.libsFilter.Value() != "" || m.libsFilter.Focused()
		m.libsFilter.SetValue("")
		m.libsFilter.Blur()
		m.libsAvail = availAll
		m.libsCur, m.libsTop = 0, 0
		m.buildLibRows()
		if dirty {
			m.setStatus("filters cleared", false)
		}
	case "s":
		// Libraries sort by name only; report the (single) field for consistency.
		m.setStatus("sort: name", false)
	case "r":
		m.libsSortDesc = !m.libsSortDesc
		m.libsCur, m.libsTop = 0, 0
		m.buildLibRows()
		dir := "ascending"
		if m.libsSortDesc {
			dir = "descending"
		}
		m.setStatus("sort order: "+dir, false)
	case "w":
		m.toggleWrap()
	case "alt+a":
		// cycle availability filter: all → on-disk → in-cache → all
		switch m.libsAvail {
		case availAll:
			m.libsAvail = availPresent
		case availPresent:
			m.libsAvail = availCache
		default:
			m.libsAvail = availAll
		}
		m.libsCur, m.libsTop = 0, 0
		m.buildLibRows()
		m.setStatus("libs: "+availLabel(m.libsAvail), false)
	case "t":
		m.setStatus(m.cycleLibsMode(), false)
	case "-", "_":
		m.setAllLibsCollapsed(true)
		m.setStatus("collapsed all", false)
	case "+", "=":
		m.setAllLibsCollapsed(false)
		m.setStatus("expanded all", false)
	case "right":
		if m.libsTree {
			m.ensureLibsCollapsed()
			if treeExpandOne(m.libsRows, &m.libsCur, m.libsCollapsed) {
				m.buildLibRows()
			}
		}
	case "left":
		if m.libsTree {
			m.ensureLibsCollapsed()
			if treeCollapseOne(m.libsRows, &m.libsCur, m.libsCollapsed) {
				m.buildLibRows()
			}
		}
	case "S":
		if lib, ok := m.libAt(m.libsCur); ok {
			m.copyToClipboard(lib, "library")
		}
	case "enter", " ":
		if m.libsCur < len(m.libsRows) && m.libsRows[m.libsCur].node.leaf < 0 {
			m.ensureLibsCollapsed()
			if treeToggleSubtree(m.libsRows, m.libsCur, m.libsCollapsed) {
				m.buildLibRows()
			}
		} else if lib, ok := m.libAt(m.libsCur); ok {
			m.openSymbolsForLib(lib)
		}
	case "o":
		if lib, ok := m.libAt(m.libsCur); ok {
			return m.openLibAsPrimary(lib)
		}
	}
	return m, nil
}

func (m *Model) openSymbolsForLib(lib string) {
	n := 0
	for _, s := range m.file.Symbols {
		if s.Library == lib {
			n++
		}
	}
	if n == 0 {
		m.setStatus("no imported symbols resolved to "+lib, true)
		return
	}
	m.symbolsFilter.SetValue("")
	m.symbolsLib = lib
	m.symbolsKindOn = false
	m.symbolsCur, m.symbolsTop = 0, 0
	m.recomputeSymbols()
	m.setMode(modeSymbols)
	m.setStatus(fmt.Sprintf("%d symbols imported from %s — Esc clears", n, lib), false)
}

func (m *Model) openLibAsPrimary(lib string) (tea.Model, tea.Cmd) {
	path, ok := explorer.ResolveLibPath(lib, m.file.Path, m.file.Info, nil)
	if !ok {
		if explorer.IsDyldSharedCacheLib(lib) {
			m.setStatus("system library "+lib+" lives in the dyld shared cache, not on disk — can't open", true)
		} else {
			m.setStatus("could not resolve library on disk: "+lib, true)
		}
		return m, nil
	}
	f, err := binfile.Open(path)
	if err != nil {
		m.setStatus("open library: "+err.Error(), true)
		return m, nil
	}
	nm, err := New(f, Options{Config: &m.cfg})
	if err != nil {
		m.setStatus("open library: "+err.Error(), true)
		return m, nil
	}
	// Descending into a dependency — remember where we came from so Back returns.
	m.enterFile(nm, filepath.Base(path))
	nm.setStatus("opened dependency "+filepath.Base(path)+"  (Ctrl+O: back)", false)
	return nm, nm.switchMode(modeInfo)
}

func (m *Model) renderLibs() string {
	bodyH := m.bodyHeight()
	info := m.file.Info
	if info == nil || len(info.DynamicLibs) == 0 {
		body := "no dynamic libraries — this binary is statically linked or has no DT_NEEDED entries\n"
		if info != nil && info.StaticLinked {
			body += "\n" + m.theme.headerKey.Render("Static-linked:") + " yes\n"
			if info.Libc.Kind != "" && info.Libc.Kind != "none" {
				body += m.theme.headerKey.Render("Libc:") + " " + info.Libc.Kind
				if info.Libc.Version != "" {
					body += " " + info.Libc.Version
				}
				body += "\n"
			}
		}
		return lipgloss.Place(m.width, bodyH, lipgloss.Center, lipgloss.Center, strings.TrimRight(body, "\n"))
	}

	m.buildLibRows()
	b := strings.Builder{}
	b.WriteString(m.renderLibsHeader())
	headerH := m.libsHeaderRows()
	visible := bodyH - headerH
	if visible < 1 {
		visible = 1
	}
	rowHeight := func(i int) int {
		return m.libRowHeight(i)
	}
	top := m.visualTopForView(m.libsCur, m.libsTop, len(m.libsRows), visible, rowHeight)
	m.libsTop = top
	m.pageRows = pageStep(top, len(m.libsRows), visible, rowHeight)
	m.renderedLibsTop = top
	if len(m.libsRows) == 0 {
		b.WriteString(m.placeCentred("no matching libraries  ·  Esc clears filters", bodyH-headerH))
		return padBody(b.String(), m.width, bodyH)
	}
	for i := top; i < len(m.libsRows); i++ {
		line := m.libRow(i, i == m.libsCur)
		for _, row := range renderLineRowsIndented(line, m.width, m.wrap, 6) {
			if renderedLineCount(b.String()) >= bodyH {
				break
			}
			b.WriteString(row)
			b.WriteString("\n")
		}
	}
	return padBody(b.String(), m.width, bodyH)
}

func (m *Model) renderLibsHeader() string {
	info := m.file.Info
	var b strings.Builder
	if info.Interp != "" {
		b.WriteString(m.theme.headerKey.Render("Interpreter: "))
		b.WriteString(info.Interp)
		b.WriteString("\n")
	}
	if info.Libc.Kind != "" {
		libcLine := info.Libc.Kind
		if info.Libc.Version != "" {
			libcLine += " " + info.Libc.Version
		}
		if info.Libc.Source != "" {
			libcLine += "  " + m.theme.footerStyle.Render("("+info.Libc.Source+")")
		}
		b.WriteString(m.theme.headerKey.Render("Libc:        "))
		b.WriteString(libcLine)
		b.WriteString("\n")
	}
	if len(info.RPath) > 0 {
		b.WriteString(m.theme.headerKey.Render("RPATH:       "))
		b.WriteString(strings.Join(info.RPath, ":"))
		b.WriteString("\n")
	}
	if len(info.RunPath) > 0 {
		b.WriteString(m.theme.headerKey.Render("RUNPATH:     "))
		b.WriteString(strings.Join(info.RunPath, ":"))
		b.WriteString("\n")
	}
	b.WriteString("\n")
	if m.libsFilter.Focused() {
		b.WriteString(m.libsFilter.View())
		b.WriteString("\n")
	} else if m.libsFilter.Value() != "" {
		b.WriteString(m.theme.footerStyle.Render("/ " + m.libsFilter.Value()))
		b.WriteString("\n")
	}
	suffix := m.libsHeaderSuffix()
	hdr := " " + activeSortHeaderLabel("Needed libraries", m.libsTitleWidth(), m.libsSortDesc) + suffix
	b.WriteString(m.tableHeader(hdr))
	b.WriteString("\n")
	return b.String()
}

func (m *Model) libsHeaderSuffix() string {
	suffix := ""
	if m.libsAvail != availAll {
		suffix += "  " + m.theme.helpKeyStyle.Render(altKeys("a")) + m.theme.footerStyle.Render(" "+availLabel(m.libsAvail))
	}
	if m.libsTree {
		suffix += "  " + m.theme.footerStyle.Render("(tree · ←/→ fold · ↵ all below · +/− all · t flat)")
	}
	return suffix
}

func (m *Model) libsTitleWidth() int {
	return lipgloss.Width("Needed libraries") + 3
}

func (m *Model) libsHeaderRows() int {
	if m.file.Info == nil || len(m.file.Info.DynamicLibs) == 0 {
		return 0
	}
	return renderedLineCount(m.renderLibsHeader())
}

func (m *Model) libsTitleRow() int {
	rows := m.libsHeaderRows()
	if rows == 0 {
		return -1
	}
	return rows - 1
}

func renderedLineCount(s string) int {
	if s == "" {
		return 0
	}
	return lipgloss.Height(strings.TrimSuffix(s, "\n"))
}

func (m *Model) libRowHeight(i int) int {
	if i < 0 || i >= len(m.libsRows) {
		return 1
	}
	return len(renderLineRowsIndented(m.libRow(i, false), m.width, m.wrap, 6))
}

func (m *Model) libRow(i int, selected bool) string {
	row := m.libsRows[i]
	n := row.node
	if n.leaf < 0 {
		collapsed := m.libsCollapsed != nil && m.libsCollapsed[n.path]
		return m.treeNodeRow(row.depth, n.label, n.count, collapsed, selected, " ", m.width)
	}
	indent := strings.Repeat(" ", row.depth*treeIndent)
	lib := m.file.Info.DynamicLibs[n.leaf]
	display := n.label // basename in tree mode, full path in flat mode
	// Mark libs that aren't openable on disk: dim them and tag the reason.
	tag := ""
	switch m.libAvail(lib) {
	case libInCache:
		tag = "  ·cache"
	case libMissing:
		tag = "  ·missing"
	}
	if !m.wrap {
		display = truncateMiddle(display, max(1, m.width-len(indent)-2-len(tag)))
	}
	var line string
	if tag != "" {
		line = " " + indent + m.theme.srcShadowStyle.Render(display+tag)
	} else {
		line = " " + indent + m.theme.colorPathByPrefix(lib, display)
	}
	if selected {
		return m.theme.tableSelStyle.Render(ansi.Strip(line))
	}
	return m.theme.symbolNameStyle.Render(line)
}
