package ui

// This file owns the dynamic-libraries view: a list of DT_NEEDED entries
// together with the linkage context (interpreter, libc kind, RPATH, RUNPATH).

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/explorer"
)

func (m *Model) updateLibs(key string) (tea.Model, tea.Cmd) {
	n := 0
	if m.file.Info != nil {
		n = len(m.file.Info.DynamicLibs)
	}
	if n == 0 {
		return m, nil
	}
	if navKey(&m.libsCur, n, m.bodyHeight(), key) {
		return m, nil
	}
	switch key {
	case "w":
		m.toggleWrap()
	case "c", "s":
		if m.file.Info != nil && m.libsCur < len(m.file.Info.DynamicLibs) {
			m.copyToClipboard(m.file.Info.DynamicLibs[m.libsCur], "library")
		}
	case "enter":
		if m.file.Info != nil && m.libsCur < len(m.file.Info.DynamicLibs) {
			m.openSymbolsForLib(m.file.Info.DynamicLibs[m.libsCur])
		}
	case "o":
		if m.file.Info != nil && m.libsCur < len(m.file.Info.DynamicLibs) {
			return m.openLibAsPrimary(m.file.Info.DynamicLibs[m.libsCur])
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
	nm.width, nm.height = m.width, m.height
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
		return padBody(body, m.width, bodyH)
	}

	b := strings.Builder{}
	b.WriteString(m.renderLibsHeader())
	headerH := lipgloss.Height(b.String())
	visible := bodyH - headerH
	if visible < 1 {
		visible = 1
	}
	rowHeight := func(i int) int {
		return m.libRowHeight(i)
	}
	top := m.visualTopForView(m.libsCur, m.libsTop, len(info.DynamicLibs), visible, rowHeight)
	m.libsTop = top
	m.renderedLibsTop = top
	for i := top; i < len(info.DynamicLibs); i++ {
		line := m.libRow(i, i == m.libsCur)
		for _, row := range renderLineRowsIndented(line, m.width, m.wrap, 6) {
			if lipgloss.Height(b.String()) >= bodyH {
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
	b.WriteString(m.tableHeader(fmt.Sprintf(" %3s  %s", "#", "Needed library")))
	b.WriteString("\n")
	return b.String()
}

func (m *Model) libsHeaderRows() int {
	if m.file.Info == nil || len(m.file.Info.DynamicLibs) == 0 {
		return 0
	}
	return lipgloss.Height(m.renderLibsHeader())
}

func (m *Model) libRowHeight(i int) int {
	if m.file.Info == nil || i < 0 || i >= len(m.file.Info.DynamicLibs) {
		return 1
	}
	return len(renderLineRowsIndented(m.libRow(i, false), m.width, m.wrap, 6))
}

func (m *Model) libRow(i int, selected bool) string {
	lib := m.file.Info.DynamicLibs[i]
	display := lib
	if !m.wrap {
		display = truncateMiddle(lib, max(1, m.width-7))
	}
	line := fmt.Sprintf(" %s  %s", m.theme.addrStyle.Render(fmt.Sprintf("%3d", i)), m.theme.colorPathByPrefix(lib, display))
	if selected {
		return m.theme.tableSelStyle.Render(ansi.Strip(line))
	}
	return m.theme.symbolNameStyle.Render(line)
}
