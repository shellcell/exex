package ui

// This file owns the dynamic-libraries view: a list of DT_NEEDED entries
// together with the linkage context (interpreter, libc kind, RPATH, RUNPATH).

import (
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/rabarbra/exex/internal/binfile"
)

func (m *Model) updateLibs(key string) (tea.Model, tea.Cmd) {
	n := 0
	if m.file.Info != nil {
		n = len(m.file.Info.DynamicLibs)
	}
	if n == 0 {
		return m, nil
	}
	switch key {
	case "w":
		m.wrap = !m.wrap
		m.setStatus(wrapStatus(m.wrap), false)
	case "up", "k":
		if m.libsCur > 0 {
			m.libsCur--
		}
	case "down", "j":
		if m.libsCur < n-1 {
			m.libsCur++
		}
	case "pgup":
		m.libsCur = max(0, m.libsCur-m.bodyHeight())
	case "pgdown":
		m.libsCur = min(n-1, m.libsCur+m.bodyHeight())
	case "home":
		m.libsCur = 0
	case "end", "G":
		m.libsCur = n - 1
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
	base := strings.TrimSuffix(strings.TrimPrefix(lib, "lib"), filepathExt(lib))
	if base == "" {
		m.setStatus("no imported symbol index for "+lib, true)
		return
	}
	m.symbolsFilter.SetValue(base)
	m.symbolsKindOn = false
	m.recomputeSymbols()
	m.mode = modeSymbols
	m.setStatus("symbols filtered by library hint: "+base, false)
}

func (m *Model) openLibAsPrimary(path string) (tea.Model, tea.Cmd) {
	if _, err := os.Stat(path); err != nil {
		m.setStatus("library path is not directly openable: "+path, true)
		return m, nil
	}
	f, err := binfile.Open(path)
	if err != nil {
		m.setStatus("open library: "+err.Error(), true)
		return m, nil
	}
	nm, err := New(f)
	if err != nil {
		m.setStatus("open library: "+err.Error(), true)
		return m, nil
	}
	nm.width, nm.height = m.width, m.height
	return nm, nm.switchMode(modeInfo)
}

func filepathExt(path string) string {
	idx := strings.LastIndexByte(path, '/')
	name := path
	if idx >= 0 {
		name = path[idx+1:]
	}
	if dot := strings.LastIndexByte(name, '.'); dot >= 0 {
		return name[dot:]
	}
	return ""
}

func (m *Model) renderLibs() string {
	bodyH := m.bodyHeight()
	info := m.file.Info
	if info == nil || len(info.DynamicLibs) == 0 {
		body := "no dynamic libraries — this binary is statically linked or has no DT_NEEDED entries\n"
		if info != nil && info.StaticLinked {
			body += "\n" + headerKey.Render("Static-linked:") + " yes\n"
			if info.Libc.Kind != "" && info.Libc.Kind != "none" {
				body += headerKey.Render("Libc:") + " " + info.Libc.Kind
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
	ensureVisualTop(m.libsCur, &m.libsTop, len(info.DynamicLibs), visible, rowHeight)
	for i := m.libsTop; i < len(info.DynamicLibs); i++ {
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
		b.WriteString(headerKey.Render("Interpreter: "))
		b.WriteString(info.Interp + "\n")
	}
	if info.Libc.Kind != "" {
		libcLine := info.Libc.Kind
		if info.Libc.Version != "" {
			libcLine += " " + info.Libc.Version
		}
		if info.Libc.Source != "" {
			libcLine += "  " + footerStyle.Render("("+info.Libc.Source+")")
		}
		b.WriteString(headerKey.Render("Libc:        "))
		b.WriteString(libcLine + "\n")
	}
	if len(info.RPath) > 0 {
		b.WriteString(headerKey.Render("RPATH:       "))
		b.WriteString(strings.Join(info.RPath, ":") + "\n")
	}
	if len(info.RunPath) > 0 {
		b.WriteString(headerKey.Render("RUNPATH:     "))
		b.WriteString(strings.Join(info.RunPath, ":") + "\n")
	}
	b.WriteString("\n")
	b.WriteString(tableHeaderStyle.Render(padRight(fmt.Sprintf(" %3s  %s", "#", "Needed library"), m.width)))
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
	line := fmt.Sprintf(" %s  %s", addrStyle.Render(fmt.Sprintf("%3d", i)), colorPathByPrefix(lib, lib))
	if selected {
		return tableSelStyle.Render(stripANSI(line))
	}
	return symbolNameStyle.Render(line)
}
