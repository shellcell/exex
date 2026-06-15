package ui

// This file owns the dynamic-libraries view: a list of DT_NEEDED entries
// together with the linkage context (interpreter, libc kind, RPATH, RUNPATH).

import (
	"fmt"
	"os"
	"path/filepath"
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
	m.mode = modeSymbols
	m.setStatus(fmt.Sprintf("%d symbols imported from %s — Esc clears", n, lib), false)
}

func (m *Model) openLibAsPrimary(lib string) (tea.Model, tea.Cmd) {
	path, ok := m.resolveLibPath(lib)
	if !ok {
		if isDyldSharedCacheLib(lib) {
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
	nm, err := New(f)
	if err != nil {
		m.setStatus("open library: "+err.Error(), true)
		return m, nil
	}
	nm.width, nm.height = m.width, m.height
	return nm, nm.switchMode(modeInfo)
}

// resolveLibPath turns a DT_NEEDED entry / Mach-O dylib path into a concrete
// file on disk, following dyld's @rpath / @loader_path / @executable_path
// substitutions and the ELF RPATH/RUNPATH + default search directories. Returns
// false when nothing on disk matches (e.g. macOS system dylibs that only exist
// inside the shared cache).
func (m *Model) resolveLibPath(lib string) (string, bool) {
	exists := func(p string) bool {
		if p == "" {
			return false
		}
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return true
		}
		return false
	}

	loaderDir := filepath.Dir(m.file.Path)
	subst := func(p string) string {
		p = strings.ReplaceAll(p, "@loader_path", loaderDir)
		p = strings.ReplaceAll(p, "@executable_path", loaderDir)
		return p
	}

	var rpaths []string
	if m.file.Info != nil {
		rpaths = append(rpaths, m.file.Info.RunPath...)
		rpaths = append(rpaths, m.file.Info.RPath...)
	}

	// @rpath/foo → try each RPATH entry. @loader_path/@executable_path resolve
	// directly against the binary's directory.
	if rest, ok := strings.CutPrefix(lib, "@rpath/"); ok {
		for _, rp := range rpaths {
			if cand := filepath.Join(subst(rp), rest); exists(cand) {
				return cand, true
			}
		}
		return "", false
	}
	if strings.HasPrefix(lib, "@loader_path") || strings.HasPrefix(lib, "@executable_path") {
		if cand := subst(lib); exists(cand) {
			return cand, true
		}
		return "", false
	}

	// Absolute or relative path that exists as-is.
	if exists(lib) {
		return lib, true
	}

	// ELF basename (libc.so.6): search RPATH/RUNPATH then the standard dirs.
	base := filepath.Base(lib)
	for _, rp := range rpaths {
		if cand := filepath.Join(subst(rp), base); exists(cand) {
			return cand, true
		}
	}
	for _, dir := range []string{"/lib", "/usr/lib", "/lib64", "/usr/lib64", "/usr/local/lib", "/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu", "/lib/aarch64-linux-gnu", "/usr/lib/aarch64-linux-gnu"} {
		if cand := filepath.Join(dir, base); exists(cand) {
			return cand, true
		}
	}
	return "", false
}

// isDyldSharedCacheLib reports whether a Mach-O dependency is a macOS system
// library that, on recent macOS, exists only inside the dyld shared cache and
// has no standalone file on disk.
func isDyldSharedCacheLib(lib string) bool {
	return strings.HasPrefix(lib, "/usr/lib/") ||
		strings.HasPrefix(lib, "/System/Library/") ||
		strings.HasPrefix(lib, "/Library/Apple/")
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
