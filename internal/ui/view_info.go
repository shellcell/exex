package ui

// This file owns the info / overview view: the file header re-aligned into one
// column, plus overview, hardening (checksec-style), dynamic-linking, and
// toolchain blocks. The Entry line is actionable — Enter follows it into the
// disassembly. The whole page scrolls through headerVP.

import (
	"fmt"
	"path/filepath"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/rabarbra/exex/internal/binfile"
)

func (m *Model) updateInfo(msg tea.KeyMsg, key string) (tea.Model, tea.Cmd) {
	switch key {
	case "home":
		m.headerVP.GotoTop()
		return m, nil
	case "end", "G":
		m.headerVP.GotoBottom()
		return m, nil
	case "enter":
		if m.dis != nil && m.file.Entry() != 0 {
			m.loadDisasmAt(m.file.Entry())
		}
		return m, nil
	case "a":
		if len(m.file.FatArches) > 1 {
			return m.switchFatArch()
		}
		return m, nil
	}
	var cmd tea.Cmd
	m.headerVP, cmd = m.headerVP.Update(msg)
	return m, cmd
}

// switchFatArch re-opens the binary at the next architecture slice of a fat
// Mach-O, returning a fresh model for it (the previous file stays mapped, like
// opening a library as primary, to avoid a use-after-unmap with any in-flight
// background decode).
func (m *Model) switchFatArch() (tea.Model, tea.Cmd) {
	arches := m.file.FatArches
	next := arches[0]
	for i, a := range arches {
		if a == m.file.FatArch {
			next = arches[(i+1)%len(arches)]
			break
		}
	}
	opts := []binfile.Option{binfile.WithArch(next)}
	if dp := m.file.DebugPath(); dp != "" {
		opts = append(opts, binfile.WithDebugPath(dp))
	}
	f, err := binfile.Open(m.file.Path, opts...)
	if err != nil {
		m.setStatus("switch arch: "+err.Error(), true)
		return m, nil
	}
	nm, err := New(f, Options{Config: &m.cfg})
	if err != nil {
		f.Close()
		m.setStatus("switch arch: "+err.Error(), true)
		return m, nil
	}
	nm.width, nm.height = m.width, m.height
	nm.setStatus("architecture: "+next, false)
	return nm, nm.Init()
}

// infoKeyWidth is the aligned width of the key column in the Info view.
const infoKeyWidth = 15

func (m *Model) renderInfo() string {
	bodyH := m.bodyHeight()
	innerW := max(1, m.width-4) // panel border (2) + padding (2)

	num := func(s string) string { return m.theme.asmNumberStyle.Render(s) }
	addrc := func(s string) string { return m.theme.addrStyle.Render(s) }
	dim := func(s string) string { return m.theme.srcShadowStyle.Render(s) }

	var b strings.Builder
	first := true
	// kv writes an indented, aligned "key  value" row; value is already styled.
	kv := func(k, v string) {
		k = strings.TrimSuffix(k, ":")
		b.WriteString("    ")
		b.WriteString(m.theme.headerKey.Render(padKey(k, infoKeyWidth)))
		b.WriteString(" ")
		b.WriteString(v)
		b.WriteByte('\n')
	}
	// kvText styles a plain value in the themed body foreground (renderStyle also
	// re-applies the view background after resets, like the rest of the panel).
	kvText := func(k, v string) { kv(k, renderStyle(v, 0, m.theme.tableRowStyle)) }
	// head opens a labelled group: an uppercase accent title followed by a dim
	// rule to the panel edge; a blank line precedes every group except the first.
	head := func(title string) {
		if !first {
			b.WriteString("\n")
		}
		first = false
		label := "  " + strings.ToUpper(title) + " "
		b.WriteString(m.theme.helpHeadStyle.Render(label))
		if fill := innerW - lipgloss.Width(label); fill > 0 {
			b.WriteString(dim(strings.Repeat("─", fill)))
		}
		b.WriteByte('\n')
	}

	info := m.file.Info

	// Summary line: the file at a glance.
	chips := []string{string(m.file.Format)}
	if m.dis != nil {
		chips = append(chips, m.dis.Name())
	}
	if t := headerField(m.file.HeaderInfo(), "Type:"); t != "" {
		chips = append(chips, t)
	}
	if info != nil {
		if info.PIE == binfile.TriYes {
			chips = append(chips, "PIE")
		}
		if info.StaticLinked {
			chips = append(chips, "static")
		} else {
			chips = append(chips, "dynamic")
		}
	}
	b.WriteString("  ")
	b.WriteString(m.theme.symbolNameStyle.Render("▸ " + filepath.Base(m.file.Path)))
	b.WriteString("   ")
	b.WriteString(dim(strings.Join(chips, " · ")))
	b.WriteString("\n\n")

	// Identity (from the format header). The Entry line is actionable.
	head("Identity")
	for _, l := range m.file.HeaderInfo() {
		if strings.HasPrefix(l, "Entry:") {
			kv("Entry", m.entryValue())
			continue
		}
		if idx := strings.IndexByte(l, ':'); idx >= 0 {
			kvText(l[:idx], strings.TrimSpace(l[idx+1:]))
		} else {
			b.WriteString("    ")
			b.WriteString(m.theme.tableRowStyle.Render(l))
			b.WriteString("\n")
		}
	}
	if m.dis != nil {
		kvText("Disassembler", m.dis.Name())
	}
	// Universal (fat) Mach-O: list the slices and which one is shown; `a` switches.
	if len(m.file.FatArches) > 1 {
		kv("Architectures", m.theme.tableRowStyle.Render(strings.Join(m.file.FatArches, ", "))+
			"  "+dim("(showing "+m.file.FatArch+", press a to switch)"))
	}

	if info != nil {
		// Overview — sizes in the number colour, addresses in the address colour.
		head("Overview")
		kv("File size", num(humanBytes(info.FileSize))+"  "+dim(fmt.Sprintf("(%d bytes)", info.FileSize)))
		if info.MappedHi > info.MappedLo {
			kv("Mapped range", addrc(fmt.Sprintf("0x%x – 0x%x", info.MappedLo, info.MappedHi))+
				"  "+dim("("+humanBytes(info.MappedHi-info.MappedLo)+")"))
		}
		if info.CodeSize > 0 {
			v := num(humanBytes(info.CodeSize))
			if info.FileSize > 0 {
				v += "  " + dim(fmt.Sprintf("(%.0f%% of file)", 100*float64(info.CodeSize)/float64(info.FileSize)))
			}
			kv("Code size", v)
		}
		if info.WordBits != 0 {
			kvText("Word size", fmt.Sprintf("%d-bit, %s", info.WordBits, info.ByteOrder))
		}
		if info.Segments > 0 {
			kv(segmentLabel(m.file.Format), num(fmt.Sprintf("%d", info.Segments)))
		}

		// Hardening — a ✓/✗/◐ badge coloured by how safe each setting is.
		head("Hardening")
		kv("PIE", m.triSec(info.PIE))
		kv("NX stack", m.triSec(info.NX))
		if info.RELRO != "" {
			kv("RELRO", m.relroSec(info.RELRO))
		}
		kv("Stack canary", m.boolSec(info.Canary, true))
		kv("FORTIFY", m.boolSec(info.Fortify, true))
		if m.file.Format == binfile.FormatMachO {
			kv("Code signature", m.boolSec(info.CodeSigned, true))
			if info.Encrypted {
				kv("Encrypted", m.theme.warnStyle.Render("⚠ yes"))
			}
		}

		// Dynamic linking.
		head("Dynamic linking")
		if info.Interp != "" {
			kvText("Interpreter", info.Interp)
		}
		if info.SoName != "" {
			kvText("SONAME", info.SoName)
		}
		if len(info.RPath) > 0 {
			kvText("RPATH", strings.Join(info.RPath, ":"))
		}
		if len(info.RunPath) > 0 {
			kvText("RUNPATH", strings.Join(info.RunPath, ":"))
		}
		if info.BuildID != "" {
			kv("Build ID", dim(info.BuildID))
		}
		kvText("Stripped", yesNo(info.Stripped))
		kvText("Static-linked", yesNo(info.StaticLinked))
		if info.Libc.Kind != "" {
			val := info.Libc.Kind
			if info.Libc.Version != "" {
				val += " " + info.Libc.Version
			}
			v := m.theme.tableRowStyle.Render(val)
			if info.Libc.Source != "" {
				v += "  " + dim("("+info.Libc.Source+")")
			}
			kv("Libc", v)
		}
		if len(info.DynamicLibs) > 0 {
			kv("Needed libs", num(fmt.Sprintf("%d", len(info.DynamicLibs)))+"  "+dim("(press 8 to view)"))
		}

		// Toolchain / provenance.
		if info.SourceLang != "" || info.Compiler != "" || info.GoVersion != "" || info.MinOS != "" {
			head("Toolchain")
			if info.SourceLang != "" {
				kvText("Language", info.SourceLang)
			}
			// For Go binaries the toolchain is shown as "Go:" below; a stray
			// clang banner from cgo/deps would only mislead.
			if info.Compiler != "" && info.GoVersion == "" {
				kvText("Compiler", info.Compiler)
			}
			if info.GoVersion != "" {
				kvText("Go", info.GoVersion)
			}
			if info.GoModule != "" {
				kvText("Go module", info.GoModule)
			}
			if info.GoVCS != "" {
				kvText("VCS", info.GoVCS)
			}
			if info.MinOS != "" {
				v := info.MinOS
				if info.SDK != "" {
					v += "  (SDK " + info.SDK + ")"
				}
				kvText("Min OS", v)
			}
		}
	}

	// Drop the single-column content into a full-width bordered panel. A long
	// page scrolls inside the panel via the viewport; the border rows (2) leave
	// bodyH-2 rows of content. Pad every line so the panel's right edge is flush.
	lines := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
	for i := range lines {
		lines[i] = padRight(lines[i], innerW)
	}

	m.headerVP.SetWidth(innerW)
	m.headerVP.SetHeight(max(1, bodyH-2))
	m.headerVP.SetContent(strings.Join(lines, "\n"))

	panel := m.theme.panelStyle.Render(m.headerVP.View())
	return lipgloss.Place(m.width, bodyH, lipgloss.Center, lipgloss.Top, panel)
}

// headerField returns the value of a "Key: value" line from a HeaderInfo slice.
func headerField(lines []string, key string) string {
	for _, l := range lines {
		if strings.HasPrefix(l, key) {
			return strings.TrimSpace(l[len(key):])
		}
	}
	return ""
}

// entryValue renders the entry point value: its address, the entry symbol, and
// a hint that Enter follows it into the disassembly.
func (m *Model) entryValue() string {
	entry := m.file.Entry()
	val := fmt.Sprintf("0x%0*x", m.file.AddrHexWidth(), entry)
	if sym, ok := m.file.SymbolAt(entry); ok {
		name := sym.Display()
		if off := entry - sym.Addr; off != 0 {
			name = fmt.Sprintf("%s+0x%x", name, off)
		}
		val += "  " + m.theme.symbolNameStyle.Render(name)
	}
	if m.dis != nil && entry != 0 {
		val += "  " + m.theme.footerStyle.Render("↵ disassemble")
	}
	return val
}

// boolSec renders a yes/no hardening flag with a ✓/✗ badge, green when it
// equals the hardened value and red otherwise.
func (m *Model) boolSec(v, hardenedWhenYes bool) string {
	if v == hardenedWhenYes {
		return m.theme.infoStyle.Render("✓ " + yesNo(v))
	}
	return m.theme.errorStyle.Render("✗ " + yesNo(v))
}

// triSec badges a tri-state hardening flag: enabled (hardened) green ✓, disabled
// red ✗, unknown dim ‐.
func (m *Model) triSec(t binfile.Tristate) string {
	switch t {
	case binfile.TriYes:
		return m.theme.infoStyle.Render("✓ " + t.String())
	case binfile.TriNo:
		return m.theme.errorStyle.Render("✗ " + t.String())
	}
	return m.theme.srcShadowStyle.Render("‐ " + t.String())
}

// relroSec badges RELRO: full = green ✓, partial = yellow ◐, none = red ✗.
func (m *Model) relroSec(s string) string {
	switch s {
	case "full":
		return m.theme.infoStyle.Render("✓ full")
	case "partial":
		return m.theme.warnStyle.Render("◐ partial")
	default:
		return m.theme.errorStyle.Render("✗ none")
	}
}

func segmentLabel(f binfile.Format) string {
	switch f {
	case binfile.FormatMachO:
		return "Load commands"
	case binfile.FormatELF:
		return "Program headers"
	}
	return "Segments"
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// humanBytes formats a byte count with a binary unit suffix.
func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// padKey right-pads a key label to a fixed column, ignoring the trailing colon
// for alignment purposes.
func padKey(s string, w int) string {
	if len(s) >= w {
		return s
	}
	return s + strings.Repeat(" ", w-len(s))
}
