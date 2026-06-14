package ui

// This file owns the info / overview view: the file header re-aligned into one
// column, plus overview, hardening (checksec-style), dynamic-linking, and
// toolchain blocks. The Entry line is actionable — Enter follows it into the
// disassembly. The whole page scrolls through headerVP.

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

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
	}
	var cmd tea.Cmd
	m.headerVP, cmd = m.headerVP.Update(msg)
	return m, cmd
}

func (m *Model) renderInfo() string {
	var b strings.Builder
	kv := func(k, v string) {
		b.WriteString(headerKey.Render(padKey(k, 16)))
		b.WriteString(" ")
		b.WriteString(v)
		b.WriteString("\n")
	}

	// Identity block (from the format header), re-aligned through kv() so it
	// shares one column with the rest of the page. The Entry line is special:
	// it carries the entry symbol and is actionable (Enter follows it).
	for _, l := range m.file.HeaderInfo() {
		if strings.HasPrefix(l, "Entry:") {
			kv("Entry:", m.entryValue())
			continue
		}
		if idx := strings.IndexByte(l, ':'); idx >= 0 {
			kv(l[:idx+1], strings.TrimSpace(l[idx+1:]))
		} else {
			b.WriteString(l)
			b.WriteString("\n")
		}
	}
	if m.dis != nil {
		kv("Disassembler:", m.dis.Name())
	}

	info := m.file.Info
	if info != nil {
		// Overview.
		b.WriteString("\n")
		kv("File size:", fmt.Sprintf("%s  (%d bytes)", humanBytes(info.FileSize), info.FileSize))
		if info.MappedHi > info.MappedLo {
			kv("Mapped range:", fmt.Sprintf("0x%x – 0x%x  (%s)", info.MappedLo, info.MappedHi, humanBytes(info.MappedHi-info.MappedLo)))
		}
		if info.CodeSize > 0 {
			kv("Code size:", humanBytes(info.CodeSize))
		}
		if info.WordBits != 0 {
			kv("Word size:", fmt.Sprintf("%d-bit, %s", info.WordBits, info.ByteOrder))
		}
		if info.Segments > 0 {
			kv(segmentLabel(m.file.Format)+":", fmt.Sprintf("%d", info.Segments))
		}

		// Hardening.
		b.WriteString("\n")
		kv("PIE:", info.PIE.String())
		kv("NX stack:", info.NX.String())
		if info.RELRO != "" {
			kv("RELRO:", info.RELRO)
		}
		kv("Stack canary:", yesNo(info.Canary))
		kv("FORTIFY:", yesNo(info.Fortify))
		if m.file.Format == binfile.FormatMachO {
			kv("Code signature:", yesNo(info.CodeSigned))
			if info.Encrypted {
				kv("Encrypted:", "yes")
			}
		}

		// Dynamic linking.
		b.WriteString("\n")
		if info.Interp != "" {
			kv("Interpreter:", info.Interp)
		}
		if info.SoName != "" {
			kv("SONAME:", info.SoName)
		}
		if len(info.RPath) > 0 {
			kv("RPATH:", strings.Join(info.RPath, ":"))
		}
		if len(info.RunPath) > 0 {
			kv("RUNPATH:", strings.Join(info.RunPath, ":"))
		}
		if info.BuildID != "" {
			kv("Build ID:", info.BuildID)
		}
		kv("Stripped:", yesNo(info.Stripped))
		kv("Static-linked:", yesNo(info.StaticLinked))
		if info.Libc.Kind != "" {
			val := info.Libc.Kind
			if info.Libc.Version != "" {
				val += " " + info.Libc.Version
			}
			if info.Libc.Source != "" {
				val += "  " + footerStyle.Render("("+info.Libc.Source+")")
			}
			kv("Libc:", val)
		}
		if len(info.DynamicLibs) > 0 {
			kv("Needed libs:", fmt.Sprintf("%d (press 6 to view)", len(info.DynamicLibs)))
		}

		// Toolchain / provenance.
		if info.SourceLang != "" || info.Compiler != "" || info.GoVersion != "" || info.MinOS != "" {
			b.WriteString("\n")
			if info.SourceLang != "" {
				kv("Language:", info.SourceLang)
			}
			// For Go binaries the toolchain is shown as "Go:" below; a stray
			// clang banner from cgo/deps would only mislead.
			if info.Compiler != "" && info.GoVersion == "" {
				kv("Compiler:", info.Compiler)
			}
			if info.GoVersion != "" {
				kv("Go:", info.GoVersion)
			}
			if info.GoModule != "" {
				kv("Go module:", info.GoModule)
			}
			if info.GoVCS != "" {
				kv("VCS:", info.GoVCS)
			}
			if info.MinOS != "" {
				v := info.MinOS
				if info.SDK != "" {
					v += "  (SDK " + info.SDK + ")"
				}
				kv("Min OS:", v)
			}
		}
	}

	m.headerVP.SetContent(strings.TrimRight(b.String(), "\n"))
	return m.headerVP.View()
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
		val += "  " + symbolNameStyle.Render(name)
	}
	if m.dis != nil && entry != 0 {
		val += "  " + footerStyle.Render("↵ disassemble")
	}
	return val
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
