// Package info implements the normal Info overview page: the file header
// re-aligned into one column, plus overview, hardening, dynamic-linking and
// toolchain blocks. Archive member browsing and fat-arch switching stay in the
// shell because they replace the whole UI model.
package info

import (
	"fmt"
	"path/filepath"
	"strings"

	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/shellcell/exex/internal/binfile"
	"github.com/shellcell/exex/internal/ui/layout"
	"github.com/shellcell/exex/internal/ui/view"
)

// State stores the scroll viewport and styled-body cache for the Info page.
type State struct {
	VP    viewport.Model
	Body  string
	BodyW int
}

// NewState returns an Info state with its viewport initialized.
func NewState() State { return State{VP: viewport.New()} }

// DropCaches discards the cached styled Info body (e.g. after a theme change).
func (st *State) DropCaches() {
	st.Body = ""
	st.BodyW = 0
}

// Update handles keys for the normal Info overview page. Model-replacing actions
// (`t` for archive members / fat slices) are intercepted by the shell adapter.
func (st *State) Update(ctx view.Context, host view.Host, msg tea.KeyMsg, key string) tea.Cmd {
	switch key {
	case "home":
		st.VP.GotoTop()
		return nil
	case "end", "G":
		st.VP.GotoBottom()
		return nil
	case "enter":
		// Follow the entry point into disasm; fall back to hex only when it can't be
		// disassembled at all (no decoder, or not in any code/data section). An entry
		// in a non-executable section (e.g. a kernel's multiboot stub) still goes to
		// disasm via disasm-all.
		if entry := ctx.File.Entry(); entry != 0 {
			canDisasm := ctx.CanDisasmAt != nil && ctx.CanDisasmAt(entry)
			if ctx.DisassemblerName != "" && (canDisasm || ctx.File.AddrDisassemblable(entry)) {
				host.JumpDisasmAtAddr(entry)
			} else {
				host.OpenHexAt(entry)
			}
		}
		return nil
	}
	var cmd tea.Cmd
	st.VP, cmd = st.VP.Update(msg)
	return cmd
}

// Scroll moves the Info viewport by delta rows.
func (st *State) Scroll(delta int) {
	if delta < 0 {
		st.VP.ScrollUp(-delta)
	} else if delta > 0 {
		st.VP.ScrollDown(delta)
	}
}

// Render draws the Info page.
func (st *State) Render(ctx view.Context) string {
	bodyH := ctx.BodyH
	innerW := max(1, ctx.Width-4) // panel border (2) + padding (2)

	// The styled content is static per (width, theme, arch slice) — only the
	// viewport scroll changes per frame — so build it once and cache by width. A
	// theme change clears it via DropCaches; an arch switch builds a fresh model.
	// Compiler() is scanned lazily during this first build, then cached.
	rebuilt := st.Body == "" || st.BodyW != innerW
	if rebuilt {
		st.Body = buildContent(ctx, innerW)
		st.BodyW = innerW
	}
	st.VP.SetWidth(innerW)
	st.VP.SetHeight(max(1, bodyH-2))
	if rebuilt {
		st.VP.SetContent(st.Body)
	}
	panel := ctx.PanelStyle.Render(st.VP.View())
	return lipgloss.Place(ctx.Width, bodyH, lipgloss.Center, lipgloss.Top, panel)
}

// buildContent renders the Info page's single-column body to width innerW
// (padded lines ready for the viewport). Cached by Render.
func buildContent(ctx view.Context, innerW int) string {
	num := func(s string) string { return ctx.NumberStyle.Render(s) }
	addrc := func(s string) string { return ctx.AddrStyle.Render(s) }
	dim := func(s string) string { return ctx.ShadowStyle.Render(s) }
	// press renders a "press <key>" hint with the key itself in the accent colour
	// the footer and table headers use, so a key looks like a key wherever it is
	// named. tail is any dim text following it (" — full ELF header fields").
	press := func(key, tail string) string {
		return dim("press ") + ctx.KeyStyle.Render(key) + dim(tail)
	}

	var b strings.Builder
	first := true
	// kv writes an indented, aligned "key  value" row; value is already styled.
	kv := func(k, v string) {
		k = strings.TrimSuffix(k, ":")
		b.WriteString("    ")
		b.WriteString(ctx.LabelStyle.Render(padKey(k, infoKeyWidth)))
		b.WriteString(" ")
		b.WriteString(v)
		b.WriteByte('\n')
	}
	// kvText styles a plain value in the themed body foreground (RenderStyle also
	// re-applies the view background after resets, like the rest of the panel).
	kvText := func(k, v string) { kv(k, layout.RenderStyle(v, 0, ctx.RowStyle)) }
	// head opens a labelled group: an uppercase accent title followed by a dim
	// rule to the panel edge; a blank line precedes every group except the first.
	head := func(title string) {
		if !first {
			b.WriteString("\n")
		}
		first = false
		label := "  " + strings.ToUpper(title) + " "
		b.WriteString(ctx.HeadStyle.Render(label))
		if fill := innerW - lipgloss.Width(label); fill > 0 {
			b.WriteString(dim(strings.Repeat("─", fill)))
		}
		b.WriteByte('\n')
	}

	info := ctx.File.Info

	// Summary line: the file at a glance.
	chips := []string{string(ctx.File.Format)}
	if ctx.DisassemblerName != "" {
		chips = append(chips, ctx.DisassemblerName)
	}
	if t := headerField(ctx.File.HeaderInfo(), "Type:"); t != "" {
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
	b.WriteString(ctx.SymStyle.Render("▸ " + filepath.Base(ctx.File.Path)))
	b.WriteString("   ")
	b.WriteString(dim(strings.Join(chips, " · ")))
	b.WriteString("\n\n")

	// Identity (from the format header). The Entry line is actionable.
	head("Identity")
	// These header fields are shown (more usefully) in the Requirements / Contents
	// blocks below, so skip them here to avoid repetition.
	identitySkip := map[string]bool{"CPU": true, "64-bit": true, "Sections": true, "Symbols": true, "DWARF info": true}
	for _, l := range ctx.File.HeaderInfo() {
		if strings.HasPrefix(l, "Entry:") {
			kv("Entry", entryValue(ctx))
			continue
		}
		if idx := strings.IndexByte(l, ':'); idx >= 0 {
			key, val := l[:idx], strings.TrimSpace(l[idx+1:])
			if identitySkip[key] {
				continue
			}
			// Explain the file type in plain language (Dylib -> dynamic library, ...).
			if key == "Type" {
				if exp := fileTypeExplain(val); exp != "" {
					kv("Type", ctx.RowStyle.Render(val)+"  "+dim("("+exp+")"))
					continue
				}
			}
			kvText(key, val)
		} else {
			b.WriteString("    ")
			b.WriteString(ctx.RowStyle.Render(l))
			b.WriteString("\n")
		}
	}
	// The disassembler is only worth surfacing when there isn't one — then it
	// explains why disasm is unavailable.
	if ctx.DisassemblerName == "" {
		kvText("Disassembler", ctx.WarnStyle.Render("none for this architecture"))
	}
	if ctx.File.SyntheticAddrs() {
		kvText("Addresses", ctx.WarnStyle.Render("synthetic")+dim("  — relocatable object; exex lays sections out so they don't collide. Real positions are section-relative."))
	}
	// Universal (fat) Mach-O: a per-architecture listing. Shown for every fat
	// binary; the slice currently loaded is marked, and `a` switches between them.
	if infos := ctx.File.FatArchInfos; len(infos) > 1 {
		head("Architectures")
		nameW, typeW := 0, 0
		for _, a := range infos {
			nameW = max(nameW, len(a.Name))
			typeW = max(typeW, len(a.Type))
		}
		for _, a := range infos {
			current := a.Name == ctx.File.FatArch
			marker := "  "
			if current {
				marker = ctx.SymStyle.Render("▸ ")
			}
			row := "    " + marker +
				ctx.RowStyle.Render(layout.PadRight(a.Name, nameW)) + "   " +
				dim(layout.PadRight(a.Type, typeW)) + "   " +
				dim(fmt.Sprintf("%d-bit", a.Bits)) + "   " +
				addrc(fmt.Sprintf("@ 0x%08x", a.Offset)) + "   " +
				num(humanBytes(a.Size))
			if current {
				row += "   " + ctx.InfoStyle.Render("● loaded") + dim(" · ") + press("t", " to switch slice")
			}
			b.WriteString(row)
			b.WriteString("\n")
		}
	}

	if info != nil {
		// Requirements — the consolidated "what it takes to run this": the CPU it
		// targets, the minimum OS, and how it links. Details live below; this is the
		// at-a-glance answer.
		head("Requirements")
		archLine := ctx.File.Arch().String()
		if info.WordBits != 0 {
			archLine += fmt.Sprintf("  ·  %d-bit  ·  %s", info.WordBits, info.ByteOrder)
		}
		kvText("CPU / arch", archLine)
		if info.MinOS != "" {
			kvText("Minimum OS", info.MinOS)
		}
		link := "dynamically linked"
		if info.StaticLinked {
			link = "statically linked"
		}
		if info.PIE == binfile.TriYes {
			link += "  ·  PIE"
		}
		kvText("Linking", link)
		kv("CPU features", press("⇧F", " to detect (SSE / AVX / NEON / …)"))

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
			kv(segmentLabel(ctx.File.Format), num(fmt.Sprintf("%d", info.Segments)))
		}

		// Contents — what's inside and the key that jumps there.
		head("Contents")
		cnt := func(label string, n int, key string) {
			kv(label, num(fmt.Sprintf("%d", n))+"  "+dim("(")+press(key, "")+dim(")"))
		}
		cnt("Sections", len(ctx.File.Sections), "2")
		cnt("Symbols", len(ctx.File.Symbols), "3")
		kv("Disassembly", press("4", ""))
		kv("Strings", press("7", ""))
		if len(info.DynamicLibs) > 0 {
			cnt("Libraries", len(info.DynamicLibs), "8")
		}
		if ctx.File.HasDWARF() {
			kv("Sources", press("9", ""))
		}
		kv("Relocations", press("0", "")) // always available; relocs build lazily on open
		kv("Raw header", press("⇧H", " — full "+string(ctx.File.Format)+" header fields"))
		kv("Find anything", press("g", " — symbol / section / string / address"))

		// Hardening — a badge coloured by how safe each setting is.
		head("Hardening")
		kv("PIE", triSec(ctx, info.PIE))
		kv("NX stack", triSec(ctx, info.NX))
		if info.RELRO != "" {
			kv("RELRO", relroSec(ctx, info.RELRO))
		}
		kv("Stack canary", boolSec(ctx, info.Canary, true))
		kv("FORTIFY", boolSec(ctx, info.Fortify, true))
		if ctx.File.Format == binfile.FormatMachO {
			kv("Code signature", boolSec(ctx, info.CodeSigned, true))
			if info.Encrypted {
				kv("Encrypted", ctx.WarnStyle.Render("⚠ yes"))
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
			v := ctx.RowStyle.Render(val)
			if info.Libc.Source != "" {
				v += "  " + dim("("+info.Libc.Source+")")
			}
			kv("Libc", v)
		}
		if len(info.DynamicLibs) > 0 {
			kv("Needed libs", num(fmt.Sprintf("%d", len(info.DynamicLibs)))+"  "+dim("(")+press("8", " to view")+dim(")"))
		}

		// Toolchain / provenance. Compiler() scans lazily (Mach-O) and caches.
		compiler := ctx.File.Compiler()
		if info.SourceLang != "" || compiler != "" || info.GoVersion != "" || info.MinOS != "" {
			head("Toolchain")
			if info.SourceLang != "" {
				kvText("Language", info.SourceLang)
			}
			// For Go binaries the toolchain is shown as "Go:" below; a stray clang
			// banner from cgo/deps would only mislead.
			if compiler != "" && info.GoVersion == "" {
				kvText("Compiler", compiler)
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

	// Drop the single-column content into a full-width bordered panel. A long page
	// scrolls inside the panel via the viewport; the border rows (2) leave
	// BodyH-2 rows of content. Pad every line so the panel's right edge is flush.
	lines := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
	for i := range lines {
		lines[i] = layout.PadRight(lines[i], innerW)
	}
	return strings.Join(lines, "\n")
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

// entryValue renders the entry point value: its address, the entry symbol, and a
// hint that Enter follows it into the disassembly.
func entryValue(ctx view.Context) string {
	entry := ctx.File.Entry()
	if entry == 0 {
		// Dylibs, bundles and object files have no entry point.
		return ctx.ShadowStyle.Render("(none)")
	}
	val := fmt.Sprintf("0x%0*x", ctx.File.AddrHexWidth(), entry)
	if sym, ok := ctx.File.SymbolAt(entry); ok {
		name := sym.Display()
		if off := entry - sym.Addr; off != 0 {
			name = fmt.Sprintf("%s+0x%x", name, off)
		}
		val += "  " + ctx.SymStyle.Render(name)
	}
	// Enter follows the entry point: into disasm when possible, else into hex.
	// The key wears the accent colour, like every other key the page names.
	action := "disassemble"
	if ctx.CanDisasmAt == nil || !ctx.CanDisasmAt(entry) {
		action = "hex"
	}
	val += "  " + ctx.KeyStyle.Render("↵") + ctx.ShadowStyle.Render(" "+action)
	return val
}

// fileTypeExplain returns a short plain-language gloss for a container file type
// (ELF ET_*, Mach-O Exec/Dylib/..., PE EXE/DLL), or "" when unknown.
func fileTypeExplain(t string) string {
	switch strings.ToUpper(strings.TrimSpace(t)) {
	case "ET_EXEC", "EXEC", "EXECUTE", "EXE", "EXECUTABLE":
		return "runnable program"
	case "ET_DYN", "DYLIB", "DLL", "DYLINKER":
		return "shared / dynamic library"
	case "ET_REL", "OBJ", "OBJECT", "REL", "RELOCATABLE":
		return "relocatable object (not yet linked)"
	case "ET_CORE", "CORE":
		return "core dump (crash snapshot)"
	case "BUNDLE":
		return "loadable bundle / plugin"
	case "DSYM":
		return "debug-symbols companion"
	case "KEXTBUNDLE", "KEXT":
		return "kernel extension"
	case "PRELOAD":
		return "preloaded program image"
	case "FILESET":
		return "Mach-O fileset (kernel collection)"
	}
	// ELF ET_DYN can be a PIE executable; the loader can't always tell, so keep the
	// generic gloss above.
	return ""
}

// boolSec renders a yes/no hardening flag with a badge, green when it equals the
// hardened value and red otherwise.
func boolSec(ctx view.Context, v, hardenedWhenYes bool) string {
	if v == hardenedWhenYes {
		return ctx.InfoStyle.Render("✓ " + yesNo(v))
	}
	return ctx.ErrorStyle.Render("✗ " + yesNo(v))
}

// triSec badges a tri-state hardening flag: enabled (hardened) green, disabled
// red, unknown dim.
func triSec(ctx view.Context, t binfile.Tristate) string {
	switch t {
	case binfile.TriYes:
		return ctx.InfoStyle.Render("✓ " + t.String())
	case binfile.TriNo:
		return ctx.ErrorStyle.Render("✗ " + t.String())
	}
	return ctx.ShadowStyle.Render("‐ " + t.String())
}

// relroSec badges RELRO: full = green, partial = yellow, none = red.
func relroSec(ctx view.Context, s string) string {
	switch s {
	case "full":
		return ctx.InfoStyle.Render("✓ full")
	case "partial":
		return ctx.WarnStyle.Render("◐ partial")
	default:
		return ctx.ErrorStyle.Render("✗ none")
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

const infoKeyWidth = 15
