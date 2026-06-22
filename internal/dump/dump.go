// Package dump renders a binary's views as plain, non-interactive text for
// stdout (the `-o` flag), turning exex into a scriptable readelf/nm/objdump-lite.
// It shares the function-disassembly formatter with the TUI's "copy function"
// so the two stay identical.
package dump

import (
	"bufio"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/disasm"
	"github.com/rabarbra/exex/internal/explorer"
)

// dumpMaxBytes bounds the decode window used for one-shot function dumps.
const dumpMaxBytes = 1 << 20

// IsView reports whether name is a known view keyword for `-o`. The CLI uses
// this to tell `-o sections` (a view) from a bare `-o` whose target is the
// positional symbol/address — so a symbol literally named "sections" can still
// be disassembled (as the positional), without colliding with the view.
func IsView(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "info", "header", "headers", "sections", "segments",
		"symbols", "syms", "strings", "libs", "libraries", "sources", "disasm", "disasm-all":
		return true
	}
	return false
}

// ViewNames lists the canonical view keywords for help/usage text.
var ViewNames = []string{"info", "sections", "segments", "symbols", "strings", "libs", "sources", "disasm", "disasm-all"}

// IsDisasm reports whether name selects a (streaming) disassembly dump, and
// whether it is the all-sections variant. The CLI routes these to DisasmTo
// rather than View so output streams instead of buffering.
func IsDisasm(name string) (disasm, all bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "disasm":
		return true, false
	case "disasm-all":
		return true, true
	}
	return false, false
}

// View dumps a named view as plain text, or errors for an unknown name.
func View(f *binfile.File, name string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "info", "header", "headers":
		return Info(f), nil
	case "sections":
		return Sections(f), nil
	case "segments":
		return Segments(f), nil
	case "symbols", "syms":
		return Symbols(f), nil
	case "strings":
		return Strings(f), nil
	case "libs", "libraries":
		return Libs(f), nil
	case "sources":
		return Sources(f), nil
	}
	return "", fmt.Errorf("unknown view %q (try: %s)", name, strings.Join(ViewNames, ", "))
}

// DisasmTo streams the disassembly objdump-style to w: a "Disassembly of section
// <name>:" header per section and a "<addr> <symbol>:" label wherever a symbol
// begins. When all is false only executable sections are emitted (objdump -d);
// when true every section with file bytes is (objdump -D).
//
// It streams per instruction (no whole-binary buffer) and demangles labels
// lazily, so output starts immediately on large binaries and `| head` / `| less`
// stops early instead of waiting for the entire image to decode. A write error
// (e.g. the reader closed the pipe) ends the dump cleanly.
func DisasmTo(w io.Writer, f *binfile.File, all bool) error {
	dis, err := disasm.For(f.Arch())
	if err != nil || dis == nil {
		return fmt.Errorf("no disassembler for this architecture")
	}
	var secs []binfile.Section
	for _, s := range f.Sections {
		if s.FileSize == 0 || s.Addr == 0 {
			continue // need file bytes and a load address to disassemble
		}
		if !all && !s.Exec {
			continue
		}
		secs = append(secs, s)
	}
	if len(secs) == 0 {
		return fmt.Errorf("no sections to disassemble")
	}
	sort.Slice(secs, func(i, j int) bool { return secs[i].Addr < secs[j].Addr })

	addrW := f.AddrHexWidth()
	raw := f.Raw()
	bw := bufio.NewWriter(w)
	defer bw.Flush()
	labels := map[string]string{} // lazy label demangle cache

	for i, s := range secs {
		end := s.Offset + s.FileSize
		if end > uint64(len(raw)) {
			continue
		}
		if i > 0 {
			bw.WriteByte('\n')
		}
		fmt.Fprintf(bw, "Disassembly of section %s:\n", s.Name)
		stop := false
		disasm.RangeFunc(dis, raw[s.Offset:end], s.Addr, func(in disasm.Inst) bool {
			if sym, ok := f.SymbolAt(in.Addr); ok && sym.Addr == in.Addr {
				if _, e := fmt.Fprintf(bw, "\n%0*x <%s>:\n", addrW, in.Addr, labelName(sym, labels)); e != nil {
					stop = true
					return false
				}
			}
			if _, e := fmt.Fprintf(bw, "%0*x:  %-21s %s\n",
				addrW, in.Addr, plainBytes(in.Bytes), strings.TrimSpace(in.Text)); e != nil {
				stop = true
				return false
			}
			return true
		})
		if stop {
			return nil // reader went away (e.g. closed pipe) — done, not an error
		}
	}
	return nil
}

// labelName resolves a function-label name, demangling lazily (Itanium/Rust) and
// caching by raw name so the streaming dump doesn't redo work or run the whole-
// table demangle pass.
func labelName(sym binfile.Symbol, cache map[string]string) string {
	if sym.Demangled != "" {
		return sym.Demangled
	}
	d, ok := cache[sym.Name]
	if !ok {
		d = binfile.DemangleName(sym.Name)
		cache[sym.Name] = d
	}
	if d != "" {
		return d
	}
	return sym.Name
}

// Info dumps the header plus key triage fields.
func Info(f *binfile.File) string {
	var b strings.Builder
	for _, l := range f.HeaderInfo() {
		b.WriteString(l)
		b.WriteByte('\n')
	}
	// Universal (fat) Mach-O: list every architecture slice; mark the loaded one.
	if len(f.FatArchInfos) > 1 {
		fmt.Fprintf(&b, "Architectures: %d (universal)\n", len(f.FatArchInfos))
		for _, a := range f.FatArchInfos {
			marker := " "
			if a.Name == f.FatArch {
				marker = "*"
			}
			fmt.Fprintf(&b, "  %s %-8s %-7s %d-bit  @ 0x%08x  %d bytes\n",
				marker, a.Name, a.Type, a.Bits, a.Offset, a.Size)
		}
	}
	in := f.Info
	if in == nil {
		return b.String()
	}
	kv := func(k, v string) { fmt.Fprintf(&b, "%-13s%s\n", k, v) }
	kv("PIE:", in.PIE.String())
	kv("NX:", in.NX.String())
	if in.RELRO != "" {
		kv("RELRO:", in.RELRO)
	}
	kv("Stack canary:", yesNo(in.Canary))
	kv("FORTIFY:", yesNo(in.Fortify))
	kv("Stripped:", yesNo(in.Stripped))
	kv("Static:", yesNo(in.StaticLinked))
	if in.Interp != "" {
		kv("Interpreter:", in.Interp)
	}
	if in.Libc.Kind != "" {
		v := in.Libc.Kind
		if in.Libc.Version != "" {
			v += " " + in.Libc.Version
		}
		kv("Libc:", v)
	}
	if in.SourceLang != "" {
		kv("Language:", in.SourceLang)
	}
	if in.Compiler != "" {
		kv("Compiler:", in.Compiler)
	}
	if in.GoVersion != "" {
		kv("Go:", in.GoVersion)
	}
	return b.String()
}

// Sections dumps the section table. An LMA (load/physical address) column is
// added only when some section's load address differs from its virtual address.
func Sections(f *binfile.File) string {
	addrW := f.AddrHexWidth()
	lma := false
	for _, s := range f.Sections {
		if s.PhysAddr != 0 {
			lma = true
			break
		}
	}
	var b strings.Builder
	if lma {
		fmt.Fprintf(&b, "%-24s %-14s %-*s %-*s %-12s %s\n", "Name", "Type", addrW+2, "Addr", addrW+2, "LMA", "Size", "Flags")
	} else {
		fmt.Fprintf(&b, "%-24s %-14s %-*s %-12s %s\n", "Name", "Type", addrW+2, "Addr", "Size", "Flags")
	}
	for _, s := range f.Sections {
		if lma {
			fmt.Fprintf(&b, "%-24s %-14s 0x%0*x %-*s %-12d %s\n",
				s.Name, s.TypeName, addrW, s.Addr, addrW+2, lmaCell(s.PhysAddr, addrW), s.Size, s.Flags)
		} else {
			fmt.Fprintf(&b, "%-24s %-14s 0x%0*x %-12d %s\n",
				s.Name, s.TypeName, addrW, s.Addr, s.Size, s.Flags)
		}
	}
	return b.String()
}

// Segments dumps the segment (memory-region) table. A PAddr column is added only
// when some segment's physical address differs from its virtual address.
func Segments(f *binfile.File) string {
	if len(f.Segments) == 0 {
		return "no segments in this binary\n"
	}
	addrW := f.AddrHexWidth()
	paddr := false
	for _, s := range f.Segments {
		if s.PhysAddr != 0 {
			paddr = true
			break
		}
	}
	var b strings.Builder
	if paddr {
		fmt.Fprintf(&b, "%-16s %-5s %-*s %-*s %-12s %-12s %s\n", "Type", "Perms", addrW+2, "Addr", addrW+2, "PAddr", "MemSize", "FileSize", "Align")
	} else {
		fmt.Fprintf(&b, "%-16s %-5s %-*s %-12s %-12s %s\n", "Type", "Perms", addrW+2, "Addr", "MemSize", "FileSize", "Align")
	}
	for _, s := range f.Segments {
		if paddr {
			fmt.Fprintf(&b, "%-16s %-5s 0x%0*x %-*s %-12d %-12d %d\n",
				s.Name, s.Perms(), addrW, s.Addr, addrW+2, lmaCell(s.PhysAddr, addrW), s.Size, s.FileSize, s.Align)
		} else {
			fmt.Fprintf(&b, "%-16s %-5s 0x%0*x %-12d %-12d %d\n",
				s.Name, s.Perms(), addrW, s.Addr, s.Size, s.FileSize, s.Align)
		}
	}
	return b.String()
}

// lmaCell formats a load/physical address, or "-" when it is unset (same as the
// virtual address).
func lmaCell(phys uint64, addrW int) string {
	if phys == 0 {
		return "-"
	}
	return fmt.Sprintf("0x%0*x", addrW, phys)
}

// Symbols dumps the symbol table (nm-like): addr, size, bind, type, name.
func Symbols(f *binfile.File) string {
	addrW := f.AddrHexWidth()
	var b strings.Builder
	for _, s := range f.Symbols {
		fmt.Fprintf(&b, "0x%0*x %8d %-6s %-7s %s\n",
			addrW, s.Addr, s.Size, bindName(s.Bind), kindName(s.Kind), s.Display())
	}
	return b.String()
}

// Strings dumps the printable strings with their address (or file offset).
func Strings(f *binfile.File) string {
	addrW := f.AddrHexWidth()
	var b strings.Builder
	for _, e := range f.Strings() {
		if e.HasAddr {
			fmt.Fprintf(&b, "0x%0*x  %s\n", addrW, e.Addr, f.StringText(e))
		} else {
			fmt.Fprintf(&b, "@0x%-*x  %s\n", addrW, e.Offset, f.StringText(e))
		}
	}
	return b.String()
}

// Sources dumps the list of source files referenced by the binary's debug info.
func Sources(f *binfile.File) string {
	files := f.SourceFiles()
	if len(files) == 0 {
		return "no source files (needs DWARF debug info)\n"
	}
	var b strings.Builder
	for _, s := range files {
		b.WriteString(s)
		b.WriteByte('\n')
	}
	return b.String()
}

// Libs dumps the dynamic library dependencies.
func Libs(f *binfile.File) string {
	if f.Info == nil || len(f.Info.DynamicLibs) == 0 {
		return "no dynamic libraries\n"
	}
	var b strings.Builder
	for _, lib := range f.Info.DynamicLibs {
		b.WriteString(lib)
		b.WriteByte('\n')
	}
	return b.String()
}

// Function resolves target (a symbol name or address) to a function and returns
// its disassembly as plain text.
func Function(f *binfile.File, target string) (string, error) {
	dis, err := disasm.For(f.Arch())
	if err != nil || dis == nil {
		return "", fmt.Errorf("no disassembler for this architecture")
	}
	sym, ok := resolveFuncSym(f, target)
	if !ok {
		return "", fmt.Errorf("no symbol or address %q", target)
	}
	if sym.Size == 0 {
		return "", fmt.Errorf("%s has no known size to disassemble", sym.Display())
	}
	svc := explorer.NewDisasmService(f, dis, dumpMaxBytes, 0)
	insts := FunctionInsts(f, svc, sym)
	if len(insts) == 0 {
		return "", fmt.Errorf("%s is not in executable code", sym.Display())
	}
	return FunctionText(sym, insts, f.AddrHexWidth()), nil
}

// FunctionInsts decodes the instructions making up sym's extent, fresh from the
// executable image. Shared with the TUI's "copy function" so both cover the
// whole function regardless of any visible decode window.
func FunctionInsts(f *binfile.File, svc *explorer.DisasmService, sym binfile.Symbol) []disasm.Inst {
	if sym.Size == 0 {
		return nil
	}
	return rangeInsts(f.ExecImage(), svc, sym.Addr, sym.Size)
}

// rangeInsts decodes the instructions covering [addr, addr+size) from the
// executable image. addr is a known instruction boundary (a function symbol), so
// decoding starts there with no lead-in: DecodeWindow's resync overlap can let a
// phantom instruction straddle addr on variable-length ISAs (x86), swallowing the
// function's real first instruction. DecodeRange with lead 0 starts on the dot.
func rangeInsts(img *binfile.Image, svc *explorer.DisasmService, addr, size uint64) []disasm.Inst {
	pos, ok := img.PosForAddr(addr)
	if !ok {
		return nil
	}
	end := addr + size
	var out []disasm.Inst
	for _, in := range svc.DecodeRange(pos, int(size), 0) {
		if in.Addr >= addr && in.Addr < end {
			out = append(out, in)
		}
	}
	return out
}

// FunctionText renders a function's instructions as plain, copy-friendly
// "addr:  bytes  text" lines under a header naming the symbol and its range.
func FunctionText(sym binfile.Symbol, insts []disasm.Inst, addrW int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s  (0x%0*x–0x%0*x, %d bytes)\n",
		sym.Display(), addrW, sym.Addr, addrW, sym.Addr+sym.Size, sym.Size)
	for _, in := range insts {
		fmt.Fprintf(&b, "0x%0*x:  %-21s %s\n",
			addrW, in.Addr, plainBytes(in.Bytes), strings.TrimSpace(in.Text))
	}
	return b.String()
}

// plainBytes formats instruction bytes as space-separated hex, no colour.
func plainBytes(b []byte) string {
	var sb strings.Builder
	for i, x := range b {
		if i > 0 {
			sb.WriteByte(' ')
		}
		fmt.Fprintf(&sb, "%02x", x)
	}
	return sb.String()
}

// resolveFuncSym finds the function symbol for target: an address (covered by a
// symbol), or an exact symbol name (raw or demangled).
func resolveFuncSym(f *binfile.File, target string) (binfile.Symbol, bool) {
	target = strings.TrimSpace(target)
	if a, err := parseAddr(target); err == nil {
		if sym, ok := f.SymbolAt(a); ok {
			return sym, true
		}
	}
	for _, s := range f.Symbols {
		if s.Addr != 0 && (s.Name == target || s.Demangled == target) {
			return s, true
		}
	}
	return binfile.Symbol{}, false
}

// parseAddr parses a 0x-prefixed hex, a bare hex (when it has a–f digits), or a
// decimal address.
func parseAddr(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return strconv.ParseUint(s[2:], 16, 64)
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			return strconv.ParseUint(s, 16, 64)
		}
	}
	return strconv.ParseUint(s, 10, 64)
}

func kindName(k binfile.SymKind) string {
	switch k {
	case binfile.SymFunc:
		return "FUNC"
	case binfile.SymObject:
		return "OBJECT"
	case binfile.SymSection:
		return "SECTION"
	case binfile.SymFile:
		return "FILE"
	case binfile.SymTLS:
		return "TLS"
	case binfile.SymCommon:
		return "COMMON"
	}
	return "NOTYPE"
}

func bindName(b binfile.SymBind) string {
	switch b {
	case binfile.BindGlobal:
		return "GLOBAL"
	case binfile.BindWeak:
		return "WEAK"
	}
	return "LOCAL"
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
