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
		"symbols", "syms", "strings", "libs", "libraries", "sources",
		"relocs", "relocations", "syscalls", "syscalls-all", "syscalls-full",
		"cpu-features", "cpufeatures", "features", "disasm", "disasm-all":
		return true
	}
	return false
}

// ViewNames lists the canonical view keywords for help/usage text.
var ViewNames = []string{"info", "sections", "segments", "symbols", "strings", "libs", "sources", "relocs", "syscalls", "syscalls-all", "cpu-features", "disasm", "disasm-all"}

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

// ViewNeedsDemangle reports whether a view actually displays symbol names, so the
// CLI can skip the whole-table demangle pass for views that don't (sections,
// segments, strings, libs, sources, info) — that pass allocates 1+ GB on a large
// C++/Swift binary and is pure waste for them.
func ViewNeedsDemangle(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "symbols", "syms":
		return true
	}
	return false
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
	case "relocs", "relocations":
		return Relocs(f), nil
	case "syscalls":
		return Syscalls(f, false), nil
	case "syscalls-all":
		return Syscalls(f, true), nil
	case "syscalls-full":
		return SyscallsFull(f), nil
	case "cpu-features", "cpufeatures", "features":
		return CPUFeatures(f)
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
	for i := range f.Sections {
		s := f.Sections[i]
		if s.FileSize == 0 {
			continue // need file bytes to disassemble
		}
		if all {
			// All-sections: the loaded image's code+data for a linked file, or an
			// object file's code/data content — but never symbol/debug/etc. metadata
			// (see binfile.IncludeInDisasmAll), which would decode to junk.
			if !f.IncludeInDisasmAll(&s) {
				continue
			}
		} else if !s.Exec {
			// Plain disasm wants executable code. (Address 0 is kept — a relocatable
			// object's .text sections sit there until the linker lays them out.)
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

	buf := make([]byte, 0, 96) // reused per line so formatting allocates nothing
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
				buf = append(buf[:0], '\n')
				buf = appendHexPad(buf, in.Addr, addrW)
				buf = append(buf, " <"...)
				buf = append(buf, labelName(sym, labels)...)
				buf = append(buf, ">:\n"...)
				if _, e := bw.Write(buf); e != nil {
					stop = true
					return false
				}
			}
			buf = appendHexPad(buf[:0], in.Addr, addrW)
			buf = append(buf, ':', ' ', ' ')
			buf = appendSpacedBytes(buf, in.Bytes, 21)
			buf = append(buf, ' ')
			buf = appendAlignAsm(buf, in.Text)
			buf = append(buf, '\n')
			if _, e := bw.Write(buf); e != nil {
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
	if c := f.Compiler(); c != "" {
		kv("Compiler:", c)
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

// Symbols dumps the symbol table to a string (nm-like: addr, size, bind, type,
// name). The CLI streams it via SymbolsTo; this buffered form is for callers that
// want the whole text (tests).
func Symbols(f *binfile.File) string {
	var b strings.Builder
	b.Grow(len(f.Symbols) * (f.AddrHexWidth() + 40))
	_ = SymbolsTo(&b, f)
	return b.String()
}

// SymbolsTo streams the symbol table to w (one row per symbol), so a table with
// hundreds of thousands of symbols never buffers the whole output. Each row's
// fixed columns are formatted into one reused buffer (no boxed Fprintf per row).
// A write error (e.g. a closed pipe) ends the dump cleanly.
func SymbolsTo(w io.Writer, f *binfile.File) error {
	addrW := f.AddrHexWidth()
	bw := bufio.NewWriter(w)
	defer bw.Flush()
	var line []byte
	for i := range f.Symbols {
		s := &f.Symbols[i]
		line = append(line[:0], '0', 'x')
		line = appendHexPad(line, s.Addr, addrW)
		line = append(line, ' ')
		line = appendRightUint(line, s.Size, 8)
		line = append(line, ' ')
		line = appendLeftStr(line, bindName(s.Bind), 6)
		line = append(line, ' ')
		line = appendLeftStr(line, kindName(s.Kind), 7)
		line = append(line, ' ')
		line = append(line, s.Display()...)
		line = append(line, '\n')
		if _, err := bw.Write(line); err != nil {
			return nil // reader went away (closed pipe) — done, not an error
		}
	}
	return nil
}

// appendRightUint appends v as decimal, right-justified in at least width columns.
func appendRightUint(dst []byte, v uint64, width int) []byte {
	var tmp [20]byte
	d := strconv.AppendUint(tmp[:0], v, 10)
	for p := width - len(d); p > 0; p-- {
		dst = append(dst, ' ')
	}
	return append(dst, d...)
}

// appendLeftStr appends s, left-justified in at least width columns (ASCII).
func appendLeftStr(dst []byte, s string, width int) []byte {
	dst = append(dst, s...)
	for p := width - len(s); p > 0; p-- {
		dst = append(dst, ' ')
	}
	return dst
}

// Strings dumps the printable strings to a string (with address or file offset).
// The CLI streams it via StringsTo; this buffered form is for tests.
func Strings(f *binfile.File) string {
	entries := f.Strings()
	var b strings.Builder
	size := 0
	for i := range entries {
		size += f.AddrHexWidth() + 5 + int(entries[i].Len) + 1
	}
	b.Grow(size)
	_ = StringsTo(&b, f)
	return b.String()
}

// StringsTo streams the printable strings to w, one per line. The per-line prefix
// is formatted into one reused buffer and the text is written straight from the
// file image (StringBytes is zero-copy), so neither a per-line copy nor a whole-
// output buffer is allocated. A write error ends the dump cleanly.
func StringsTo(w io.Writer, f *binfile.File) error {
	addrW := f.AddrHexWidth()
	bw := bufio.NewWriter(w)
	defer bw.Flush()
	var line []byte
	for _, e := range f.Strings() {
		line = line[:0]
		if e.HasAddr {
			line = append(line, '0', 'x')
			line = appendHexPad(line, e.Addr, addrW)
		} else {
			// "@0x" + offset left-justified in addrW hex columns (matches "%-*x").
			line = append(line, '@', '0', 'x')
			n := len(line)
			line = appendHexPad(line, e.Offset, 0)
			for w := len(line) - n; w < addrW; w++ {
				line = append(line, ' ')
			}
		}
		line = append(line, ' ', ' ')
		if _, err := bw.Write(line); err != nil {
			return nil
		}
		if _, err := bw.Write(f.StringBytes(e)); err != nil {
			return nil
		}
		if err := bw.WriteByte('\n'); err != nil {
			return nil
		}
	}
	return nil
}

// StreamView writes a view straight to w when it has a streaming form (the large
// symbol/string tables), returning whether it handled the view. The CLI uses it
// so those dumps never buffer the whole output; other views fall back to View.
func StreamView(w io.Writer, f *binfile.File, name string) (handled bool, err error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "symbols", "syms":
		return true, SymbolsTo(w, f)
	case "strings":
		return true, StringsTo(w, f)
	}
	return false, nil
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
			addrW, in.Addr, plainBytes(in.Bytes), AlignAsm(in.Text))
	}
	return b.String()
}

// asmMnemWidth is the column the mnemonic is right-justified within so operands
// start in a fixed, left-justified column. The mnemonic/operand boundary becomes
// a single vertical seam, which makes operands easy to scan down.
const asmMnemWidth = 7

// hexLower indexes a nibble to its lowercase hex digit, for the append helpers
// below that format without fmt (the streaming dump is allocation-sensitive).
const hexLower = "0123456789abcdef"

// AlignAsm renders an instruction's text objdump-style: the mnemonic
// right-aligned in asmMnemWidth, operands left-aligned after a single space (so
// the mnemonic/operand boundary is a single vertical seam). A mnemonic longer
// than the field simply overflows it (no truncation). Hex immediates are already
// produced by the decoder (see disasm.hexImmediates); this only handles layout,
// so the dump and the TUI disasm view stay identical.
func AlignAsm(text string) string { return string(appendAlignAsm(nil, text)) }

// appendAlignAsm is AlignAsm writing into dst, so the streaming dump can format a
// whole line into one reused buffer instead of allocating a string per row.
func appendAlignAsm(dst []byte, text string) []byte {
	text = strings.TrimSpace(text)
	i := strings.IndexAny(text, " \t")
	if i < 0 { // bare mnemonic: right-justify it alone
		for pad := asmMnemWidth - len(text); pad > 0; pad-- {
			dst = append(dst, ' ')
		}
		return append(dst, text...)
	}
	mnem := text[:i]
	args := strings.TrimLeft(text[i+1:], " \t")
	for pad := asmMnemWidth - len(mnem); pad > 0; pad-- {
		dst = append(dst, ' ')
	}
	dst = append(dst, mnem...)
	dst = append(dst, ' ')
	return append(dst, args...)
}

// appendHexPad appends v as lowercase hex, zero-padded to at least width digits
// (no "0x" prefix), like fmt's "%0*x".
func appendHexPad(dst []byte, v uint64, width int) []byte {
	var tmp [16]byte
	n := len(tmp)
	for {
		n--
		tmp[n] = hexLower[v&0xf]
		v >>= 4
		if v == 0 {
			break
		}
	}
	for pad := width - (len(tmp) - n); pad > 0; pad-- {
		dst = append(dst, '0')
	}
	return append(dst, tmp[n:]...)
}

// appendSpacedBytes appends b as space-separated hex ("01 00 00 14"), padded with
// trailing spaces to at least minW columns (like fmt's "%-21s" over plainBytes).
func appendSpacedBytes(dst []byte, b []byte, minW int) []byte {
	start := len(dst)
	for i, x := range b {
		if i > 0 {
			dst = append(dst, ' ')
		}
		dst = append(dst, hexLower[x>>4], hexLower[x&0xf])
	}
	for w := len(dst) - start; w < minW; w++ {
		dst = append(dst, ' ')
	}
	return dst
}

// plainBytes formats instruction bytes as space-separated hex, no colour.
func plainBytes(b []byte) string { return string(appendSpacedBytes(nil, b, 0)) }

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
