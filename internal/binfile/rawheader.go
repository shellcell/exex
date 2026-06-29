package binfile

// Raw container-header fields for the Sections view's Header sub-mode and a
// scriptable counterpart. Where the standard library's parsed header omits a
// field (ELF e_flags / e_phnum / …), it is read straight from the mapped bytes.
// Each field is a label plus an already-formatted value string, so the renderer
// only has to lay them out.

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"strings"
)

// HeaderField is one raw header entry: a field name and its formatted value.
type HeaderField struct {
	Name  string
	Value string
}

// RawHeader returns the raw container-header fields (ELF e_*, Mach-O mach_header,
// PE COFF/optional header), or nil if none were collected.
func (f *File) RawHeader() []HeaderField { return f.rawHeader }

// elfRawHeader formats the ELF header: the e_ident breakdown plus the numeric
// fields, reading e_flags / counts / offsets from the raw bytes (debug/elf's
// FileHeader does not expose them).
func (f *File) elfRawHeader(ef *elf.File) []HeaderField {
	bo := ef.ByteOrder
	is64 := ef.Class == elf.ELFCLASS64
	hdr := f.raw
	u16 := func(off int) uint16 {
		if off+2 > len(hdr) {
			return 0
		}
		return bo.Uint16(hdr[off:])
	}
	u32 := func(off int) uint32 {
		if off+4 > len(hdr) {
			return 0
		}
		return bo.Uint32(hdr[off:])
	}

	var fs []HeaderField
	add := func(name, val string) { fs = append(fs, HeaderField{name, val}) }

	// e_ident: the 16 magic/identification bytes.
	identLen := 16
	if len(hdr) < identLen {
		identLen = len(hdr)
	}
	add("e_ident", hexBytes(hdr[:identLen]))
	add("Class", ef.Class.String())
	add("Data", ef.Data.String())
	add("Version", ef.Version.String())
	add("OS/ABI", ef.OSABI.String())
	add("ABI version", fmt.Sprintf("%d", ef.ABIVersion))
	add("Type", ef.Type.String())
	add("Machine", ef.Machine.String())
	add("Entry", fmt.Sprintf("0x%x", ef.Entry))
	if interp := f.elfInterp(ef); interp != "" {
		add("Interpreter", interp)
	}

	// Offsets, counts and sizes live at fixed positions after e_ident (16).
	if is64 {
		add("Program header off", fmt.Sprintf("0x%x", be64(hdr, 32, bo)))
		add("Section header off", fmt.Sprintf("0x%x", be64(hdr, 40, bo)))
		add("Flags", elfFlagsString(ef.Machine, u32(48)))
		add("Header size", fmt.Sprintf("%d", u16(52)))
		add("Program headers", fmt.Sprintf("%d × %d bytes", u16(56), u16(54)))
		add("Section headers", fmt.Sprintf("%d × %d bytes", u16(60), u16(58)))
		add("Section str index", fmt.Sprintf("%d", u16(62)))
	} else {
		add("Program header off", fmt.Sprintf("0x%x", u32(28)))
		add("Section header off", fmt.Sprintf("0x%x", u32(32)))
		add("Flags", elfFlagsString(ef.Machine, u32(36)))
		add("Header size", fmt.Sprintf("%d", u16(40)))
		add("Program headers", fmt.Sprintf("%d × %d bytes", u16(44), u16(42)))
		add("Section headers", fmt.Sprintf("%d × %d bytes", u16(48), u16(46)))
		add("Section str index", fmt.Sprintf("%d", u16(50)))
	}

	// Program-header (segment) breakdown — what the e_phnum count above only totals.
	// Each segment's type and R/W/X permissions, with its virtual address and the
	// file-vs-memory sizes (the gap is .bss). Mirrors the Mach-O load-command list.
	if len(ef.Progs) > 0 {
		add("", "── program headers ──")
		for _, p := range ef.Progs {
			val := fmt.Sprintf("%s  vaddr 0x%x  filesz 0x%x  memsz 0x%x",
				elfProgPerm(p.Flags), p.Vaddr, p.Filesz, p.Memsz)
			add(p.Type.String(), val)
		}
	}
	return fs
}

// elfInterp returns the dynamic-linker path from the PT_INTERP segment, or "".
func (f *File) elfInterp(ef *elf.File) string {
	for _, p := range ef.Progs {
		if p.Type != elf.PT_INTERP {
			continue
		}
		end := p.Off + p.Filesz
		if p.Off >= uint64(len(f.raw)) || end > uint64(len(f.raw)) || end <= p.Off {
			return ""
		}
		s := f.raw[p.Off:end]
		if i := indexByte(s, 0); i >= 0 { // drop the trailing NUL
			s = s[:i]
		}
		return string(s)
	}
	return ""
}

// indexByte is bytes.IndexByte without pulling the import for a single use.
func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

// elfProgPerm renders a segment's permission bits as an "rwx" triad.
func elfProgPerm(fl elf.ProgFlag) string {
	b := []byte("---")
	if fl&elf.PF_R != 0 {
		b[0] = 'r'
	}
	if fl&elf.PF_W != 0 {
		b[1] = 'w'
	}
	if fl&elf.PF_X != 0 {
		b[2] = 'x'
	}
	return string(b)
}

// be64 reads a 64-bit value at off using the file's byte order, guarding bounds.
func be64(b []byte, off int, bo interface{ Uint64([]byte) uint64 }) uint64 {
	if off+8 > len(b) {
		return 0
	}
	return bo.Uint64(b[off:])
}

// elfFlagsString renders e_flags: the raw hex, plus a short ABI note for the few
// architectures whose flags carry a commonly-useful meaning.
func elfFlagsString(m elf.Machine, flags uint32) string {
	s := fmt.Sprintf("0x%x", flags)
	switch m {
	case elf.EM_ARM:
		if v := (flags >> 24) & 0xff; v != 0 {
			s += fmt.Sprintf("  (EABI v%d)", v)
		}
		if flags&0x200 != 0 {
			s += " soft-float"
		}
		if flags&0x400 != 0 {
			s += " hard-float"
		}
	case elf.EM_RISCV:
		if flags&0x1 != 0 {
			s += "  RVC"
		}
		switch (flags >> 1) & 0x3 {
		case 1:
			s += " float-single"
		case 2:
			s += " float-double"
		case 3:
			s += " float-quad"
		}
	}
	return s
}

// machoRawHeader formats the Mach-O mach_header fields, decoding the opaque ones
// (CPU subtype, flags) to names and appending a breakdown of the load commands —
// the structural heart of a Mach-O that the bare header struct only counts.
func (f *File) machoRawHeader(mf *macho.File) []HeaderField {
	var fs []HeaderField
	add := func(name, val string) { fs = append(fs, HeaderField{name, val}) }
	add("Magic", fmt.Sprintf("0x%x", mf.Magic))
	add("CPU type", mf.Cpu.String())
	add("CPU subtype", machoSubCPUName(mf.Cpu, uint32(mf.SubCpu)))
	add("File type", mf.Type.String())
	add("Load commands", fmt.Sprintf("%d (%d bytes)", mf.Ncmd, mf.Cmdsz))
	flagsVal := fmt.Sprintf("0x%x", uint32(mf.Flags))
	if names := machoFlagNames(uint32(mf.Flags)); names != "" {
		flagsVal += "  " + names
	}
	add("Flags", flagsVal)

	// Load-command breakdown: one row per distinct command type, with its count,
	// in first-appearance order (the actual layout order of the header).
	counts := map[uint32]int{}
	var order []uint32
	for _, l := range mf.Loads {
		raw := l.Raw()
		if len(raw) < 4 {
			continue
		}
		cmd := mf.ByteOrder.Uint32(raw)
		if counts[cmd] == 0 {
			order = append(order, cmd)
		}
		counts[cmd]++
	}
	if len(order) > 0 {
		add("", "── load commands ──")
		for _, cmd := range order {
			val := "1"
			if counts[cmd] > 1 {
				val = fmt.Sprintf("× %d", counts[cmd])
			}
			add(machoLoadCommandName(cmd), val)
		}
	}
	return fs
}

// machoFlags maps mach_header MH_* flag bits to short names, in bit order.
var machoFlags = []struct {
	bit  uint32
	name string
}{
	{macho.FlagNoUndefs, "NOUNDEFS"}, {macho.FlagIncrLink, "INCRLINK"},
	{macho.FlagDyldLink, "DYLDLINK"}, {macho.FlagBindAtLoad, "BINDATLOAD"},
	{macho.FlagPrebound, "PREBOUND"}, {macho.FlagSplitSegs, "SPLITSEGS"},
	{macho.FlagTwoLevel, "TWOLEVEL"}, {macho.FlagWeakDefines, "WEAKDEFINES"},
	{macho.FlagBindsToWeak, "BINDSTOWEAK"}, {macho.FlagAllowStackExecution, "ALLOWSTACKEXEC"},
	{macho.FlagRootSafe, "ROOTSAFE"}, {macho.FlagSetuidSafe, "SETUIDSAFE"},
	{macho.FlagNoReexportedDylibs, "NOREEXPORTEDDYLIBS"}, {macho.FlagPIE, "PIE"},
	{macho.FlagDeadStrippableDylib, "DEADSTRIPPABLE"}, {macho.FlagHasTLVDescriptors, "TLVDESCRIPTORS"},
	{macho.FlagNoHeapExecution, "NOHEAPEXEC"}, {macho.FlagAppExtensionSafe, "APPEXTSAFE"},
}

// machoFlagNames lists the set MH_* flag names, space-separated.
func machoFlagNames(flags uint32) string {
	var names []string
	for _, f := range machoFlags {
		if flags&f.bit != 0 {
			names = append(names, f.name)
		}
	}
	return strings.Join(names, " ")
}

// machoSubCPUName names a CPU subtype for the common architectures (the high byte
// carries capability bits, e.g. LIB64/pointer-auth), falling back to hex.
func machoSubCPUName(cpu macho.Cpu, sub uint32) string {
	base := sub & 0x00ffffff
	name := ""
	switch cpu {
	case macho.CpuArm64:
		switch base {
		case 0:
			name = "ARM64_ALL"
		case 1:
			name = "ARM64_V8"
		case 2:
			name = "ARM64E"
		}
	case macho.CpuAmd64:
		switch base {
		case 3:
			name = "X86_64_ALL"
		case 8:
			name = "X86_64_H"
		}
	case macho.CpuArm:
		switch base {
		case 9:
			name = "ARM_V7"
		case 11:
			name = "ARM_V7S"
		case 13:
			name = "ARM_V8"
		}
	}
	if name == "" {
		return fmt.Sprintf("0x%x", sub)
	}
	if sub&0x80000000 != 0 {
		name += " +LIB64"
	}
	return name
}

// machoLoadCommandName maps a load-command number (LC_*) to its name; the
// LC_REQ_DYLD high bit is ignored for the lookup.
func machoLoadCommandName(cmd uint32) string {
	switch cmd &^ 0x80000000 {
	case 0x1:
		return "LC_SEGMENT"
	case 0x2:
		return "LC_SYMTAB"
	case 0x3:
		return "LC_SYMSEG"
	case 0x4:
		return "LC_THREAD"
	case 0x5:
		return "LC_UNIXTHREAD"
	case 0xb:
		return "LC_DYSYMTAB"
	case 0xc:
		return "LC_LOAD_DYLIB"
	case 0xd:
		return "LC_ID_DYLIB"
	case 0xe:
		return "LC_LOAD_DYLINKER"
	case 0xf:
		return "LC_ID_DYLINKER"
	case 0x10:
		return "LC_PREBOUND_DYLIB"
	case 0x11:
		return "LC_ROUTINES"
	case 0x12:
		return "LC_SUB_FRAMEWORK"
	case 0x14:
		return "LC_SUB_CLIENT"
	case 0x16:
		return "LC_TWOLEVEL_HINTS"
	case 0x18:
		return "LC_LOAD_WEAK_DYLIB"
	case 0x19:
		return "LC_SEGMENT_64"
	case 0x1a:
		return "LC_ROUTINES_64"
	case 0x1b:
		return "LC_UUID"
	case 0x1c:
		return "LC_RPATH"
	case 0x1d:
		return "LC_CODE_SIGNATURE"
	case 0x1e:
		return "LC_SEGMENT_SPLIT_INFO"
	case 0x1f:
		return "LC_REEXPORT_DYLIB"
	case 0x21:
		return "LC_ENCRYPTION_INFO"
	case 0x22:
		return "LC_DYLD_INFO"
	case 0x24:
		return "LC_VERSION_MIN_MACOSX"
	case 0x25:
		return "LC_VERSION_MIN_IPHONEOS"
	case 0x26:
		return "LC_FUNCTION_STARTS"
	case 0x27:
		return "LC_DYLD_ENVIRONMENT"
	case 0x28:
		return "LC_MAIN"
	case 0x29:
		return "LC_DATA_IN_CODE"
	case 0x2a:
		return "LC_SOURCE_VERSION"
	case 0x2b:
		return "LC_DYLIB_CODE_SIGN_DRS"
	case 0x2c:
		return "LC_ENCRYPTION_INFO_64"
	case 0x2d:
		return "LC_LINKER_OPTION"
	case 0x2e:
		return "LC_LINKER_OPTIMIZATION_HINT"
	case 0x2f:
		return "LC_VERSION_MIN_TVOS"
	case 0x30:
		return "LC_VERSION_MIN_WATCHOS"
	case 0x31:
		return "LC_NOTE"
	case 0x32:
		return "LC_BUILD_VERSION"
	case 0x33:
		return "LC_DYLD_EXPORTS_TRIE"
	case 0x34:
		return "LC_DYLD_CHAINED_FIXUPS"
	case 0x35:
		return "LC_FILESET_ENTRY"
	}
	return fmt.Sprintf("LC_0x%x", cmd)
}

// peRawHeader formats the PE COFF file header and the salient optional-header
// fields (image base, subsystem, sizes), reading whichever 32/64-bit optional
// header is present.
func (f *File) peRawHeader(pf *pe.File) []HeaderField {
	var fs []HeaderField
	add := func(name, val string) { fs = append(fs, HeaderField{name, val}) }
	fh := pf.FileHeader
	add("Machine", fmt.Sprintf("0x%x", fh.Machine))
	add("Sections", fmt.Sprintf("%d", fh.NumberOfSections))
	add("Timestamp", fmt.Sprintf("0x%x", fh.TimeDateStamp))
	add("Symbols", fmt.Sprintf("%d", fh.NumberOfSymbols))
	add("Opt header size", fmt.Sprintf("%d", fh.SizeOfOptionalHeader))
	add("Characteristics", fmt.Sprintf("0x%x", fh.Characteristics))
	switch oh := pf.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		add("Magic", fmt.Sprintf("0x%x (PE32+)", oh.Magic))
		add("Entry point", fmt.Sprintf("0x%x", oh.AddressOfEntryPoint))
		add("Image base", fmt.Sprintf("0x%x", oh.ImageBase))
		add("Subsystem", fmt.Sprintf("%d", oh.Subsystem))
		add("DLL chars", fmt.Sprintf("0x%x", oh.DllCharacteristics))
		add("Image size", fmt.Sprintf("%d", oh.SizeOfImage))
	case *pe.OptionalHeader32:
		add("Magic", fmt.Sprintf("0x%x (PE32)", oh.Magic))
		add("Entry point", fmt.Sprintf("0x%x", oh.AddressOfEntryPoint))
		add("Image base", fmt.Sprintf("0x%x", oh.ImageBase))
		add("Subsystem", fmt.Sprintf("%d", oh.Subsystem))
		add("DLL chars", fmt.Sprintf("0x%x", oh.DllCharacteristics))
		add("Image size", fmt.Sprintf("%d", oh.SizeOfImage))
	}
	return fs
}

// hexBytes formats bytes as lowercase space-separated hex ("7f 45 4c 46 …").
func hexBytes(b []byte) string {
	const hexLower = "0123456789abcdef"
	if len(b) == 0 {
		return ""
	}
	out := make([]byte, 0, len(b)*3)
	for i, x := range b {
		if i > 0 {
			out = append(out, ' ')
		}
		out = append(out, hexLower[x>>4], hexLower[x&0xf])
	}
	return string(out)
}
