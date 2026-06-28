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
	return fs
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

// machoRawHeader formats the Mach-O mach_header fields.
func (f *File) machoRawHeader(mf *macho.File) []HeaderField {
	var fs []HeaderField
	add := func(name, val string) { fs = append(fs, HeaderField{name, val}) }
	add("Magic", fmt.Sprintf("0x%x", mf.Magic))
	add("CPU type", mf.Cpu.String())
	add("CPU subtype", fmt.Sprintf("0x%x", uint32(mf.SubCpu)))
	add("File type", mf.Type.String())
	add("Load commands", fmt.Sprintf("%d (%d bytes)", mf.Ncmd, mf.Cmdsz))
	add("Flags", fmt.Sprintf("0x%x", uint32(mf.Flags)))
	return fs
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
