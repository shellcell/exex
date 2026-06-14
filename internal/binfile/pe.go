package binfile

import (
	"bytes"
	"debug/dwarf"
	"debug/pe"
	"fmt"
	"strings"

	"github.com/rabarbra/exex/internal/disasm"
)

// PE section characteristics (not exported by debug/pe).
const (
	scnCntCode       = 0x00000020
	scnCntUninitData = 0x00000080
	scnMemExecute    = 0x20000000
	scnMemWrite      = 0x80000000
)

// loadPE parses f.raw as a PE/COFF object and populates the neutral model.
func (f *File) loadPE() error {
	pf, err := pe.NewFile(bytes.NewReader(f.raw))
	if err != nil {
		return err
	}
	f.Format = FormatPE
	f.arch = peArch(pf.Machine)

	var imageBase uint64
	var entryRVA, dllChars uint32
	switch oh := pf.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		imageBase, entryRVA, dllChars = oh.ImageBase, oh.AddressOfEntryPoint, uint32(oh.DllCharacteristics)
		f.addrWidth = 16
	case *pe.OptionalHeader32:
		imageBase, entryRVA, dllChars = uint64(oh.ImageBase), oh.AddressOfEntryPoint, uint32(oh.DllCharacteristics)
		f.addrWidth = 8
	default:
		f.addrWidth = 16
	}
	if entryRVA != 0 {
		f.entry = imageBase + uint64(entryRVA)
	}

	for _, s := range pf.Sections {
		ch := s.Characteristics
		exec := ch&scnMemExecute != 0 || ch&scnCntCode != 0
		write := ch&scnMemWrite != 0
		bss := ch&scnCntUninitData != 0

		memSize := uint64(s.VirtualSize)
		if memSize == 0 {
			memSize = uint64(s.Size)
		}
		fileSize := uint64(s.Size) // SizeOfRawData
		if fileSize > memSize {
			fileSize = memSize // trim the on-disk alignment padding
		}
		if bss || s.Offset == 0 {
			fileSize = 0
		}
		sec := Section{
			Name:     s.Name,
			Addr:     imageBase + uint64(s.VirtualAddress),
			Size:     memSize,
			Offset:   uint64(s.Offset),
			FileSize: fileSize,
			TypeName: "PE",
			Category: peCategory(s.Name, exec, write, bss),
			Alloc:    true,
			Exec:     exec,
			Write:    write,
		}
		sec.Flags = neutralFlags(true, write, exec)
		f.Sections = append(f.Sections, sec)
	}

	// COFF symbols (present in MinGW/gcc images; MSVC images are usually
	// stripped, with debug info in a separate PDB). Value is treated as an RVA.
	for _, s := range pf.Symbols {
		if s.SectionNumber <= 0 {
			continue // undefined / absolute / debug
		}
		// A COFF symbol's Value is the offset from the start of its section, so
		// the virtual address is the section's address plus that offset.
		kind, secName, addr := SymOther, "", uint64(0)
		if idx := int(s.SectionNumber) - 1; idx >= 0 && idx < len(f.Sections) {
			sec := &f.Sections[idx]
			secName = sec.Name
			addr = sec.Addr + uint64(s.Value)
			if sec.Exec {
				kind = SymFunc
			} else {
				kind = SymObject
			}
		}
		bind := BindLocal
		if s.StorageClass == 2 { // IMAGE_SYM_CLASS_EXTERNAL
			bind = BindGlobal
		}
		f.Symbols = append(f.Symbols, Symbol{
			Name:    s.Name,
			Addr:    addr,
			Kind:    kind,
			Bind:    bind,
			Section: secName,
		})
	}

	if d := peDWARF(pf); d != nil {
		f.dwarf = d
		f.lines = loadLines(d)
	}

	f.loadPEInfo(pf, dllChars)
	f.header = f.peHeaderInfo(pf)
	return nil
}

func peArch(m uint16) disasm.Arch {
	switch m {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return disasm.ArchAMD64
	case pe.IMAGE_FILE_MACHINE_I386:
		return disasm.ArchX86
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return disasm.ArchARM64
	}
	return disasm.ArchUnknown
}

func peCategory(name string, exec, write, bss bool) SectionCategory {
	if strings.HasPrefix(name, ".debug") || strings.HasPrefix(name, ".zdebug") {
		return CatDebug
	}
	switch {
	case exec:
		return CatText
	case bss:
		return CatBSS
	case write:
		return CatData
	default:
		return CatRodata
	}
}

func peDWARF(pf *pe.File) *dwarf.Data {
	if d, err := pf.DWARF(); err == nil {
		return d
	}
	return nil
}

func (f *File) loadPEInfo(pf *pe.File, dllChars uint32) {
	in := &Info{}
	if libs, err := pf.ImportedLibraries(); err == nil {
		in.DynamicLibs = libs
	}
	in.Stripped = len(pf.Symbols) == 0
	in.StaticLinked = len(in.DynamicLibs) == 0
	in.WordBits = 32
	if f.addrWidth == 16 {
		in.WordBits = 64
	}
	in.ByteOrder = "little-endian"

	in.PIE = TriNo
	if dllChars&pe.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0 {
		in.PIE = TriYes
	}
	in.NX = TriNo
	if dllChars&pe.IMAGE_DLLCHARACTERISTICS_NX_COMPAT != 0 {
		in.NX = TriYes
	}
	f.Info = in
}

func (f *File) peHeaderInfo(pf *pe.File) []string {
	machine := map[uint16]string{
		pe.IMAGE_FILE_MACHINE_AMD64: "x86-64",
		pe.IMAGE_FILE_MACHINE_I386:  "x86",
		pe.IMAGE_FILE_MACHINE_ARM64: "ARM64",
	}[pf.Machine]
	if machine == "" {
		machine = "unknown"
	}
	kind := "EXE"
	if pf.Characteristics&pe.IMAGE_FILE_DLL != 0 {
		kind = "DLL"
	}
	return []string{
		fmt.Sprintf("Path:        %s", f.Path),
		fmt.Sprintf("Format:      %s", f.Format),
		fmt.Sprintf("Machine:     %s", machine),
		fmt.Sprintf("Type:        %s", kind),
		fmt.Sprintf("Entry:       0x%x", f.entry),
		fmt.Sprintf("Sections:    %d", len(f.Sections)),
		fmt.Sprintf("Symbols:     %d", len(f.Symbols)),
		fmt.Sprintf("DWARF info:  %v", f.dwarf != nil),
	}
}
