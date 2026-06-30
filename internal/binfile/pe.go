package binfile

import (
	"bytes"
	"debug/dwarf"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/rabarbra/exex/internal/arch"
)

// PE data-directory indices used here.
const (
	dirImport      = 1  // IMAGE_DIRECTORY_ENTRY_IMPORT
	dirDelayImport = 13 // IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT
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
	if f.layoutOnly {
		return nil
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

	// Synthesise symbols for imported functions at their IAT slot addresses, so
	// call targets through the IAT resolve and the Symbols view's imported/library
	// filters work — mirroring appendELFImportSymbols / machoImportSymbols.
	f.loadPEImports(pf, imageBase)

	if peHasDWARF(pf) {
		f.dwarfAvail = true
		f.dwarfBuild = func() *dwarf.Data { return peDWARF(pf) }
	}

	f.loadPEInfo(pf, dllChars)
	f.header = f.peHeaderInfo(pf)
	f.rawHeader = f.peRawHeader(pf)
	f.relocBuild = func() []Reloc { return peRelocs(pf, imageBase) }
	return nil
}

// loadPEImports walks the import (and delay-import) directories, synthesising a
// Symbol at each import's IAT slot address: Name = the imported function (or
// "DLL!ordinalN"), Library = the owning DLL, Kind = SymObject (the slot is a
// function-pointer data cell). Best-effort: malformed tables are skipped.
func (f *File) loadPEImports(pf *pe.File, imageBase uint64) {
	ptr := f.addrWidth / 2 // 8 bytes for PE32+, 4 for PE32
	bo := binary.LittleEndian

	at := func(rva uint32, n int) []byte {
		off, ok := peRVAOffset(pf, rva)
		if !ok || off < 0 || off+n > len(f.raw) {
			return nil
		}
		return f.raw[off : off+n]
	}
	str := func(rva uint32) string {
		off, ok := peRVAOffset(pf, rva)
		if !ok || off < 0 || off >= len(f.raw) {
			return ""
		}
		b := f.raw[off:]
		if i := bytes.IndexByte(b, 0); i >= 0 {
			return string(b[:i])
		}
		return ""
	}
	ordinalFlag := uint64(1) << (uint(ptr)*8 - 1)

	// walkThunks emits one symbol per non-null thunk entry. iltRVA names the
	// lookup table (function names/ordinals); iatRVA is where the resolved slot
	// addresses live (what call sites reference).
	walkThunks := func(dll string, iltRVA, iatRVA uint32) {
		for j := 0; ; j++ {
			tb := at(iltRVA+uint32(j*ptr), ptr)
			if len(tb) < ptr {
				break
			}
			var v uint64
			if ptr == 8 {
				v = bo.Uint64(tb)
			} else {
				v = uint64(bo.Uint32(tb))
			}
			if v == 0 {
				break // null terminator
			}
			name := ""
			if v&ordinalFlag != 0 {
				name = fmt.Sprintf("%s!ordinal%d", strings.TrimSuffix(dll, ".dll"), v&0xffff)
			} else if name = str(uint32(v) + 2); name == "" { // skip 2-byte hint
				continue
			}
			f.Symbols = append(f.Symbols, Symbol{
				Name:    name,
				Addr:    imageBase + uint64(iatRVA) + uint64(j*ptr),
				Kind:    SymObject,
				Bind:    BindGlobal,
				Library: dll,
			})
		}
	}

	// Regular imports: IMAGE_IMPORT_DESCRIPTOR is 20 bytes, array ends at a zero
	// entry. Fields: [0]OriginalFirstThunk(ILT) [12]Name [16]FirstThunk(IAT).
	if dir, ok := peDataDir(pf, dirImport); ok {
		for i := 0; ; i++ {
			d := at(dir.VirtualAddress+uint32(i*20), 20)
			if len(d) < 20 {
				break
			}
			ilt, nameRVA, iat := bo.Uint32(d[0:]), bo.Uint32(d[12:]), bo.Uint32(d[16:])
			if nameRVA == 0 && iat == 0 {
				break
			}
			if ilt == 0 {
				ilt = iat // bound imports may zero the ILT; the IAT still holds names pre-bind
			}
			walkThunks(str(nameRVA), ilt, iat)
		}
	}

	// Delay imports: IMAGE_DELAYLOAD_DESCRIPTOR is 32 bytes; the RVAs here are
	// already RVAs in modern images. Fields: [4]DllName [16]ImportNameTable
	// [12]ImportAddressTable.
	if dir, ok := peDataDir(pf, dirDelayImport); ok {
		for i := 0; ; i++ {
			d := at(dir.VirtualAddress+uint32(i*32), 32)
			if len(d) < 32 {
				break
			}
			nameRVA, iat, ilt := bo.Uint32(d[4:]), bo.Uint32(d[12:]), bo.Uint32(d[16:])
			if nameRVA == 0 && iat == 0 {
				break
			}
			if ilt == 0 {
				ilt = iat
			}
			walkThunks(str(nameRVA), ilt, iat)
		}
	}
}

// peDataDir returns data-directory entry idx, across PE32/PE32+ optional headers.
func peDataDir(pf *pe.File, idx int) (pe.DataDirectory, bool) {
	switch oh := pf.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		if idx < len(oh.DataDirectory) {
			return oh.DataDirectory[idx], true
		}
	case *pe.OptionalHeader32:
		if idx < len(oh.DataDirectory) {
			return oh.DataDirectory[idx], true
		}
	}
	return pe.DataDirectory{}, false
}

// peRVAOffset maps a virtual address (RVA) to a file offset via the section table.
func peRVAOffset(pf *pe.File, rva uint32) (int, bool) {
	for _, s := range pf.Sections {
		size := s.VirtualSize
		if size < s.Size {
			size = s.Size
		}
		if rva >= s.VirtualAddress && rva < s.VirtualAddress+size {
			return int(s.Offset + (rva - s.VirtualAddress)), true
		}
	}
	return 0, false
}

func peArch(m uint16) arch.Arch {
	switch m {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return arch.ArchAMD64
	case pe.IMAGE_FILE_MACHINE_I386:
		return arch.ArchX86
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return arch.ArchARM64
	}
	return arch.ArchUnknown
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

func peHasDWARF(pf *pe.File) bool {
	for _, s := range pf.Sections {
		if strings.HasPrefix(s.Name, ".debug") || strings.HasPrefix(s.Name, ".zdebug") {
			return true
		}
	}
	return false
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
		fmt.Sprintf("DWARF info:  %v", f.HasDWARF()),
	}
}
