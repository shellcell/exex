package binfile

// Relocations: a format-neutral list of relocation entries for the Relocations
// view and the `-o relocs` dump. ELF is covered richly (every SHT_REL/SHT_RELA
// section, with the type name and target symbol resolved); Mach-O and PE expose
// the per-section relocations the standard library parses (mostly object
// files). The list is built lazily on first use, mirroring the DWARF build, so
// the common path that never opens the view pays nothing.

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"sort"
)

// Reloc is one relocation entry, normalised across container formats.
type Reloc struct {
	Offset    uint64 // address (or file offset) the relocation patches
	Type      string // relocation type name, e.g. "R_X86_64_JUMP_SLOT"
	Sym       string // target symbol name, or "" when the entry has none
	Addend    int64  // RELA addend (ELF) or 0
	HasAddend bool   // whether Addend is meaningful (RELA entries)
	Section   string // section the relocation lives in (.rela.plt, __got, .reloc, …)
	Lib       string // resolved owning library for the symbol, when known
}

// Relocations returns the binary's relocation entries, building them on first
// call. The slice may be empty (e.g. a fully-resolved static binary, or a
// Mach-O that uses dyld chained fixups, which the standard library does not
// decode).
func (f *File) Relocations() []Reloc {
	f.relocOnce.Do(func() {
		if f.relocBuild != nil {
			f.relocs = f.relocBuild()
		}
	})
	return f.relocs
}

// HasRelocs reports whether the binary has any relocation entries (cheap after
// the first Relocations() build; triggers it otherwise).
func (f *File) HasRelocs() bool { return len(f.Relocations()) > 0 }

// IsRelocatable reports whether the file is a relocatable object (ELF ET_REL /
// Mach-O MH_OBJECT) — a cheap flag set at load. Only such files carry relocations
// against code operands (a linked image's dynamic relocs patch GOT/data, never
// instructions), so the disasm reloc annotation is gated on this to avoid forcing
// the (potentially large) reloc build on a linked binary that never needs it.
func (f *File) IsRelocatable() bool { return f.relocatable }

// RelocsInRange returns the relocations whose patched address falls in [lo, hi),
// via a lazily-built address-sorted index — so the disasm/hex views can annotate
// the instruction or byte a relocation lands on without scanning the whole list.
func (f *File) RelocsInRange(lo, hi uint64) []Reloc {
	f.relocSortOnce.Do(func() {
		rs := append([]Reloc(nil), f.Relocations()...)
		sort.Slice(rs, func(i, j int) bool { return rs[i].Offset < rs[j].Offset })
		f.relocsByAddr = rs
	})
	rs := f.relocsByAddr
	i := sort.Search(len(rs), func(i int) bool { return rs[i].Offset >= lo })
	var out []Reloc
	for ; i < len(rs) && rs[i].Offset < hi; i++ {
		out = append(out, rs[i])
	}
	return out
}

// elfRelocs decodes every SHT_REL / SHT_RELA section into the neutral model,
// resolving each entry's type name (per machine) and target symbol (via the
// reloc section's linked symbol table).
func (f *File) elfRelocs(ef *elf.File) []Reloc {
	is64 := ef.Class == elf.ELFCLASS64
	bo := ef.ByteOrder
	typeName := elfRelocTypeNamer(ef.Machine)

	var out []Reloc
	for _, s := range ef.Sections {
		if s.Type != elf.SHT_RELA && s.Type != elf.SHT_REL {
			continue
		}
		data, err := s.Data()
		if err != nil {
			continue
		}
		syms, libOf := elfRelocSymbols(ef, s)
		rela := s.Type == elf.SHT_RELA
		entSize := elfRelocEntSize(is64, rela)
		// In a relocatable object r_offset is relative to the section the relocs
		// apply to (sh_info); add that section's (possibly synthetic) base so Offset
		// is always an absolute address that matches the disasm/hex/symbol views. In
		// a linked image r_offset is already a virtual address.
		var targetBase uint64
		targetName := s.Name
		if ef.Type == elf.ET_REL && int(s.Info) < len(f.Sections) {
			targetBase = f.Sections[s.Info].Addr
			targetName = f.Sections[s.Info].Name
		}
		for off := 0; off+entSize <= len(data); off += entSize {
			roff, sym, rtype := decodeReloc(data, off, is64, bo)
			r := Reloc{
				Offset:  targetBase + roff,
				Type:    typeName(rtype),
				Section: targetName,
			}
			if rela {
				r.HasAddend = true
				if is64 {
					r.Addend = int64(bo.Uint64(data[off+16:]))
				} else {
					r.Addend = int64(int32(bo.Uint32(data[off+8:])))
				}
			}
			if sym != 0 && int(sym)-1 < len(syms) {
				es := syms[int(sym)-1]
				r.Sym = es.Name
				r.Lib = libOf(sym)
			}
			out = append(out, r)
		}
	}
	return out
}

// elfRelocEntSize is the per-entry byte size for a REL/RELA section.
func elfRelocEntSize(is64, rela bool) int {
	switch {
	case is64 && rela:
		return 24 // r_offset(8) r_info(8) r_addend(8)
	case is64:
		return 16 // r_offset(8) r_info(8)
	case rela:
		return 12 // r_offset(4) r_info(4) r_addend(4)
	default:
		return 8 // r_offset(4) r_info(4)
	}
}

// elfRelocSymbols returns the symbol table a reloc section is linked to (via
// sh_link: .dynsym for dynamic relocs, .symtab otherwise), plus a helper that
// maps a symbol index to its owning library when versioned. Symbols are in
// index order without the index-0 null entry, so callers index with sym-1.
func elfRelocSymbols(ef *elf.File, s *elf.Section) ([]elf.Symbol, func(uint32) string) {
	noLib := func(uint32) string { return "" }
	if int(s.Link) < len(ef.Sections) {
		if ef.Sections[s.Link].Name == ".symtab" {
			if syms, err := ef.Symbols(); err == nil {
				return syms, noLib
			}
		}
	}
	dyn, err := ef.DynamicSymbols()
	if err != nil {
		return nil, noLib
	}
	symLib := elfDynSymLibraries(ef, len(dyn))
	return dyn, func(sym uint32) string {
		if int(sym) < len(symLib) {
			return symLib[sym]
		}
		return ""
	}
}

// elfRelocTypeNamer returns a function mapping a raw relocation type number to
// its symbolic name for the given machine, falling back to "0x…" for machines
// the standard library has no named type set for.
func elfRelocTypeNamer(m elf.Machine) func(uint32) string {
	switch m {
	case elf.EM_X86_64:
		return func(t uint32) string { return elf.R_X86_64(t).String() }
	case elf.EM_386:
		return func(t uint32) string { return elf.R_386(t).String() }
	case elf.EM_AARCH64:
		return func(t uint32) string { return elf.R_AARCH64(t).String() }
	case elf.EM_ARM:
		return func(t uint32) string { return elf.R_ARM(t).String() }
	case elf.EM_RISCV:
		return func(t uint32) string { return elf.R_RISCV(t).String() }
	case elf.EM_PPC64:
		return func(t uint32) string { return elf.R_PPC64(t).String() }
	case elf.EM_PPC:
		return func(t uint32) string { return elf.R_PPC(t).String() }
	case elf.EM_S390:
		return func(t uint32) string { return elf.R_390(t).String() }
	case elf.EM_MIPS:
		return func(t uint32) string { return elf.R_MIPS(t).String() }
	case elf.EM_LOONGARCH:
		return func(t uint32) string { return elf.R_LARCH(t).String() }
	}
	return func(t uint32) string { return fmt.Sprintf("0x%x", t) }
}

// machoRelocs collects the per-section relocations the standard library parses
// (chiefly object files; linked images use dyld bind/rebase or chained fixups,
// which it does not decode). Built eagerly while mf.Symtab is still live so
// external entries can be named. base is the slice's virtual-address base.
func machoRelocs(mf *macho.File, base uint64) []Reloc {
	var syms []macho.Symbol
	if mf.Symtab != nil {
		syms = mf.Symtab.Syms
	}
	nameType := machoRelocTypeNamer(mf.Cpu)
	var out []Reloc
	for _, s := range mf.Sections {
		for _, rl := range s.Relocs {
			r := Reloc{
				Offset:  base + uint64(s.Addr) + uint64(rl.Addr),
				Type:    nameType(rl.Type),
				Section: s.Seg + "," + s.Name,
			}
			if rl.Extern && int(rl.Value) < len(syms) {
				r.Sym = syms[rl.Value].Name
			}
			out = append(out, r)
		}
	}
	return out
}

// machoRelocTypeNamer maps a Mach-O relocation type to a short name for the two
// arches this tool most often disassembles; others fall back to a numeric form.
func machoRelocTypeNamer(cpu macho.Cpu) func(uint8) string {
	switch cpu {
	case macho.CpuAmd64:
		names := []string{"UNSIGNED", "SIGNED", "BRANCH", "GOT_LOAD", "GOT", "SUBTRACTOR", "SIGNED_1", "SIGNED_2", "SIGNED_4", "TLV"}
		return func(t uint8) string {
			if int(t) < len(names) {
				return "X86_64_RELOC_" + names[t]
			}
			return fmt.Sprintf("RELOC_%d", t)
		}
	case macho.CpuArm64:
		names := []string{"UNSIGNED", "SUBTRACTOR", "BRANCH26", "PAGE21", "PAGEOFF12", "GOT_LOAD_PAGE21", "GOT_LOAD_PAGEOFF12", "POINTER_TO_GOT", "TLVP_LOAD_PAGE21", "TLVP_LOAD_PAGEOFF12", "ADDEND"}
		return func(t uint8) string {
			if int(t) < len(names) {
				return "ARM64_RELOC_" + names[t]
			}
			return fmt.Sprintf("RELOC_%d", t)
		}
	}
	return func(t uint8) string { return fmt.Sprintf("RELOC_%d", t) }
}

// peBaseRelocType indices into IMAGE_REL_BASED_* names.
var peBaseRelocType = map[uint16]string{
	0:  "ABSOLUTE",
	1:  "HIGH",
	2:  "LOW",
	3:  "HIGHLOW",
	4:  "HIGHADJ",
	10: "DIR64",
}

// peRelocs decodes the base-relocation directory (.reloc) of a PE image into the
// neutral model: each fixup's virtual address and kind. This is the relocation
// data that actually matters for a linked PE (COFF per-section relocs only exist
// in object files). Entries of type ABSOLUTE are block padding and skipped.
func peRelocs(pf *pe.File, imageBase uint64) []Reloc {
	rva, size, ok := peDataDirectory(pf, 5) // IMAGE_DIRECTORY_ENTRY_BASERELOC
	if !ok || size == 0 {
		return nil
	}
	data, ok := peReadRVA(pf, rva, size)
	if !ok {
		return nil
	}
	var out []Reloc
	for off := 0; off+8 <= len(data); {
		pageRVA := binary.LittleEndian.Uint32(data[off:])
		blockSize := binary.LittleEndian.Uint32(data[off+4:])
		if blockSize < 8 || off+int(blockSize) > len(data) {
			break
		}
		for e := off + 8; e+2 <= off+int(blockSize); e += 2 {
			ent := binary.LittleEndian.Uint16(data[e:])
			typ := ent >> 12
			if typ == 0 {
				continue // ABSOLUTE — padding
			}
			name, known := peBaseRelocType[typ]
			if !known {
				name = fmt.Sprintf("REL_%d", typ)
			}
			out = append(out, Reloc{
				Offset:  imageBase + uint64(pageRVA) + uint64(ent&0x0fff),
				Type:    "IMAGE_REL_BASED_" + name,
				Section: ".reloc",
			})
		}
		off += int(blockSize)
	}
	return out
}

// peDataDirectory returns the (RVA, size) of optional-header data directory i.
func peDataDirectory(pf *pe.File, i int) (rva, size uint32, ok bool) {
	switch oh := pf.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		if i < len(oh.DataDirectory) {
			return oh.DataDirectory[i].VirtualAddress, oh.DataDirectory[i].Size, true
		}
	case *pe.OptionalHeader32:
		if i < len(oh.DataDirectory) {
			return oh.DataDirectory[i].VirtualAddress, oh.DataDirectory[i].Size, true
		}
	}
	return 0, 0, false
}

// peReadRVA returns size bytes of the section containing rva, from the file image.
func peReadRVA(pf *pe.File, rva, size uint32) ([]byte, bool) {
	for _, s := range pf.Sections {
		if rva >= s.VirtualAddress && rva < s.VirtualAddress+s.VirtualSize {
			data, err := s.Data()
			if err != nil {
				return nil, false
			}
			start := rva - s.VirtualAddress
			end := start + size
			if end > uint32(len(data)) {
				end = uint32(len(data))
			}
			if start > end {
				return nil, false
			}
			return data[start:end], true
		}
	}
	return nil, false
}
