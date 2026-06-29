package binfile

import (
	"bytes"
	"debug/dwarf"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rabarbra/exex/internal/arch"
)

// elfDWARF returns DWARF for the binary: embedded, or from a separate debug
// file referenced by .gnu_debuglink (the ELF analogue of macOS .dSYM).
func (f *File) elfDWARF(ef *elf.File) *dwarf.Data {
	if d, err := ef.DWARF(); err == nil {
		return d
	}
	name := elfDebugLink(ef)
	dir := filepath.Dir(f.Path)

	// An explicit --debug path wins: it may be the debug file itself or a
	// directory that contains it (under either the debuglink name or the
	// binary's own name).
	var cands []string
	if f.debugPath != "" {
		if st, err := os.Stat(f.debugPath); err == nil && st.IsDir() {
			if name != "" {
				cands = append(cands, filepath.Join(f.debugPath, name))
			}
			cands = append(cands, filepath.Join(f.debugPath, filepath.Base(f.Path)))
		} else {
			cands = append(cands, f.debugPath)
		}
	}
	if name != "" {
		cands = append(cands,
			filepath.Join(dir, name),
			filepath.Join(dir, ".debug", name),
			filepath.Join("/usr/lib/debug", dir, name),
		)
	}
	for _, c := range cands {
		de, err := elf.Open(c)
		if err != nil {
			continue
		}
		d, err := de.DWARF()
		de.Close()
		if err == nil {
			return d
		}
	}
	return nil
}

// elfDebugLink returns the filename stored in .gnu_debuglink, or "".
func elfDebugLink(ef *elf.File) string {
	sec := ef.Section(".gnu_debuglink")
	if sec == nil {
		return ""
	}
	data, err := sec.Data()
	if err != nil {
		return ""
	}
	if i := bytes.IndexByte(data, 0); i > 0 {
		return string(data[:i])
	}
	return ""
}

// loadELF parses f.raw as an ELF object and populates the neutral model.
func (f *File) loadELF() error {
	ef, err := elf.NewFile(bytes.NewReader(f.raw))
	if err != nil {
		return err
	}
	f.Format = FormatELF
	f.entry = ef.Entry
	f.arch = elfArch(ef)
	if ef.Class == elf.ELFCLASS32 {
		f.addrWidth = 8
	} else {
		f.addrWidth = 16
	}

	for _, s := range ef.Sections {
		fileSize := s.FileSize
		if s.Type == elf.SHT_NOBITS {
			fileSize = 0
		}
		sec := Section{
			Name:     s.Name,
			Addr:     s.Addr,
			Size:     s.Size,
			Offset:   s.Offset,
			FileSize: fileSize,
			TypeName: strings.TrimPrefix(s.Type.String(), "SHT_"),
			Flags:    elfFlags(s.Flags),
			Category: elfCategory(s),
			Alloc:    s.Flags&elf.SHF_ALLOC != 0,
			Exec:     s.Flags&elf.SHF_EXECINSTR != 0,
			Write:    s.Flags&elf.SHF_WRITE != 0,
		}
		f.Sections = append(f.Sections, sec)
	}

	// Relocatable objects (.o, kernel modules) load every section at address 0, so
	// the sections — and all their functions — would collide in one address space
	// and only one could be shown. Lay them out at synthetic sequential addresses
	// so each is distinct and navigable; the real position stays section-relative.
	// synthBase[i] is section i's assigned base (0 for sections left at address 0).
	synthBase := make([]uint64, len(f.Sections))
	f.relocatable = ef.Type == elf.ET_REL
	if ef.Type == elf.ET_REL {
		var base uint64
		for i := range f.Sections {
			s := &f.Sections[i]
			if !s.Alloc || s.Size == 0 {
				continue
			}
			align := uint64(1)
			if i < len(ef.Sections) && ef.Sections[i].Addralign > 1 {
				align = ef.Sections[i].Addralign
			}
			base = (base + align - 1) &^ (align - 1)
			synthBase[i] = base
			s.Addr = base
			s.SynthAddr = true
			base += s.Size
		}
		f.synthetic = base > 0
	}

	staticSyms, _ := ef.Symbols()
	dynSyms, _ := ef.DynamicSymbols()
	type symKey struct {
		name string
		addr uint64
	}
	seen := map[symKey]bool{}
	add := func(s elf.Symbol) {
		if s.Name == "" || isELFMappingSymbol(s.Name) || isELFLocalLabel(s) {
			return
		}
		key := symKey{s.Name, s.Value}
		if seen[key] {
			return
		}
		seen[key] = true
		sec := ""
		addr := s.Value
		realOff := s.Value
		if int(s.Section) >= 0 && int(s.Section) < len(ef.Sections) {
			sec = ef.Sections[s.Section].Name
			// In the synthetic layout, a symbol's real value is its offset within
			// its section; its synthetic address is that section's base + offset.
			if f.synthetic && int(s.Section) < len(f.Sections) && f.Sections[s.Section].SynthAddr {
				addr = synthBase[s.Section] + s.Value
			}
		}
		f.Symbols = append(f.Symbols, Symbol{
			Name:    s.Name,
			Addr:    addr,
			RealOff: realOff,
			Size:    s.Size,
			Kind:    elfSymKind(elf.ST_TYPE(s.Info)),
			Bind:    elfSymBind(elf.ST_BIND(s.Info)),
			Section: sec,
		})
	}
	for _, s := range staticSyms {
		add(s)
	}
	for _, s := range dynSyms {
		add(s)
	}
	f.appendELFImportSymbols(ef)

	for _, p := range ef.Progs {
		paddr := p.Paddr
		if paddr == p.Vaddr {
			paddr = 0 // only carry a physical address when it differs
		}
		f.Segments = append(f.Segments, Segment{
			Name:     strings.TrimPrefix(p.Type.String(), "PT_"),
			Addr:     p.Vaddr,
			PhysAddr: paddr,
			Size:     p.Memsz,
			Offset:   p.Off,
			FileSize: p.Filesz,
			Align:    p.Align,
			R:        p.Flags&elf.PF_R != 0,
			W:        p.Flags&elf.PF_W != 0,
			X:        p.Flags&elf.PF_X != 0,
		})
	}
	// Section load addresses (LMA): map each section through the PT_LOAD segment
	// whose file bytes contain it. LMA = p_paddr + (sh_offset - p_offset). Only
	// recorded when it differs from the virtual address (higher-half kernels etc.).
	for i := range f.Sections {
		s := &f.Sections[i]
		if s.Addr == 0 || s.FileSize == 0 {
			continue
		}
		for _, p := range ef.Progs {
			if p.Type != elf.PT_LOAD || p.Paddr == p.Vaddr || p.Filesz == 0 {
				continue
			}
			if s.Offset >= p.Off && s.Offset < p.Off+p.Filesz {
				if lma := p.Paddr + (s.Offset - p.Off); lma != s.Addr {
					s.PhysAddr = lma
				}
				break
			}
		}
	}

	if d := f.elfDWARF(ef); d != nil {
		f.dwarf = d // line table decoded lazily on first source lookup
	}

	f.loadELFInfo(ef)
	f.header = f.elfHeaderInfo(ef)
	f.rawHeader = f.elfRawHeader(ef)
	f.relocBuild = func() []Reloc { return f.elfRelocs(ef) }
	return nil
}

// decodeReloc extracts (offset, symbol index, type) from a relocation entry.
func decodeReloc(data []byte, off int, is64 bool, bo binary.ByteOrder) (roff uint64, sym, rtype uint32) {
	if is64 {
		roff = bo.Uint64(data[off:])
		info := bo.Uint64(data[off+8:])
		return roff, uint32(info >> 32), uint32(info)
	}
	roff = uint64(bo.Uint32(data[off:]))
	info := bo.Uint32(data[off+4:])
	return roff, info >> 8, info & 0xff
}

// appendELFImportSymbols synthesises symbols for dynamic relocations: each GOT
// slot (and, by pairing .rela.plt with .plt, each PLT stub) is named after the
// imported dynamic symbol it binds to. This resolves calls/jumps to imported
// functions in the disassembly for x86-64 and 386.
func (f *File) appendELFImportSymbols(ef *elf.File) {
	dyn, err := ef.DynamicSymbols()
	if err != nil || len(dyn) == 0 {
		return
	}
	is64 := ef.Class == elf.ELFCLASS64
	bo := ef.ByteOrder

	var jumpSlot, globDat uint32
	switch ef.Machine {
	case elf.EM_X86_64:
		jumpSlot, globDat = uint32(elf.R_X86_64_JMP_SLOT), uint32(elf.R_X86_64_GLOB_DAT)
	case elf.EM_386:
		jumpSlot, globDat = uint32(elf.R_386_JMP_SLOT), uint32(elf.R_386_GLOB_DAT)
	default:
		return
	}

	symLib := elfDynSymLibraries(ef, len(dyn))
	libOf := func(sym uint32) string {
		if int(sym) < len(symLib) {
			return symLib[sym]
		}
		return ""
	}

	add := func(addr uint64, name, lib string, kind SymKind, sec string) {
		f.Symbols = append(f.Symbols, Symbol{Name: name, Addr: addr, Kind: kind, Bind: BindGlobal, Section: sec, Library: lib})
	}

	type pltEntry struct{ name, lib string } // imports from .rel(a).plt, in entry order, for PLT pairing
	var pltNames []pltEntry
	for _, s := range ef.Sections {
		if s.Type != elf.SHT_RELA && s.Type != elf.SHT_REL {
			continue
		}
		data, err := s.Data()
		if err != nil {
			continue
		}
		entSize := 8 // REL32
		if s.Type == elf.SHT_RELA {
			entSize = 24 // RELA64
		}
		isPlt := s.Name == ".rela.plt" || s.Name == ".rel.plt"
		for off := 0; off+entSize <= len(data); off += entSize {
			roff, sym, rtype := decodeReloc(data, off, is64, bo)
			if sym == 0 || int(sym-1) >= len(dyn) {
				continue
			}
			name := dyn[sym-1].Name
			if name == "" {
				continue
			}
			lib := libOf(sym)
			switch rtype {
			case jumpSlot:
				add(roff, name, lib, SymObject, s.Name) // GOT slot
				if isPlt {
					pltNames = append(pltNames, pltEntry{name, lib})
				}
			case globDat:
				add(roff, name, lib, SymObject, s.Name)
			}
		}
	}

	// Name the PLT stubs by pairing them with the JUMP_SLOT relocations in
	// order. .plt.sec (CET/IBT) packs entries from index 0; classic .plt
	// reserves entry 0 for the resolver.
	if len(pltNames) > 0 {
		if plt := ef.Section(".plt.sec"); plt != nil {
			for i, e := range pltNames {
				add(plt.Addr+uint64(i)*16, e.name, e.lib, SymFunc, ".plt.sec")
			}
		} else if plt := ef.Section(".plt"); plt != nil {
			for i, e := range pltNames {
				add(plt.Addr+uint64(i+1)*16, e.name, e.lib, SymFunc, ".plt")
			}
		}
	}
}

// elfDynSymLibraries resolves, for each dynamic symbol index, the shared library
// it is versioned against, by pairing .gnu.version (a per-dynsym version index)
// with .gnu.version_r (verneed: version index → library filename). Returns a
// slice of length n indexed by dynsym index; entries are "" when unknown.
func elfDynSymLibraries(ef *elf.File, n int) []string {
	versym := ef.Section(".gnu.version")
	verneed := ef.Section(".gnu.version_r")
	if versym == nil || verneed == nil || n == 0 {
		return nil
	}
	vsData, err := versym.Data()
	if err != nil {
		return nil
	}
	vnData, err := verneed.Data()
	if err != nil {
		return nil
	}
	// The verneed strings live in its linked string table (usually .dynstr).
	if int(verneed.Link) >= len(ef.Sections) {
		return nil
	}
	strData, err := ef.Sections[verneed.Link].Data()
	if err != nil {
		return nil
	}
	str := func(off uint32) string {
		if int(off) >= len(strData) {
			return ""
		}
		end := bytes.IndexByte(strData[off:], 0)
		if end < 0 {
			return string(strData[off:])
		}
		return string(strData[off : int(off)+end])
	}

	bo := ef.ByteOrder
	// Walk the verneed entries, mapping each version index (vna_other) to the
	// library file the parent verneed names (vn_file).
	verIdxLib := map[uint16]string{}
	for off := 0; off+16 <= len(vnData); {
		// Elf_Verneed: version(2) cnt(2) file(4) aux(4) next(4)
		cnt := bo.Uint16(vnData[off+2:])
		file := bo.Uint32(vnData[off+4:])
		aux := bo.Uint32(vnData[off+8:])
		next := bo.Uint32(vnData[off+12:])
		lib := str(file)
		ap := off + int(aux)
		for i := 0; i < int(cnt) && ap+16 <= len(vnData); i++ {
			// Elf_Vernaux: hash(4) flags(2) other(2) name(4) next(4)
			other := bo.Uint16(vnData[ap+6:])
			anext := bo.Uint32(vnData[ap+12:])
			verIdxLib[other&0x7fff] = lib
			if anext == 0 {
				break
			}
			ap += int(anext)
		}
		if next == 0 {
			break
		}
		off += int(next)
	}
	if len(verIdxLib) == 0 {
		return nil
	}

	out := make([]string, n)
	for i := 0; i < n && (i+1)*2 <= len(vsData); i++ {
		v := bo.Uint16(vsData[i*2:]) & 0x7fff
		if lib, ok := verIdxLib[v]; ok {
			out[i] = lib
		}
	}
	return out
}

// isELFMappingSymbol reports whether name is an ARM/AArch64 ELF mapping symbol
// ($a/$d/$t/$x, optionally with a ".suffix"). These mark code/data boundaries
// and would otherwise shadow real function names in disasm annotations.
func isELFMappingSymbol(name string) bool {
	if len(name) < 2 || name[0] != '$' {
		return false
	}
	switch name[1] {
	case 'a', 'd', 't', 'x':
		return len(name) == 2 || name[2] == '.'
	}
	return false
}

// isELFLocalLabel reports whether s is a compiler/assembler-internal local label
// — the ".L…" convention used by GNU as and LLVM (".L0", ".LBB1_2", ".LCPI0_0").
// These aren't program symbols; RISC-V keeps them in .symtab for linker
// relaxation, where they otherwise flood the table (often all literally ".L0")
// and shadow real function labels in the disassembly view.
func isELFLocalLabel(s elf.Symbol) bool {
	return elf.ST_BIND(s.Info) == elf.STB_LOCAL &&
		elf.ST_TYPE(s.Info) == elf.STT_NOTYPE &&
		strings.HasPrefix(s.Name, ".L")
}

func elfArch(ef *elf.File) arch.Arch {
	le := ef.ByteOrder == binary.LittleEndian
	is64 := ef.Class == elf.ELFCLASS64
	switch ef.Machine {
	case elf.EM_X86_64:
		return arch.ArchAMD64
	case elf.EM_386:
		return arch.ArchX86
	case elf.EM_AARCH64:
		return arch.ArchARM64
	case elf.EM_RISCV:
		return arch.ArchRISCV64
	case elf.EM_ARM:
		// armasm decodes little-endian A32. Big-endian ARM (armeb) is BE-8 on
		// modern toolchains, which keeps instructions little-endian in memory, so
		// the same decoder applies. (Legacy BE-32, with big-endian instruction
		// words, is effectively extinct.)
		return arch.ArchARM
	case elf.EM_PPC:
		if le {
			return arch.ArchPPCLE
		}
		return arch.ArchPPC
	case elf.EM_PPC64:
		if le {
			return arch.ArchPPC64LE
		}
		return arch.ArchPPC64
	case elf.EM_S390:
		// EM_S390 covers 31-bit s390 and 64-bit s390x; x/arch decodes s390x.
		if is64 {
			return arch.ArchS390X
		}
	case elf.EM_LOONGARCH:
		if le && is64 {
			return arch.ArchLoong64
		}
	}
	return arch.ArchUnknown
}

func elfSymKind(t elf.SymType) SymKind {
	switch t {
	case elf.STT_FUNC:
		return SymFunc
	case elf.STT_OBJECT:
		return SymObject
	case elf.STT_SECTION:
		return SymSection
	case elf.STT_FILE:
		return SymFile
	case elf.STT_TLS:
		return SymTLS
	case elf.STT_COMMON:
		return SymCommon
	}
	return SymOther
}

func elfSymBind(b elf.SymBind) SymBind {
	switch b {
	case elf.STB_GLOBAL:
		return BindGlobal
	case elf.STB_WEAK:
		return BindWeak
	}
	return BindLocal
}

func elfFlags(f elf.SectionFlag) string {
	var b strings.Builder
	if f&elf.SHF_ALLOC != 0 {
		b.WriteByte('A')
	}
	if f&elf.SHF_WRITE != 0 {
		b.WriteByte('W')
	}
	if f&elf.SHF_EXECINSTR != 0 {
		b.WriteByte('X')
	}
	if f&elf.SHF_MERGE != 0 {
		b.WriteByte('M')
	}
	if f&elf.SHF_STRINGS != 0 {
		b.WriteByte('S')
	}
	if f&elf.SHF_TLS != 0 {
		b.WriteByte('T')
	}
	if b.Len() == 0 {
		return "-"
	}
	return b.String()
}

func elfCategory(s *elf.Section) SectionCategory {
	name, flags := s.Name, s.Flags
	if strings.HasPrefix(name, ".debug") || strings.HasPrefix(name, ".zdebug") {
		return CatDebug
	}
	if strings.HasPrefix(name, ".note") {
		return CatNote
	}
	switch s.Type {
	case elf.SHT_SYMTAB, elf.SHT_DYNSYM, elf.SHT_STRTAB:
		return CatSymtab
	case elf.SHT_DYNAMIC, elf.SHT_HASH, elf.SHT_GNU_HASH, elf.SHT_GNU_VERSYM,
		elf.SHT_GNU_VERDEF, elf.SHT_GNU_VERNEED:
		return CatDynamic
	case elf.SHT_REL, elf.SHT_RELA:
		return CatReloc
	case elf.SHT_NOBITS:
		return CatBSS
	}
	switch {
	case flags&elf.SHF_EXECINSTR != 0:
		return CatText
	case flags&elf.SHF_TLS != 0:
		return CatTLS
	case flags&elf.SHF_WRITE != 0:
		return CatData
	case flags&elf.SHF_ALLOC != 0:
		return CatRodata
	}
	return CatOther
}

func (f *File) elfHeaderInfo(ef *elf.File) []string {
	h := ef.FileHeader
	return []string{
		fmt.Sprintf("Path:        %s", f.Path),
		fmt.Sprintf("Format:      %s", f.Format),
		fmt.Sprintf("Class:       %s", h.Class),
		fmt.Sprintf("Data:        %s", h.Data),
		fmt.Sprintf("OS/ABI:      %s", h.OSABI),
		fmt.Sprintf("Type:        %s", h.Type),
		fmt.Sprintf("Machine:     %s", h.Machine),
		fmt.Sprintf("Entry:       0x%x", h.Entry),
		fmt.Sprintf("Sections:    %d", len(f.Sections)),
		fmt.Sprintf("Symbols:     %d", len(f.Symbols)),
		fmt.Sprintf("DWARF info:  %v", f.dwarf != nil),
	}
}

// ---- dynamic linking / identity ----

func (f *File) loadELFInfo(ef *elf.File) {
	in := &Info{}
	if sec := ef.Section(".interp"); sec != nil {
		if data, err := sec.Data(); err == nil {
			in.Interp = strings.TrimRight(string(data), "\x00")
		}
	}
	if libs, err := ef.ImportedLibraries(); err == nil {
		in.DynamicLibs = libs
	}
	if v, err := ef.DynString(elf.DT_RPATH); err == nil {
		in.RPath = splitColon(v)
	}
	if v, err := ef.DynString(elf.DT_RUNPATH); err == nil {
		in.RunPath = splitColon(v)
	}
	if v, err := ef.DynString(elf.DT_SONAME); err == nil && len(v) > 0 {
		in.SoName = v[0]
	}
	in.BuildID = readBuildID(ef)

	hasSymtab := false
	for _, s := range ef.Sections {
		if s.Type == elf.SHT_SYMTAB {
			hasSymtab = true
			break
		}
	}
	in.Stripped = !hasSymtab
	in.StaticLinked = in.Interp == "" && len(in.DynamicLibs) == 0
	in.Libc = identifyLibc(ef, in)

	// Layout.
	in.WordBits = 32
	if ef.Class == elf.ELFCLASS64 {
		in.WordBits = 64
	}
	in.ByteOrder = "little-endian"
	if ef.Data == elf.ELFDATA2MSB {
		in.ByteOrder = "big-endian"
	}
	in.Segments = len(ef.Progs)

	// PIE: an ET_DYN executable, confirmed by DF_1_PIE when present.
	if ef.Type == elf.ET_DYN {
		in.PIE = TriYes
	} else {
		in.PIE = TriNo
	}
	if vals, err := ef.DynValue(elf.DT_FLAGS_1); err == nil {
		for _, v := range vals {
			if v&uint64(elf.DF_1_PIE) != 0 {
				in.PIE = TriYes
			}
		}
	}

	// NX: a PT_GNU_STACK without the executable flag.
	in.NX = TriUnknown
	for _, p := range ef.Progs {
		if p.Type == elf.PT_GNU_STACK {
			if p.Flags&elf.PF_X != 0 {
				in.NX = TriNo
			} else {
				in.NX = TriYes
			}
		}
	}

	// RELRO: a PT_GNU_RELRO segment (partial), full when also BIND_NOW.
	relro := false
	for _, p := range ef.Progs {
		if p.Type == elf.PT_GNU_RELRO {
			relro = true
		}
	}
	bindNow := false
	if vals, err := ef.DynValue(elf.DT_FLAGS); err == nil {
		for _, v := range vals {
			if v&uint64(elf.DF_BIND_NOW) != 0 {
				bindNow = true
			}
		}
	}
	if vals, err := ef.DynValue(elf.DT_FLAGS_1); err == nil {
		for _, v := range vals {
			if v&uint64(elf.DF_1_NOW) != 0 {
				bindNow = true
			}
		}
	}
	if vals, err := ef.DynValue(elf.DT_BIND_NOW); err == nil && len(vals) > 0 {
		bindNow = true
	}
	switch {
	case relro && bindNow:
		in.RELRO = "full"
	case relro:
		in.RELRO = "partial"
	default:
		in.RELRO = "none"
	}

	// Compiler from .comment.
	if sec := ef.Section(".comment"); sec != nil {
		if d, err := sec.Data(); err == nil {
			in.Compiler = cleanComment(d)
		}
	}

	f.Info = in
}

// cleanComment turns a NUL-separated .comment blob into a readable, deduped
// one-liner.
func cleanComment(b []byte) string {
	var out []string
	seen := map[string]bool{}
	for _, p := range strings.Split(string(b), "\x00") {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	s := strings.Join(out, "; ")
	if len(s) > 120 {
		s = s[:119] + "…"
	}
	return s
}

// readBuildID parses .note.gnu.build-id and returns the descriptor as hex.
func readBuildID(ef *elf.File) string {
	sec := ef.Section(".note.gnu.build-id")
	if sec == nil {
		return ""
	}
	data, err := sec.Data()
	if err != nil {
		return ""
	}
	order := ef.ByteOrder
	for off := 0; off+12 <= len(data); {
		nameSz := order.Uint32(data[off:])
		descSz := order.Uint32(data[off+4:])
		nType := order.Uint32(data[off+8:])
		off += 12
		if off+int(nameSz) > len(data) {
			break
		}
		name := data[off : off+int(nameSz)]
		off += align4(int(nameSz))
		if off+int(descSz) > len(data) {
			break
		}
		desc := data[off : off+int(descSz)]
		off += align4(int(descSz))
		if nType == 3 && bytes.HasPrefix(name, []byte("GNU\x00")) {
			return fmt.Sprintf("%x", desc)
		}
	}
	return ""
}

func identifyLibc(ef *elf.File, in *Info) LibcInfo {
	if in.Interp != "" {
		low := strings.ToLower(in.Interp)
		switch {
		case strings.Contains(low, "musl"):
			return LibcInfo{Kind: "musl", Source: "interp"}
		case strings.Contains(low, "uclibc"):
			return LibcInfo{Kind: "uClibc", Source: "interp"}
		case strings.HasPrefix(low, "/system/bin/linker"):
			return LibcInfo{Kind: "bionic", Source: "interp"}
		case strings.Contains(low, "ld-linux") || strings.HasSuffix(low, "/ld.so.1") || strings.HasSuffix(low, "/ld.so.2"):
			return LibcInfo{Kind: "glibc", Source: "interp"}
		}
	}
	for _, lib := range in.DynamicLibs {
		low := strings.ToLower(lib)
		switch {
		case strings.HasPrefix(low, "libc.musl") || strings.Contains(low, "musl"):
			return LibcInfo{Kind: "musl", Source: "needed"}
		case strings.HasPrefix(low, "libuclibc") || strings.Contains(low, "uclibc"):
			return LibcInfo{Kind: "uClibc", Source: "needed"}
		case low == "libc.so.6":
			return LibcInfo{Kind: "glibc", Source: "needed"}
		case low == "libc.so" || low == "libc.so.0":
			return LibcInfo{Kind: "bionic", Source: "needed"}
		}
	}
	if k := fingerprintLibcRodata(ef); k.Kind != "" {
		return k
	}
	if in.StaticLinked {
		return LibcInfo{Kind: "unknown", Source: "static"}
	}
	if len(in.DynamicLibs) == 0 {
		return LibcInfo{Kind: "none", Source: "no-deps"}
	}
	return LibcInfo{Kind: "unknown", Source: "no-match"}
}

func fingerprintLibcRodata(ef *elf.File) LibcInfo {
	for _, s := range ef.Sections {
		if !strings.HasPrefix(s.Name, ".rodata") {
			continue
		}
		data, err := s.Data()
		if err != nil {
			continue
		}
		if i := bytes.Index(data, []byte("GNU C Library")); i >= 0 {
			return LibcInfo{Kind: "glibc", Source: "rodata-fingerprint", Version: extractGlibcVersion(data[i:])}
		}
		if bytes.Contains(data, []byte("musl libc")) {
			return LibcInfo{Kind: "musl", Source: "rodata-fingerprint", Version: extractMuslVersion(data)}
		}
		if bytes.Contains(data, []byte("uClibc")) {
			return LibcInfo{Kind: "uClibc", Source: "rodata-fingerprint"}
		}
		if bytes.Contains(data, []byte("Bionic")) {
			return LibcInfo{Kind: "bionic", Source: "rodata-fingerprint"}
		}
	}
	return LibcInfo{}
}
