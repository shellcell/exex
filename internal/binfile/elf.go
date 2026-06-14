package binfile

import (
	"bytes"
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/rabarbra/exex/internal/disasm"
)

// elfDWARF returns DWARF for the binary: embedded, or from a separate debug
// file referenced by .gnu_debuglink (the ELF analogue of macOS .dSYM).
func (f *File) elfDWARF(ef *elf.File) *dwarf.Data {
	if d, err := ef.DWARF(); err == nil {
		return d
	}
	name := elfDebugLink(ef)
	if name == "" {
		return nil
	}
	dir := filepath.Dir(f.Path)
	for _, c := range []string{
		filepath.Join(dir, name),
		filepath.Join(dir, ".debug", name),
		filepath.Join("/usr/lib/debug", dir, name),
	} {
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
	f.arch = elfArch(ef.Machine)
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

	staticSyms, _ := ef.Symbols()
	dynSyms, _ := ef.DynamicSymbols()
	seen := map[string]bool{}
	add := func(s elf.Symbol) {
		key := fmt.Sprintf("%s@%x", s.Name, s.Value)
		if seen[key] {
			return
		}
		seen[key] = true
		sec := ""
		if int(s.Section) >= 0 && int(s.Section) < len(ef.Sections) {
			sec = ef.Sections[s.Section].Name
		}
		f.Symbols = append(f.Symbols, Symbol{
			Name:    s.Name,
			Addr:    s.Value,
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

	if d := f.elfDWARF(ef); d != nil {
		f.dwarf = d
		f.lines = loadLines(d)
	}

	f.loadELFInfo(ef)
	f.header = f.elfHeaderInfo(ef)
	return nil
}

func elfArch(m elf.Machine) disasm.Arch {
	switch m {
	case elf.EM_X86_64:
		return disasm.ArchAMD64
	case elf.EM_386:
		return disasm.ArchX86
	case elf.EM_AARCH64:
		return disasm.ArchARM64
	case elf.EM_RISCV:
		return disasm.ArchRISCV64
	}
	return disasm.ArchUnknown
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
