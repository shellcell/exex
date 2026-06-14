// Package binfile loads an executable (ELF or Mach-O) and exposes the bits the
// explorer needs through a single, format-neutral model: header info,
// sections, symbols, address→source mapping, and continuous virtual-address /
// raw-file byte images for the hex and disassembly views.
package binfile

import (
	"debug/dwarf"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rabarbra/exex/internal/disasm"
)

// Format identifies the container the binary was loaded from.
type Format string

const (
	FormatELF   Format = "ELF"
	FormatMachO Format = "Mach-O"
	FormatPE    Format = "PE"
)

// SymKind is a format-neutral symbol category. Both ELF symbol types and the
// looser Mach-O symbol table are mapped onto these so the UI can colour and
// route a symbol without knowing where it came from.
type SymKind uint8

const (
	SymOther   SymKind = iota
	SymFunc            // executable code
	SymObject          // data object
	SymSection         // names a whole section
	SymFile            // source filename
	SymTLS             // thread-local storage
	SymCommon          // uninitialised common block
)

// SymBind is a format-neutral symbol binding/scope.
type SymBind uint8

const (
	BindLocal SymBind = iota
	BindGlobal
	BindWeak
)

// SectionCategory drives section-table row colouring without leaning on
// format-specific section types.
type SectionCategory uint8

const (
	CatOther   SectionCategory = iota
	CatText                    // executable code
	CatData                    // writable data
	CatBSS                     // zero-initialised data
	CatRodata                  // read-only allocated data
	CatTLS                     // thread-local storage
	CatDebug                   // DWARF / debug info
	CatNote                    // notes / build metadata
	CatSymtab                  // symbol & string tables
	CatDynamic                 // dynamic-linking metadata
	CatReloc                   // relocations
)

// Section is one named region of the file, in a format-neutral shape. Addr is
// the load (virtual) address, 0 when the section is not mapped. Offset/FileSize
// describe where its bytes live in the file (FileSize == 0 for BSS-style
// zero-fill sections that occupy no file space).
type Section struct {
	Name     string
	Addr     uint64
	Size     uint64 // in-memory size
	Offset   uint64 // file offset of the bytes
	FileSize uint64 // bytes actually present in the file
	TypeName string // short type label for the table ("PROGBITS", "__text", …)
	Flags    string // short flag string ("AX", "r-x", …)
	Category SectionCategory
	Alloc    bool // occupies memory at runtime (has a virtual address)
	Exec     bool // executable
	Write    bool // writable
}

// Symbol is a format-neutral symbol. Name is the raw (possibly mangled) name
// as stored in the file; Demangled holds the human-readable form when the name
// was a recognised C++/Rust mangling, else "".
type Symbol struct {
	Name      string
	Demangled string
	Addr      uint64
	Size      uint64
	Kind      SymKind
	Bind      SymBind
	Section   string
}

// Display returns the demangled name when available, else the raw name.
func (s Symbol) Display() string {
	if s.Demangled != "" {
		return s.Demangled
	}
	return s.Name
}

type File struct {
	Path     string
	Format   Format
	Sections []Section
	Symbols  []Symbol // sorted by Name
	Info     *Info

	raw       []byte // entire file contents (source for the raw view + section data)
	arch      disasm.Arch
	entry     uint64
	addrWidth int // hex digits in a printed address (8 or 16)
	header    []string

	symByAddr []Symbol // sorted by Addr
	dwarf     *dwarf.Data
	lines     []lineEntry         // sorted by Addr
	sources   map[string][]string // resolved file -> lines

	vaImage   *Image        // all mapped sections, in VA order (lazy)
	execImage *Image        // executable sections only, in VA order (lazy)
	strings   []StringEntry // printable strings, extracted lazily
}

type lineEntry struct {
	Addr uint64
	File string
	Line int
}

// Open reads path, detects its container format, and builds the neutral model.
func Open(path string) (*File, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	f := &File{
		Path:    path,
		raw:     raw,
		sources: map[string][]string{},
	}
	switch {
	case len(raw) >= 4 && raw[0] == 0x7f && raw[1] == 'E' && raw[2] == 'L' && raw[3] == 'F':
		if err := f.loadELF(); err != nil {
			return nil, err
		}
	case isMachO(raw):
		if err := f.loadMachO(); err != nil {
			return nil, err
		}
	case len(raw) >= 2 && raw[0] == 'M' && raw[1] == 'Z':
		if err := f.loadPE(); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unrecognised file format (not ELF, Mach-O, or PE)")
	}

	f.finalizeSymbols()
	f.computeOverview()
	return f, nil
}

// finalizeSymbols sorts symbols, fills in missing sizes, and builds the
// address-indexed copy used for reverse lookups. Loaders append unsorted
// symbols with their Size left at 0 when the container doesn't record one
// (notably Mach-O); we infer those from the gap to the next symbol so the
// disasm view can still annotate ranges and SymbolAt can cover an address.
func (f *File) finalizeSymbols() {
	for i := range f.Symbols {
		f.Symbols[i].Demangled = demangleName(f.Symbols[i].Name)
	}
	f.demangleSwift()
	sort.Slice(f.Symbols, func(i, j int) bool { return f.Symbols[i].Name < f.Symbols[j].Name })

	f.symByAddr = make([]Symbol, 0, len(f.Symbols))
	for _, s := range f.Symbols {
		if s.Addr != 0 {
			f.symByAddr = append(f.symByAddr, s)
		}
	}
	sort.Slice(f.symByAddr, func(i, j int) bool {
		if f.symByAddr[i].Addr != f.symByAddr[j].Addr {
			return f.symByAddr[i].Addr < f.symByAddr[j].Addr
		}
		return f.symByAddr[i].Size > f.symByAddr[j].Size
	})
	f.inferSizes()
}

// inferSizes gives zero-sized symbols an extent reaching to the next symbol at
// a higher address (clamped to the containing section's end). Symbols that
// already carry a size are left untouched.
func (f *File) inferSizes() {
	for i := range f.symByAddr {
		if f.symByAddr[i].Size != 0 {
			continue
		}
		addr := f.symByAddr[i].Addr
		var next uint64
		for j := i + 1; j < len(f.symByAddr); j++ {
			if f.symByAddr[j].Addr > addr {
				next = f.symByAddr[j].Addr
				break
			}
		}
		if sec := f.SectionAt(addr); sec != nil {
			secEnd := sec.Addr + sec.Size
			if next == 0 || next > secEnd {
				next = secEnd
			}
		}
		if next > addr {
			f.symByAddr[i].Size = next - addr
		}
	}
}

// sectionData returns the file bytes backing a section (nil for zero-fill).
func (f *File) sectionData(s *Section) []byte {
	if s.FileSize == 0 {
		return nil
	}
	end := s.Offset + s.FileSize
	if s.Offset >= uint64(len(f.raw)) || end > uint64(len(f.raw)) {
		return nil
	}
	return f.raw[s.Offset:end]
}

func loadLines(d *dwarf.Data) []lineEntry {
	var out []lineEntry
	r := d.Reader()
	for {
		cu, err := r.Next()
		if err != nil || cu == nil {
			break
		}
		if cu.Tag != dwarf.TagCompileUnit {
			r.SkipChildren()
			continue
		}
		lr, err := d.LineReader(cu)
		if err != nil || lr == nil {
			continue
		}
		var le dwarf.LineEntry
		for {
			if err := lr.Next(&le); err != nil {
				break
			}
			if le.File == nil {
				continue
			}
			out = append(out, lineEntry{Addr: le.Address, File: le.File.Name, Line: le.Line})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr < out[j].Addr })
	return out
}

// LookupAddr returns the source file:line covering addr, or "", 0.
func (f *File) LookupAddr(addr uint64) (string, int) {
	if len(f.lines) == 0 {
		return "", 0
	}
	i := sort.Search(len(f.lines), func(i int) bool { return f.lines[i].Addr > addr })
	if i == 0 {
		return "", 0
	}
	le := f.lines[i-1]
	return le.File, le.Line
}

// SymbolAt returns the symbol whose extent covers addr.
func (f *File) SymbolAt(addr uint64) (Symbol, bool) {
	if len(f.symByAddr) == 0 {
		return Symbol{}, false
	}
	i := sort.Search(len(f.symByAddr), func(i int) bool { return f.symByAddr[i].Addr > addr })
	if i == 0 {
		return Symbol{}, false
	}
	s := f.symByAddr[i-1]
	if s.Size == 0 {
		if s.Addr == addr {
			return s, true
		}
		return Symbol{}, false
	}
	if addr >= s.Addr && addr < s.Addr+s.Size {
		return s, true
	}
	return Symbol{}, false
}

// NextSymbol returns the first symbol (by address) strictly after addr that
// satisfies pred (a nil pred accepts any symbol).
func (f *File) NextSymbol(addr uint64, pred func(Symbol) bool) (Symbol, bool) {
	for _, s := range f.symByAddr {
		if s.Addr <= addr {
			continue
		}
		if pred == nil || pred(s) {
			return s, true
		}
	}
	return Symbol{}, false
}

// PrevSymbol returns the last symbol (by address) strictly before addr that
// satisfies pred (a nil pred accepts any symbol).
func (f *File) PrevSymbol(addr uint64, pred func(Symbol) bool) (Symbol, bool) {
	for i := len(f.symByAddr) - 1; i >= 0; i-- {
		s := f.symByAddr[i]
		if s.Addr >= addr {
			continue
		}
		if pred == nil || pred(s) {
			return s, true
		}
	}
	return Symbol{}, false
}

// DefaultExecAddr resolves a guaranteed-executable address to land the disasm
// view on, honouring the requested strategy and falling back down a sensible
// chain when the choice can't be resolved. Returns 0 only when the binary has
// no executable code at all.
//
// Strategies: "entry" (the entry point), "main"/"start" (those symbols),
// "text" (the .text/__text section), "lowest" (lowest executable address).
func (f *File) DefaultExecAddr(strategy string) uint64 {
	inExec := func(a uint64) bool {
		_, ok := f.ExecImage().PosForAddr(a)
		return ok
	}
	try := func(s string) (uint64, bool) {
		switch s {
		case "entry":
			if f.entry != 0 && inExec(f.entry) {
				return f.entry, true
			}
		case "main":
			if a, ok := f.symbolAddr("main", "_main"); ok {
				return a, true
			}
		case "start":
			if a, ok := f.symbolAddr("_start", "start", "__start"); ok {
				return a, true
			}
		case "text":
			if a, ok := f.execSectionAddr(".text", "__text"); ok {
				return a, true
			}
		case "lowest":
			if im := f.ExecImage(); len(im.Regions) > 0 {
				return im.Regions[0].Addr, true
			}
		}
		return 0, false
	}
	for _, s := range []string{strategy, "entry", "main", "start", "text", "lowest"} {
		if a, ok := try(s); ok {
			return a
		}
	}
	return 0
}

// symbolAddr returns the address of the first named symbol that lands in
// executable code.
func (f *File) symbolAddr(names ...string) (uint64, bool) {
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	for _, s := range f.symByAddr {
		if want[s.Name] {
			if _, ok := f.ExecImage().PosForAddr(s.Addr); ok {
				return s.Addr, true
			}
		}
	}
	return 0, false
}

// execSectionAddr returns the address of the first executable section matching
// one of the given names.
func (f *File) execSectionAddr(names ...string) (uint64, bool) {
	for i := range f.Sections {
		s := &f.Sections[i]
		if !s.Exec || s.Size == 0 {
			continue
		}
		for _, n := range names {
			if s.Name == n {
				return s.Addr, true
			}
		}
	}
	return 0, false
}

// SectionAt returns the mapped section whose VM range covers addr.
func (f *File) SectionAt(addr uint64) *Section {
	for i := range f.Sections {
		s := &f.Sections[i]
		if !s.Alloc || s.Size == 0 {
			continue
		}
		if addr >= s.Addr && addr < s.Addr+s.Size {
			return s
		}
	}
	return nil
}

// IsMapped reports whether addr falls inside any mapped section.
func (f *File) IsMapped(addr uint64) bool { return f.SectionAt(addr) != nil }

// IsExecSection reports whether a section is executable (eligible for disasm).
func IsExecSection(s *Section) bool { return s != nil && s.Exec && s.Size > 0 }

// SourceLines returns the source file's lines, searching common locations.
func (f *File) SourceLines(name string) []string {
	if name == "" {
		return nil
	}
	if v, ok := f.sources[name]; ok {
		return v
	}
	candidates := []string{name}
	if !filepath.IsAbs(name) {
		candidates = append(candidates, filepath.Join(filepath.Dir(f.Path), name))
	}
	candidates = append(candidates, filepath.Base(name))
	for _, c := range candidates {
		if b, err := os.ReadFile(c); err == nil {
			lines := strings.Split(string(b), "\n")
			f.sources[name] = lines
			return lines
		}
	}
	f.sources[name] = nil
	return nil
}

// HasDWARF reports whether DWARF info was loaded.
func (f *File) HasDWARF() bool { return f.dwarf != nil }

// Entry returns the entry-point virtual address.
func (f *File) Entry() uint64 { return f.entry }

// Arch returns the disassembler architecture for this binary.
func (f *File) Arch() disasm.Arch { return f.arch }

// Raw returns the entire file contents (source for the raw hex view).
func (f *File) Raw() []byte { return f.raw }

// AddrHexWidth is the number of hex digits an address should be printed with.
func (f *File) AddrHexWidth() int {
	if f.addrWidth == 0 {
		return 16
	}
	return f.addrWidth
}

// HeaderInfo returns the container header as a list of "Label: value" lines.
func (f *File) HeaderInfo() []string { return f.header }
