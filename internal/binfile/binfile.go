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
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/rabarbra/exex/internal/arch"
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
	Library   string // for imports: the shared library this symbol is bound to
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

	raw       []byte       // entire file contents (mmap'd or read; raw view + section data)
	unmap     func() error // releases the mapping backing raw (nil-safe via Close)
	arch      arch.Arch
	entry     uint64
	addrWidth int // hex digits in a printed address (8 or 16)
	header    []string

	symByAddr []Symbol // sorted by Addr
	dwarf     *dwarf.Data
	lines     []lineEntry         // sorted by Addr (loaded lazily from dwarf)
	linesOnce sync.Once           // guards the lazy line-table decode
	sources   map[string][]string // resolved file -> lines

	vaImage   *Image        // all mapped sections, in VA order (lazy)
	execImage *Image        // executable sections only, in VA order (lazy)
	strings   []StringEntry // printable strings, extracted lazily
}

type lineEntry struct {
	Addr uint64
	File string
	Line int
	Col  int
}

// Open reads path, detects its container format, and builds the neutral model.
func Open(path string) (*File, error) {
	// mapFile mmaps the file where that's safe (always on Linux; on macOS only
	// when the Mach-O carries no code signature, since mmap'ing a signed binary
	// gets the process SIGKILL'd), otherwise it reads the file into the heap.
	raw, closer, err := mapFile(path)
	if err != nil {
		return nil, err
	}
	f := &File{
		Path:    path,
		raw:     raw,
		unmap:   closer,
		sources: map[string][]string{},
	}
	switch {
	case len(raw) >= 4 && raw[0] == 0x7f && raw[1] == 'E' && raw[2] == 'L' && raw[3] == 'F':
		if err := f.loadELF(); err != nil {
			f.Close()
			return nil, err
		}
	case isMachO(raw):
		if err := f.loadMachO(); err != nil {
			f.Close()
			return nil, err
		}
	case len(raw) >= 2 && raw[0] == 'M' && raw[1] == 'Z':
		if err := f.loadPE(); err != nil {
			f.Close()
			return nil, err
		}
	default:
		f.Close()
		return nil, fmt.Errorf("unrecognised file format (not ELF, Mach-O, or PE)")
	}

	f.finalizeSymbols()
	f.computeOverview()
	return f, nil
}

// Close releases the file mapping. Safe to call more than once; afterwards the
// raw bytes (and anything slicing into them) must not be used.
func (f *File) Close() error {
	if f == nil || f.unmap == nil {
		return nil
	}
	err := f.unmap()
	f.unmap = nil
	f.raw = nil
	return err
}

// finalizeSymbols sorts symbols, fills in missing sizes, and builds the
// address-indexed copy used for reverse lookups. Loaders append unsorted
// symbols with their Size left at 0 when the container doesn't record one
// (notably Mach-O); we infer those from the gap to the next symbol so the
// disasm view can still annotate ranges and SymbolAt can cover an address.
// finalizeSymbols sorts symbols and builds the address index. Demangling is
// intentionally NOT done here — it's the slowest part of loading a big symbol
// table, so callers run it separately (ComputeDemangled/ApplyDemangled) off the
// critical path; until then Display() falls back to the raw name.
func (f *File) finalizeSymbols() {
	sort.Slice(f.Symbols, func(i, j int) bool { return f.Symbols[i].Name < f.Symbols[j].Name })

	addrIdx := make([]int, 0, len(f.Symbols))
	for i, s := range f.Symbols {
		if s.Addr != 0 {
			addrIdx = append(addrIdx, i)
		}
	}
	sortAddrIdx := func() {
		sort.Slice(addrIdx, func(i, j int) bool {
			si := f.Symbols[addrIdx[i]]
			sj := f.Symbols[addrIdx[j]]
			if si.Addr != sj.Addr {
				return si.Addr < sj.Addr
			}
			return si.Size > sj.Size
		})
	}
	sortAddrIdx()
	f.inferSymbolSizes(addrIdx)
	sortAddrIdx()

	f.symByAddr = make([]Symbol, 0, len(addrIdx))
	for _, idx := range addrIdx {
		f.symByAddr = append(f.symByAddr, f.Symbols[idx])
	}
}

// inferSymbolSizes gives zero-sized symbols an extent reaching to the next
// symbol at a higher address (clamped to the containing section's end). Symbols
// that already carry a size are left untouched.
func (f *File) inferSymbolSizes(addrIdx []int) {
	for i, idx := range addrIdx {
		if f.Symbols[idx].Size != 0 {
			continue
		}
		addr := f.Symbols[idx].Addr
		var next uint64
		for j := i + 1; j < len(addrIdx); j++ {
			candidate := f.Symbols[addrIdx[j]].Addr
			if candidate > addr {
				next = candidate
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
			f.Symbols[idx].Size = next - addr
		}
	}
}

// ComputeDemangled returns the demangled form of every symbol name, indexed
// like f.Symbols ("" when a name isn't mangled). It only reads names, so it is
// safe to run on a background goroutine; apply the result with ApplyDemangled
// on the goroutine that owns the File. Demangling a large symbol table
// (Rust/C++/Swift binaries carry 100k+ mangled names) dominates load time, and
// demangle.Filter is pure, so the C++/Rust pass is fanned out across cores.
func (f *File) ComputeDemangled() []string {
	out := make([]string, len(f.Symbols))
	n := runtime.NumCPU()
	if n < 1 {
		n = 1
	}
	itanium := func(lo, hi int) {
		for i := lo; i < hi; i++ {
			out[i] = demangleName(f.Symbols[i].Name)
		}
	}
	if len(f.Symbols) < 2048 || n == 1 {
		itanium(0, len(f.Symbols))
	} else {
		chunk := (len(f.Symbols) + n - 1) / n
		var wg sync.WaitGroup
		for lo := 0; lo < len(f.Symbols); lo += chunk {
			hi := min(lo+chunk, len(f.Symbols))
			wg.Add(1)
			go func(lo, hi int) { defer wg.Done(); itanium(lo, hi) }(lo, hi)
		}
		wg.Wait()
	}
	demangleSwiftInto(f.Symbols, out)
	return out
}

// ApplyDemangled stores the result of ComputeDemangled onto the symbols (and the
// address-indexed copies). Run it on the File's owning goroutine.
func (f *File) ApplyDemangled(d []string) {
	if len(d) != len(f.Symbols) {
		return
	}
	byName := make(map[string]string, len(d))
	for i := range f.Symbols {
		f.Symbols[i].Demangled = d[i]
		if d[i] != "" {
			byName[f.Symbols[i].Name] = d[i]
		}
	}
	for i := range f.symByAddr {
		if dm, ok := byName[f.symByAddr[i].Name]; ok {
			f.symByAddr[i].Demangled = dm
		}
	}
}

// lineEntries returns the address→source line table, decoding it from DWARF on
// first use. Decoding is deferred out of Open because it's only needed once the
// user looks at source mapping (the Sources view / source pane), and it is a
// large slice of the startup cost for binaries with rich debug info.
func (f *File) lineEntries() []lineEntry {
	f.linesOnce.Do(func() {
		if f.dwarf != nil {
			f.lines = loadLines(f.dwarf)
		}
	})
	return f.lines
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
			out = append(out, lineEntry{Addr: le.Address, File: le.File.Name, Line: le.Line, Col: le.Column})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr < out[j].Addr })
	return out
}

// SourceFiles returns the sorted, de-duplicated set of source files referenced
// by the DWARF line table.
func (f *File) SourceFiles() []string {
	seen := map[string]bool{}
	var out []string
	for _, le := range f.lineEntries() {
		if le.File != "" && !seen[le.File] {
			seen[le.File] = true
			out = append(out, le.File)
		}
	}
	sort.Strings(out)
	return out
}

// LineToAddr returns an address that maps to file:line — exact when possible,
// otherwise the nearest line at or after it in the same file.
func (f *File) LineToAddr(file string, line int) (uint64, bool) {
	var (
		best     uint64
		bestLine int
		found    bool
	)
	for _, le := range f.lineEntries() {
		if le.File != file {
			continue
		}
		if le.Line == line {
			if !found || le.Addr < best {
				best, bestLine, found = le.Addr, le.Line, true
			}
			if bestLine == line {
				// keep scanning for the lowest address at the exact line
				continue
			}
		}
		// Track the nearest line >= the target as a fallback.
		if le.Line >= line && (!found || (bestLine != line && le.Line < bestLine)) {
			best, bestLine, found = le.Addr, le.Line, true
		}
	}
	return best, found
}

// LookupAddr returns the source file:line covering addr, or "", 0.
func (f *File) LookupAddr(addr uint64) (string, int) {
	file, line, _ := f.LookupAddrCol(addr)
	return file, line
}

// LookupAddrCol is LookupAddr plus the DWARF column (0 when unknown).
func (f *File) LookupAddrCol(addr uint64) (file string, line, col int) {
	lines := f.lineEntries()
	if len(lines) == 0 {
		return "", 0, 0
	}
	i := sort.Search(len(lines), func(i int) bool { return lines[i].Addr > addr })
	if i == 0 {
		return "", 0, 0
	}
	le := lines[i-1]
	return le.File, le.Line, le.Col
}

// MappedLines returns the set of line numbers in file that have any machine
// code mapped to them.
func (f *File) MappedLines(file string) map[int]bool {
	out := map[int]bool{}
	for _, le := range f.lineEntries() {
		if le.File == file {
			out[le.Line] = true
		}
	}
	return out
}

// LineColumns returns the distinct, sorted DWARF columns (>0) recorded for
// file:line — the positions within the line that code maps to.
func (f *File) LineColumns(file string, line int) []int {
	seen := map[int]bool{}
	for _, le := range f.lineEntries() {
		if le.File == file && le.Line == line && le.Col > 0 {
			seen[le.Col] = true
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]int, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Ints(out)
	return out
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

// Arch returns the CPU architecture for this binary.
func (f *File) Arch() arch.Arch { return f.arch }

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
