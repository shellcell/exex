// Package binfile loads an executable (ELF or Mach-O) and exposes the bits the
// explorer needs through a single, format-neutral model: header info,
// sections, symbols, address→source mapping, and continuous virtual-address /
// raw-file byte images for the hex and disassembly views.
package binfile

import (
	"cmp"
	"debug/dwarf"
	"os"
	"path/filepath"
	"runtime"
	"slices"
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
	Name      string
	Addr      uint64
	PhysAddr  uint64 // load/physical address (LMA); 0 when same as Addr or unknown
	SynthAddr bool   // Addr is a synthetic layout address (relocatable object); real address is 0
	Size      uint64 // in-memory size
	Offset    uint64 // file offset of the bytes
	FileSize  uint64 // bytes actually present in the file
	TypeName  string // short type label for the table ("PROGBITS", "__text", …)
	Flags     string // short flag string ("AX", "r-x", …)
	Category  SectionCategory
	Alloc     bool // occupies memory at runtime (has a virtual address)
	Exec      bool // executable
	Write     bool // writable
}

// Segment is a loadable region of the program's memory image — an ELF program
// header (PT_LOAD, …) or a Mach-O segment (__TEXT, …). Sections live inside
// segments; this is the coarser memory-map level. Not all formats have segments
// (PE has none), so Segments may be empty.
type Segment struct {
	Name     string // type label: "LOAD", "DYNAMIC", "__TEXT", …
	Addr     uint64 // virtual address (0 when not mapped)
	PhysAddr uint64 // physical/load address (ELF p_paddr); 0 when same as Addr or unknown
	Size     uint64 // in-memory size
	Offset   uint64 // file offset of the bytes
	FileSize uint64 // bytes present in the file
	Align    uint64 // alignment (0 when unknown)
	R, W, X  bool   // permissions
}

// FatArchInfo summarises one architecture slice of a universal (fat) Mach-O,
// for the Info view's per-architecture listing.
type FatArchInfo struct {
	Name   string // conventional CPU name, e.g. "x86_64", "arm64"
	Type   string // Mach-O file type: "Exec", "Dylib", …
	Bits   int    // 32 or 64
	Offset uint64 // file offset where the slice begins
	Size   uint64 // slice size in bytes
}

// Perms renders the segment's permission bits as an "rwx" string.
func (s Segment) Perms() string {
	b := []byte("---")
	if s.R {
		b[0] = 'r'
	}
	if s.W {
		b[1] = 'w'
	}
	if s.X {
		b[2] = 'x'
	}
	return string(b)
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
	// RealOff is the symbol's real position within its section (st_value) when the
	// file uses a synthetic address layout (a relocatable object); Addr is then the
	// synthetic address exex assigned. Both equal Addr otherwise.
	RealOff uint64
}

// Display returns the demangled name when available, else the raw name.
func (s Symbol) Display() string {
	if s.Demangled != "" {
		return s.Demangled
	}
	return s.Name
}

// File is the format-neutral representation of one loaded binary.
type File struct {
	Path     string
	Format   Format
	Sections []Section
	Segments []Segment // loadable memory regions (ELF program headers / Mach-O segments); empty for PE
	Symbols  []Symbol  // sorted by Name
	Info     *Info

	// Fat (universal) Mach-O: the names of every architecture slice, the one
	// currently loaded, and per-slice details for the Info view. FatArches is
	// empty for thin binaries and non-Mach-O.
	FatArches    []string
	FatArch      string
	FatArchInfos []FatArchInfo

	debugPath string       // explicit external debug-symbols path (--debug), or ""
	reqArch   string       // requested fat-Mach-O slice (--arch), or ""
	raw       []byte       // entire file contents (mmap'd or read; raw view + section data)
	unmap     func() error // releases the mapping backing raw (nil-safe via Close)
	arch      arch.Arch
	entry     uint64
	addrWidth int // hex digits in a printed address (8 or 16)
	header    []string
	rawHeader []HeaderField // raw container-header fields (Header sub-view)

	relocs        []Reloc        // relocation entries (built lazily)
	relocBuild    func() []Reloc // builds relocs on first Relocations() call
	relocOnce     sync.Once      // guards the lazy relocation build
	relocsByAddr  []Reloc        // relocs sorted by Offset, for address lookup (lazy)
	relocSortOnce sync.Once      // guards the sorted-reloc build

	symByAddr      []Symbol // sorted by Addr
	lowerName      []string // lazily-built lowercased Symbols[i].Name (for filtering)
	lowerDemangled []string // lazily-built lowercased Symbols[i].Demangled

	dwarf        *dwarf.Data
	dwarfAvail   bool               // DWARF is present (cheap check); HasDWARF without parsing
	dwarfBuild   func() *dwarf.Data // builds dwarf lazily on first line/source lookup
	compilerOnce sync.Once          // guards the lazy compiler-banner scan (Mach-O)
	dwarfOnce    sync.Once          // guards the lazy DWARF decode
	lines        []lineEntry        // sorted by Addr (loaded lazily from dwarf)
	lineFiles    []string           // file-name table; lineEntry.File indexes into this
	linesOnce    sync.Once          // guards the lazy line-table decode
	indexOnce    sync.Once          // builds line lookup indexes from lines
	lineCols     map[lineKey][]int  // distinct DWARF columns by source file:line
	lineMap      map[string]map[int]bool
	lineAddr     map[lineKey]uint64  // lowest mapped address per source file:line
	fileLines    map[string][]int    // sorted distinct mapped line numbers per file
	sources      map[string][]string // resolved file -> lines
	sourceExists map[string]bool     // resolved file -> exists on disk (cheap presence)

	vaImage   *Image        // all mapped sections, in VA order (lazy)
	execImage *Image        // executable sections only, in VA order (lazy)
	allImage  *Image        // every section with file content (disasm-all), lazy
	disasmAll bool          // ExecImage returns allImage (disassemble all sections)
	synthetic bool          // section/symbol addresses are a synthetic layout (relocatable object)
	relocatable bool        // a relocatable object (ELF ET_REL / Mach-O MH_OBJECT)
	strings   []StringEntry // printable strings, extracted lazily
}

// lineEntry maps a code address to a source location. File is an index into
// File.lineFiles rather than a string, and Line/Col are int32 — this keeps each
// entry at 24 bytes instead of 40, which matters because rich debug binaries
// produce millions of them.
type lineEntry struct {
	Addr uint64
	File int32
	Line int32
	Col  int32
}

type lineKey struct {
	File string
	Line int
}

// finalizeSymbols sorts symbols and builds the address index. Demangling is
// intentionally NOT done here — it's the slowest part of loading a big symbol
// table, so callers run it separately (ComputeDemangled/ApplyDemangled) off the
// critical path; until then Display() falls back to the raw name.
func (f *File) finalizeSymbols() {
	// Parallel chunk-sort + k-way merge; falls back to a plain sort for small
	// tables. One of the larger Open costs on big symbol tables.
	sortSymbolsByName(f.Symbols)

	addrIdx := make([]int, 0, len(f.Symbols))
	for i, s := range f.Symbols {
		if s.Addr != 0 {
			addrIdx = append(addrIdx, i)
		}
	}
	sortAddrIdx := func() {
		slices.SortFunc(addrIdx, func(i, j int) int {
			si, sj := f.Symbols[i], f.Symbols[j]
			switch {
			case si.Addr != sj.Addr:
				return cmp.Compare(si.Addr, sj.Addr) // ascending by address
			case si.Size != sj.Size:
				return cmp.Compare(sj.Size, si.Size) // larger size first
			default:
				return 0
			}
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
	n := max(runtime.NumCPU(), 1)
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
	// Demangled names just changed; drop the lowercased filter index so it is
	// rebuilt (with the demangled forms) on the next filter.
	f.lowerName, f.lowerDemangled = nil, nil
}

// LowerNames returns per-symbol lowercased Name and Demangled slices, indexed
// like f.Symbols (an entry is "" when the symbol has no demangled form). It is
// built once and reused so case-insensitive filtering doesn't re-lowercase the
// whole table on every keystroke. Call on the File's owning goroutine;
// ApplyDemangled invalidates the cache.
func (f *File) LowerNames() (names, demangled []string) {
	if f.lowerName == nil {
		f.lowerName = make([]string, len(f.Symbols))
		f.lowerDemangled = make([]string, len(f.Symbols))
		for i := range f.Symbols {
			f.lowerName[i] = strings.ToLower(f.Symbols[i].Name)
			if f.Symbols[i].Demangled != "" {
				f.lowerDemangled[i] = strings.ToLower(f.Symbols[i].Demangled)
			}
		}
	}
	return f.lowerName, f.lowerDemangled
}

// lineEntries returns the address→source line table, decoding it from DWARF on
// first use. Decoding is deferred out of Open because it's only needed once the
// user looks at source mapping (the Sources view / source pane), and it is a
// large slice of the startup cost for binaries with rich debug info.
func (f *File) lineEntries() []lineEntry {
	f.linesOnce.Do(func() {
		f.ensureDWARF()
		if f.dwarf != nil {
			f.lines, f.lineFiles = loadLines(f.dwarf)
		}
	})
	return f.lines
}

// ensureDWARF builds the DWARF data on first use (the parse is deferred out of
// Open — it's a large part of startup for debug binaries and only the source
// pane / line mapping needs it). A no-op for formats that parsed DWARF eagerly.
func (f *File) ensureDWARF() {
	f.dwarfOnce.Do(func() {
		if f.dwarf == nil && f.dwarfBuild != nil {
			f.dwarf = f.dwarfBuild()
		}
	})
}

// WarmDebugInfo eagerly performs the normally-lazy DWARF *parse* (dwarf.Data) so
// the source pane / Sources view start from a warm decode. It deliberately does
// NOT build the address→line table and lookup maps: those are large (hundreds of
// MB and millions of entries on a rich debug binary) and would be wasted heap if
// the user never opens source — they stay lazy until first source access. Safe
// from a background goroutine (Once-guarded); a no-op without debug info.
func (f *File) WarmDebugInfo() {
	if !f.HasDWARF() {
		return
	}
	f.ensureDWARF()
}

// ensureLineIndexes builds source-line lookup maps from the lazy DWARF line table.
func (f *File) ensureLineIndexes() {
	f.indexOnce.Do(func() {
		colsSeen := map[lineKey]map[int]bool{}
		lineMap := map[string]map[int]bool{}
		lineAddr := map[lineKey]uint64{}
		for _, le := range f.lineEntries() {
			file := f.lineFileName(le.File)
			if file == "" || le.Line == 0 {
				continue
			}
			line := int(le.Line)
			if lineMap[file] == nil {
				lineMap[file] = map[int]bool{}
			}
			lineMap[file][line] = true
			key := lineKey{File: file, Line: line}
			if a, ok := lineAddr[key]; !ok || le.Addr < a {
				lineAddr[key] = le.Addr
			}
			if le.Col > 0 {
				if colsSeen[key] == nil {
					colsSeen[key] = map[int]bool{}
				}
				colsSeen[key][int(le.Col)] = true
			}
		}
		lineCols := make(map[lineKey][]int, len(colsSeen))
		for key, seen := range colsSeen {
			cols := make([]int, 0, len(seen))
			for col := range seen {
				cols = append(cols, col)
			}
			sort.Ints(cols)
			lineCols[key] = cols
		}
		fileLines := make(map[string][]int, len(lineMap))
		for file, lines := range lineMap {
			ls := make([]int, 0, len(lines))
			for ln := range lines {
				ls = append(ls, ln)
			}
			sort.Ints(ls)
			fileLines[file] = ls
		}
		f.lineMap = lineMap
		f.lineCols = lineCols
		f.lineAddr = lineAddr
		f.fileLines = fileLines
	})
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

// lineFileName resolves a lineEntry.File index to its source file name.
func (f *File) lineFileName(i int32) string {
	if i < 0 || int(i) >= len(f.lineFiles) {
		return ""
	}
	return f.lineFiles[i]
}

// loadLines extracts and sorts DWARF line-table entries, returning the entries
// and the interned file-name table they index into.
func loadLines(d *dwarf.Data) ([]lineEntry, []string) {
	var out []lineEntry
	var files []string
	fileIdx := map[string]int32{}
	intern := func(name string) int32 {
		if i, ok := fileIdx[name]; ok {
			return i
		}
		i := int32(len(files))
		files = append(files, name)
		fileIdx[name] = i
		return i
	}
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
			r.SkipChildren()
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
			out = append(out, lineEntry{Addr: le.Address, File: intern(le.File.Name), Line: int32(le.Line), Col: int32(le.Column)})
		}
		r.SkipChildren()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr < out[j].Addr })
	return out, files
}

// SourceFiles returns the sorted, de-duplicated set of source files referenced
// by the DWARF line table.
func (f *File) SourceFiles() []string {
	f.lineEntries() // populates f.lineFiles (already de-duplicated by interning)
	out := make([]string, len(f.lineFiles))
	copy(out, f.lineFiles)
	sort.Strings(out)
	return out
}

// LineToAddr returns an address that maps to file:line — the lowest address at
// the exact line when possible, otherwise the lowest address of the nearest
// mapped line at or after it in the same file.
func (f *File) LineToAddr(file string, line int) (uint64, bool) {
	f.ensureLineIndexes()
	if a, ok := f.lineAddr[lineKey{File: file, Line: line}]; ok {
		return a, true
	}
	lines := f.fileLines[file]
	i := sort.Search(len(lines), func(i int) bool { return lines[i] >= line })
	if i >= len(lines) {
		return 0, false
	}
	a, ok := f.lineAddr[lineKey{File: file, Line: lines[i]}]
	return a, ok
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
	return f.lineFileName(le.File), int(le.Line), int(le.Col)
}

// MappedLines returns the set of line numbers in file that have any machine
// code mapped to them.
func (f *File) MappedLines(file string) map[int]bool {
	f.ensureLineIndexes()
	lines := f.lineMap[file]
	if len(lines) == 0 {
		return map[int]bool{}
	}
	out := make(map[int]bool, len(lines))
	for line := range lines {
		out[line] = true
	}
	return out
}

// LineColumns returns the distinct, sorted DWARF columns (>0) recorded for
// file:line — the positions within the line that code maps to.
func (f *File) LineColumns(file string, line int) []int {
	f.ensureLineIndexes()
	return f.lineCols[lineKey{File: file, Line: line}]
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

// SymbolsInRange returns address-indexed symbols that overlap [from, to).
func (f *File) SymbolsInRange(from uint64, to uint64) []Symbol {
	if len(f.symByAddr) == 0 || to <= from {
		return []Symbol{}
	}
	i := sort.Search(len(f.symByAddr), func(i int) bool { return f.symByAddr[i].Addr >= from })
	if i > 0 {
		prev := f.symByAddr[i-1]
		prevEnd := prev.Addr + prev.Size
		if prev.Size > 0 && (prevEnd < prev.Addr || prevEnd > from) {
			i--
		}
	}
	res := []Symbol{}
	for ; i < len(f.symByAddr); i++ {
		s := f.symByAddr[i]
		if s.Addr >= to {
			break
		}
		if s.Size == 0 {
			if s.Addr >= from {
				res = append(res, s)
			}
			continue
		}
		end := s.Addr + s.Size
		if end < s.Addr {
			end = ^uint64(0)
		}
		if s.Addr < to && end > from {
			res = append(res, s)
		}
	}
	return res
}

// NextSymbol returns the first symbol (by address) strictly after addr that
// satisfies pred (a nil pred accepts any symbol). symByAddr is sorted by Addr,
// so it binary-searches to the first candidate and scans only from there.
func (f *File) NextSymbol(addr uint64, pred func(Symbol) bool) (Symbol, bool) {
	i := sort.Search(len(f.symByAddr), func(i int) bool { return f.symByAddr[i].Addr > addr })
	for ; i < len(f.symByAddr); i++ {
		if s := f.symByAddr[i]; pred == nil || pred(s) {
			return s, true
		}
	}
	return Symbol{}, false
}

// PrevSymbol returns the last symbol (by address) strictly before addr that
// satisfies pred (a nil pred accepts any symbol). symByAddr is sorted by Addr,
// so it binary-searches to the last candidate and scans only from there.
func (f *File) PrevSymbol(addr uint64, pred func(Symbol) bool) (Symbol, bool) {
	i := sort.Search(len(f.symByAddr), func(i int) bool { return f.symByAddr[i].Addr >= addr })
	for i--; i >= 0; i-- {
		if s := f.symByAddr[i]; pred == nil || pred(s) {
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
// SourceExists reports whether the source file name resolves to a readable file
// on disk, using the same candidate resolution as SourceLines but only stat-ing
// (cheap) rather than reading. Result is cached.
func (f *File) SourceExists(name string) bool {
	if name == "" {
		return false
	}
	if f.sourceExists == nil {
		f.sourceExists = map[string]bool{}
	}
	if v, ok := f.sourceExists[name]; ok {
		return v
	}
	ok := false
	for _, c := range f.sourceCandidates(name) {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			ok = true
			break
		}
	}
	f.sourceExists[name] = ok
	return ok
}

// sourceCandidates lists the on-disk paths tried for a DWARF source name, in
// order, shared by SourceLines and SourceExists.
func (f *File) sourceCandidates(name string) []string {
	candidates := []string{name}
	if !filepath.IsAbs(name) {
		candidates = append(candidates, filepath.Join(filepath.Dir(f.Path), name))
	}
	return append(candidates, filepath.Base(name))
}

func (f *File) SourceLines(name string) []string {
	if name == "" {
		return nil
	}
	if f.sources == nil {
		f.sources = map[string][]string{}
	}
	if v, ok := f.sources[name]; ok {
		return v
	}
	for _, c := range f.sourceCandidates(name) {
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
func (f *File) HasDWARF() bool { return f.dwarfAvail || f.dwarf != nil }

// Entry returns the entry-point virtual address.
func (f *File) Entry() uint64 { return f.entry }

// Arch returns the CPU architecture for this binary.
func (f *File) Arch() arch.Arch { return f.arch }

// Raw returns the entire file contents (source for the raw hex view).
func (f *File) Raw() []byte { return f.raw }

// DebugPath returns the explicit external debug-symbols path (--debug), or "".
func (f *File) DebugPath() string { return f.debugPath }

// RequestedArch returns the fat-Mach-O slice requested via --arch, or "" when
// none was given (the host/first slice was auto-selected).
func (f *File) RequestedArch() string { return f.reqArch }

// AddrHexWidth is the number of hex digits an address should be printed with.
func (f *File) AddrHexWidth() int {
	if f.addrWidth == 0 {
		return 16
	}
	return f.addrWidth
}

// HeaderInfo returns the container header as a list of "Label: value" lines.
func (f *File) HeaderInfo() []string { return f.header }
