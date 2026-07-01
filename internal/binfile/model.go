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

	debugPath  string       // explicit external debug-symbols path (--debug), or ""
	reqArch    string       // requested fat-Mach-O slice (--arch), or ""
	raw        []byte       // entire file contents (mmap'd or read; raw view + section data)
	unmap      func() error // releases the mapping backing raw (nil-safe via Close)
	layoutOnly bool         // only architecture/sections/segments/raw were loaded
	arch       arch.Arch
	entry      uint64
	addrWidth  int // hex digits in a printed address (8 or 16), set from the bitness
	// compactAddr narrows AddrHexWidth to 8 digits for a 64-bit binary whose every
	// address fits in 32 bits (set from the "compact addresses" preference). It only
	// affects the *printed* width — PointerBytes keeps the true word size. dispWidth
	// caches the resulting hex-digit count so AddrHexWidth (called per row, per
	// frame, and in hit-testing) stays a plain field read; SetCompactAddr refreshes
	// it, and the expensive MaxAddr scan happens there at most once, only when
	// compaction is actually requested.
	compactAddr bool
	dispWidth   int       // cached AddrHexWidth result (0 until SetCompactAddr/load)
	maxAddr     uint64    // highest meaningful address (lazy; for compactAddr)
	maxAddrOnce sync.Once // guards the maxAddr scan
	header      []string
	rawHeader   []HeaderField // raw container-header fields (Header sub-view)

	relocs        []Reloc        // relocation entries (built lazily)
	relocBuild    func() []Reloc // builds relocs on first Relocations() call
	relocOnce     sync.Once      // guards the lazy relocation build
	relocAvail    bool           // cheap load-time indication that relocations exist
	relocAvailSet bool           // relocAvail was populated by the format loader
	relocsByAddr  []Reloc        // relocs sorted by Offset, for address lookup (lazy)
	relocSortOnce sync.Once      // guards the sorted-reloc build

	symByAddr      []int    // indices into Symbols, sorted by Addr
	symMaxEnd      []uint64 // prefix maximum symbol end by symByAddr position
	lowerName      []string // lazily-built lowercased Symbols[i].Name (for filtering)
	lowerDemangled []string // lazily-built lowercased Symbols[i].Demangled

	dwarf        *dwarf.Data
	dwarfAvail   bool               // DWARF is present (cheap check); HasDWARF without parsing
	dwarfBuild   func() *dwarf.Data // builds dwarf lazily on first line/source lookup
	compilerOnce sync.Once          // guards the lazy compiler-banner scan (Mach-O)
	dwarfOnce    sync.Once          // guards the lazy DWARF decode
	lines        []lineEntry        // sorted by Addr (loaded lazily from dwarf)
	lineFiles    []string           // file-name table; lineEntry.File indexes into this
	sourceFiles  []string           // sorted DWARF source filenames, without line rows
	linesOnce    sync.Once          // guards the lazy line-table decode
	indexOnce    sync.Once          // builds line lookup indexes from lines
	lineCols     map[lineKey][]int  // distinct DWARF columns by source file:line
	lineMap      map[string]map[int]bool
	lineAddr     map[lineKey]uint64  // lowest mapped address per source file:line
	fileLines    map[string][]int    // sorted distinct mapped line numbers per file
	sources      map[string][]string // resolved file -> lines
	sourceExists map[string]bool     // resolved file -> exists on disk (cheap presence)

	vaImage     *Image        // all mapped sections, in VA order (lazy)
	execImage   *Image        // executable sections only, in VA order (lazy)
	allImage    *Image        // every section with file content (disasm-all), lazy
	disasmAll   bool          // ExecImage returns allImage (disassemble all sections)
	synthetic   bool          // section/symbol addresses are a synthetic layout (relocatable object)
	relocatable bool          // a relocatable object (ELF ET_REL / Mach-O MH_OBJECT)
	strings     []StringEntry // printable strings, extracted lazily
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
	// One of the larger Open costs on big symbol tables.
	sortSymbolsByName(f.Symbols)

	addrIdx := make([]int, 0, len(f.Symbols))
	for i, s := range f.Symbols {
		if s.Addr != 0 || (f.synthetic && s.Section != "") {
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

	f.symByAddr = addrIdx
	f.buildSymbolMaxEnds()
}

func (f *File) buildSymbolMaxEnds() {
	f.symMaxEnd = make([]uint64, len(f.symByAddr))
	var maxEnd uint64
	for i, idx := range f.symByAddr {
		end := symbolLookupEnd(f.Symbols[idx])
		if end > maxEnd {
			maxEnd = end
		}
		f.symMaxEnd[i] = maxEnd
	}
}

func symbolLookupEnd(s Symbol) uint64 {
	if s.Size == 0 {
		return s.Addr
	}
	end := s.Addr + s.Size
	if end < s.Addr {
		return ^uint64(0)
	}
	return end
}

// inferSymbolSizes gives zero-sized symbols an extent reaching to the next
// symbol at a higher address (clamped to the containing section's end). Symbols
// that already carry a size are left untouched.
func (f *File) inferSymbolSizes(addrIdx []int) {
	explicitSize := make([]bool, len(f.Symbols))
	for i := range f.Symbols {
		explicitSize[i] = f.Symbols[i].Size != 0
	}

	var secs []*Section
	for i := range f.Sections {
		if f.Sections[i].Alloc && f.Sections[i].Size != 0 {
			secs = append(secs, &f.Sections[i])
		}
	}
	sort.Slice(secs, func(i, j int) bool { return secs[i].Addr < secs[j].Addr })
	sectionEnd := func(addr uint64) uint64 {
		i := sort.Search(len(secs), func(i int) bool { return secs[i].Addr > addr })
		if i == 0 {
			return 0
		}
		s := secs[i-1]
		if addr >= s.Addr && addr < s.Addr+s.Size {
			return s.Addr + s.Size
		}
		return 0
	}

	var groupAddr, nextAddr uint64
	haveGroup := false
	for i := len(addrIdx) - 1; i >= 0; i-- {
		idx := addrIdx[i]
		addr := f.Symbols[idx].Addr
		if !haveGroup {
			groupAddr = addr
			haveGroup = true
		} else if addr != groupAddr {
			nextAddr = groupAddr
			groupAddr = addr
		}
		if f.Symbols[idx].Size != 0 {
			continue
		}
		// If another symbol at this exact address already carries an extent, keep
		// this alias exact-only instead of inferring a competing, often larger range.
		if hasExplicitSameAddr(f.Symbols, explicitSize, addrIdx, i) {
			continue
		}
		next := nextAddr
		if end := sectionEnd(addr); end != 0 {
			if next == 0 || next > end {
				next = end
			}
		}
		if next > addr {
			f.Symbols[idx].Size = next - addr
		}
	}
}

func hasExplicitSameAddr(symbols []Symbol, explicitSize []bool, addrIdx []int, pos int) bool {
	addr := symbols[addrIdx[pos]].Addr
	for i := pos - 1; i >= 0 && symbols[addrIdx[i]].Addr == addr; i-- {
		if explicitSize[addrIdx[i]] {
			return true
		}
	}
	for i := pos + 1; i < len(addrIdx) && symbols[addrIdx[i]].Addr == addr; i++ {
		if explicitSize[addrIdx[i]] {
			return true
		}
	}
	return false
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

// ApplyDemangled stores the result of ComputeDemangled onto the symbols. Run it
// on the File's owning goroutine.
func (f *File) ApplyDemangled(d []string) {
	if len(d) != len(f.Symbols) {
		return
	}
	for i := range f.Symbols {
		f.Symbols[i].Demangled = d[i]
	}
	// Demangled names just changed; drop the lowercased filter index so it is
	// rebuilt (with the demangled forms) on the next filter.
	f.lowerName, f.lowerDemangled = nil, nil
}

// ClearDemangled drops every symbol's demangled form in place, so Display falls
// back to the raw mangled name. It avoids ApplyDemangled's allocations (no names
// slice, no name→demangled map), which matters when toggling demangling off on a
// binary with hundreds of thousands of symbols.
func (f *File) ClearDemangled() {
	for i := range f.Symbols {
		f.Symbols[i].Demangled = ""
	}
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
		f.dwarfBuild = nil
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

func sourceFilesOnly(d *dwarf.Data) []string {
	seen := map[string]bool{}
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
		addFiles := func() {
			for _, file := range lr.Files() {
				if file != nil && file.Name != "" {
					seen[file.Name] = true
				}
			}
		}
		addFiles()
		var le dwarf.LineEntry
		for {
			if err := lr.Next(&le); err != nil {
				break
			}
			if le.File != nil && le.File.Name != "" {
				seen[le.File.Name] = true
			}
		}
		addFiles()
		r.SkipChildren()
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// SourceFiles returns the sorted, de-duplicated set of source files referenced
// by the DWARF line table. It reads only the per-CU file tables and does not
// build the full address-sorted line-entry table used by source lookup.
func (f *File) SourceFiles() []string {
	if f.sourceFiles == nil {
		f.ensureDWARF()
		if f.sourceFiles == nil && f.dwarf != nil {
			f.sourceFiles = sourceFilesOnly(f.dwarf)
		} else if f.sourceFiles == nil && len(f.lineFiles) > 0 {
			f.sourceFiles = append([]string(nil), f.lineFiles...)
			sort.Strings(f.sourceFiles)
		} else if f.sourceFiles == nil {
			f.sourceFiles = []string{}
		}
	}
	out := make([]string, len(f.sourceFiles))
	copy(out, f.sourceFiles)
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
	i := sort.Search(len(f.symByAddr), func(i int) bool { return f.Symbols[f.symByAddr[i]].Addr > addr })
	for i > 0 {
		groupEnd := i
		groupAddr := f.Symbols[f.symByAddr[groupEnd-1]].Addr
		if groupAddr != addr && len(f.symMaxEnd) == len(f.symByAddr) && f.symMaxEnd[groupEnd-1] <= addr {
			break
		}
		groupStart := groupEnd - 1
		for groupStart > 0 && f.Symbols[f.symByAddr[groupStart-1]].Addr == groupAddr {
			groupStart--
		}
		for j := groupStart; j < groupEnd; j++ {
			s := f.Symbols[f.symByAddr[j]]
			if symbolCoversAddr(s, addr) {
				return s, true
			}
		}
		i = groupStart
	}
	return Symbol{}, false
}

func symbolCoversAddr(s Symbol, addr uint64) bool {
	if s.Size == 0 {
		return s.Addr == addr
	}
	end := s.Addr + s.Size
	if end < s.Addr {
		return addr >= s.Addr
	}
	return addr >= s.Addr && addr < end
}

// SymbolsInRange returns address-indexed symbols that overlap [from, to).
func (f *File) SymbolsInRange(from uint64, to uint64) []Symbol {
	if len(f.symByAddr) == 0 || to <= from {
		return []Symbol{}
	}
	res := []Symbol{}
	i := f.symbolRangeStart(from)
	for ; i < len(f.symByAddr); i++ {
		s := f.Symbols[f.symByAddr[i]]
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

// SymbolRangeIter walks address-indexed symbols that overlap a half-open address
// range without allocating a result slice.
type SymbolRangeIter struct {
	f  *File
	i  int
	to uint64
}

func (f *File) SymbolRangeIter(from uint64, to uint64) SymbolRangeIter {
	if len(f.symByAddr) == 0 || to <= from {
		return SymbolRangeIter{}
	}
	return SymbolRangeIter{f: f, i: f.symbolRangeStart(from), to: to}
}

func (it *SymbolRangeIter) Next() (Symbol, bool) {
	if it.f == nil {
		return Symbol{}, false
	}
	for ; it.i < len(it.f.symByAddr); it.i++ {
		s := it.f.Symbols[it.f.symByAddr[it.i]]
		if s.Addr >= it.to {
			return Symbol{}, false
		}
		if s.Size == 0 {
			it.i++
			return s, true
		}
		it.i++
		return s, true
	}
	return Symbol{}, false
}

func (f *File) symbolRangeStart(from uint64) int {
	i := sort.Search(len(f.symByAddr), func(i int) bool { return f.Symbols[f.symByAddr[i]].Addr >= from })
	if i > 0 {
		prev := f.Symbols[f.symByAddr[i-1]]
		prevEnd := prev.Addr + prev.Size
		if prev.Size > 0 && (prevEnd < prev.Addr || prevEnd > from) {
			i--
		}
	}
	return i
}

// NextSymbol returns the first symbol (by address) strictly after addr that
// satisfies pred (a nil pred accepts any symbol). symByAddr is sorted by Addr,
// so it binary-searches to the first candidate and scans only from there.
func (f *File) NextSymbol(addr uint64, pred func(Symbol) bool) (Symbol, bool) {
	i := sort.Search(len(f.symByAddr), func(i int) bool { return f.Symbols[f.symByAddr[i]].Addr > addr })
	for ; i < len(f.symByAddr); i++ {
		if s := f.Symbols[f.symByAddr[i]]; pred == nil || pred(s) {
			return s, true
		}
	}
	return Symbol{}, false
}

// PrevSymbol returns the last symbol (by address) strictly before addr that
// satisfies pred (a nil pred accepts any symbol). symByAddr is sorted by Addr,
// so it binary-searches to the last candidate and scans only from there.
func (f *File) PrevSymbol(addr uint64, pred func(Symbol) bool) (Symbol, bool) {
	i := sort.Search(len(f.symByAddr), func(i int) bool { return f.Symbols[f.symByAddr[i]].Addr >= addr })
	for i--; i >= 0; i-- {
		if s := f.Symbols[f.symByAddr[i]]; pred == nil || pred(s) {
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
// With the compact-addresses preference set, a 64-bit binary whose addresses all
// fit in 32 bits prints 8 digits instead of 16; the true word size is unaffected
// (see PointerBytes). It's a plain read of the cached width — the work happens in
// SetCompactAddr, not on this hot path.
func (f *File) AddrHexWidth() int {
	if f.dispWidth != 0 {
		return f.dispWidth
	}
	if f.addrWidth == 0 {
		return 16
	}
	return f.addrWidth
}

// SetCompactAddr enables or disables the narrowed 64-bit address display and
// recomputes the cached print width. It is a pure display preference; the
// disasm/hex/list views all read AddrHexWidth, so one call re-flows every address
// column consistently. The MaxAddr scan only runs when compaction is requested
// (the && short-circuits otherwise), so turning it off costs nothing.
func (f *File) SetCompactAddr(on bool) {
	f.compactAddr = on
	full := f.addrWidth
	if full == 0 {
		full = 16
	}
	if on && full == 16 && f.MaxAddr() < (1<<32) {
		full = 8
	}
	f.dispWidth = full
}

// PointerBytes is the binary's true pointer width in bytes (8 for 64-bit, 4 for
// 32-bit) — independent of the compact-addresses display preference, so word
// decoding stays correct even when addresses print narrow.
func (f *File) PointerBytes() int {
	w := f.addrWidth
	if w == 0 {
		w = 16
	}
	return w / 2
}

// MaxAddr returns the highest meaningful virtual address in the file (the end of
// the highest section/segment, the largest symbol address, and the entry point),
// scanned once. Used to decide whether compact addresses are safe.
func (f *File) MaxAddr() uint64 {
	f.maxAddrOnce.Do(func() {
		hi := f.entry
		for i := range f.Sections {
			if e := f.Sections[i].Addr + f.Sections[i].Size; e > hi {
				hi = e
			}
		}
		for i := range f.Segments {
			if e := f.Segments[i].Addr + f.Segments[i].Size; e > hi {
				hi = e
			}
		}
		for i := range f.Symbols {
			if a := f.Symbols[i].Addr; a > hi {
				hi = a
			}
		}
		f.maxAddr = hi
	})
	return f.maxAddr
}

// HeaderInfo returns the container header as a list of "Label: value" lines.
func (f *File) HeaderInfo() []string { return f.header }
