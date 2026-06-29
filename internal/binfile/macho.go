package binfile

import (
	"bytes"
	"debug/dwarf"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/rabarbra/exex/internal/arch"
)

// Mach-O magic numbers (thin, both byte orders, plus the fat headers).
const (
	machoMagic32   = 0xfeedface
	machoMagic64   = 0xfeedfacf
	machoCigam32   = 0xcefaedfe
	machoCigam64   = 0xcffaedfe
	machoFatMagic  = 0xcafebabe
	machoFatMagic2 = 0xbebafeca
)

// VM protection bits (mach/vm_prot.h).
const (
	vmProtRead    = 0x1
	vmProtWrite   = 0x2
	vmProtExecute = 0x4
)

// Mach-O load command + symbol constants we parse by hand.
const (
	lcMain             = 0x80000028
	lcLoadDylinker     = 0x0e
	lcUUID             = 0x1b
	lcCodeSignature    = 0x1d
	lcEncryptionInfo   = 0x21
	lcEncryptionInfo64 = 0x2c
	lcBuildVersion     = 0x32
	lcVersionMinMacos  = 0x24
	lcVersionMinIos    = 0x25
	lcVersionMinTvos   = 0x2f
	lcVersionMinWatch  = 0x30
	nStab              = 0xe0
	nType              = 0x0e
	nSect              = 0x0e // N_TYPE value meaning "defined in section number n_sect"
	nExt               = 0x01
	nWeakDef           = 0x0080 // n_desc bit

	// Section attribute bits (high 24 bits of a section's flags field).
	machoAttrPureInstr = 0x80000000 // S_ATTR_PURE_INSTRUCTIONS
	machoAttrSomeInstr = 0x00000400 // S_ATTR_SOME_INSTRUCTIONS
)

func isMachO(raw []byte) bool {
	if len(raw) < 4 {
		return false
	}
	switch binary.BigEndian.Uint32(raw) {
	case machoMagic32, machoMagic64, machoCigam32, machoCigam64:
		return true
	case machoFatMagic, machoFatMagic2:
		return isFatMachO(raw)
	}
	return false
}

func isFatMachO(raw []byte) bool {
	if len(raw) < 8 {
		return false
	}
	switch binary.BigEndian.Uint32(raw) {
	case machoFatMagic:
		// 0xCAFEBABE is also the Java .class magic. A fat Mach-O follows the magic
		// with nfat_arch (a small architecture count); a Java class follows it with
		// minor/major version, where major is always >= 45. So a sane, small count
		// means fat Mach-O; anything larger is a .class (or not fat at all).
		n := binary.BigEndian.Uint32(raw[4:8])
		return n >= 1 && n <= 0x14
	case machoFatMagic2:
		// Byte-swapped fat magic (FAT_CIGAM) — not a Java class.
		return true
	}
	return false
}

// machoCPUName is the conventional short name for a Mach-O CPU type (matching
// `lipo`/`file`), used to list and select fat-binary slices.
func machoCPUName(c macho.Cpu) string {
	switch c {
	case macho.CpuAmd64:
		return "x86_64"
	case macho.Cpu386:
		return "i386"
	case macho.CpuArm64:
		return "arm64"
	case macho.CpuArm:
		return "arm"
	}
	return fmt.Sprintf("cpu(0x%x)", uint32(c))
}

// machoArchName is the conventional slice name including the CPU subtype, so fat
// slices that share a CPU type stay distinct — e.g. x86_64 vs x86_64h, arm64 vs
// arm64e. Without the subtype these collapse to one name and selecting / cycling
// fat slices (sqlite3 ships x86_64 + x86_64h + arm64e) is broken.
func machoArchName(c macho.Cpu, sub uint32) string {
	sub &^= 0x80000000 // CPU_SUBTYPE_LIB64
	switch c {
	case macho.CpuAmd64:
		if sub == 8 { // CPU_SUBTYPE_X86_64_H (Haswell)
			return "x86_64h"
		}
		return "x86_64"
	case macho.CpuArm64:
		if sub == 2 { // CPU_SUBTYPE_ARM64E
			return "arm64e"
		}
		return "arm64"
	}
	return machoCPUName(c)
}

// loadMachO parses f.raw as a Mach-O object and populates the neutral model.
// For universal ("fat") binaries it selects the slice named by f.reqArch, else
// the host architecture's slice, else the first.
func (f *File) loadMachO() error {
	mf, base, arches, chosen, err := parseMachO(f.raw, f.reqArch)
	if err != nil {
		return err
	}
	if len(arches) > 1 {
		f.FatArchInfos = arches
		f.FatArches = make([]string, len(arches))
		for i, a := range arches {
			f.FatArches[i] = a.Name
		}
	}
	f.FatArch = chosen

	f.Format = FormatMachO
	f.relocatable = mf.Type == macho.TypeObj
	f.arch = machoArch(mf.Cpu)
	if mf.Magic == macho.Magic64 {
		f.addrWidth = 16
	} else {
		f.addrWidth = 8
	}

	// Index segments so per-section protection / category can be derived.
	segByName := map[string]*macho.Segment{}
	var textSeg *macho.Segment
	for _, l := range mf.Loads {
		if seg, ok := l.(*macho.Segment); ok {
			segByName[seg.Name] = seg
			if seg.Name == "__TEXT" {
				textSeg = seg
			}
			f.Segments = append(f.Segments, Segment{
				Name:     seg.Name,
				Addr:     seg.Addr,
				Size:     seg.Memsz,
				Offset:   base + seg.Offset,
				FileSize: seg.Filesz,
				R:        seg.Prot&vmProtRead != 0,
				W:        seg.Prot&vmProtWrite != 0,
				X:        seg.Prot&vmProtExecute != 0,
			})
		}
	}

	for _, s := range mf.Sections {
		seg := segByName[s.Seg]
		write := false
		if seg != nil {
			write = seg.Prot&vmProtWrite != 0
		}
		// The whole __TEXT segment maps r-x, so segment protection over-reports
		// executability (it would flag __cstring, __const, …). Treat only
		// sections carrying instruction attributes as code, so disasm and the
		// executable image stay limited to real code.
		exec := s.Flags&(machoAttrPureInstr|machoAttrSomeInstr) != 0
		zerofill := isZerofill(s.Flags)
		fileSize := uint64(s.Size)
		if zerofill {
			fileSize = 0
		}
		sec := Section{
			Name:     s.Name,
			Addr:     s.Addr,
			Size:     s.Size,
			Offset:   base + uint64(s.Offset),
			FileSize: fileSize,
			TypeName: s.Seg,
			Category: machoCategory(s, seg, exec, write, zerofill),
			Alloc:    s.Addr != 0,
			Exec:     exec,
			Write:    write,
		}
		sec.Flags = neutralFlags(sec.Alloc, write, exec)
		f.Sections = append(f.Sections, sec)
	}

	if mf.Symtab != nil {
		for _, s := range mf.Symtab.Syms {
			if s.Type&nStab != 0 {
				continue // debug stab, not a real symbol
			}
			defined := s.Type&nType == nSect && s.Sect > 0
			secName := ""
			kind := SymOther
			if defined {
				if int(s.Sect) <= len(f.Sections) {
					sec := &f.Sections[s.Sect-1]
					secName = sec.Name
					if sec.Exec {
						kind = SymFunc
					} else {
						kind = SymObject
					}
				}
			}
			addr := s.Value
			if !defined {
				addr = 0
			}
			f.Symbols = append(f.Symbols, Symbol{
				Name:    s.Name,
				Addr:    addr,
				Kind:    kind,
				Bind:    machoBind(s),
				Section: secName,
			})
		}
	}

	var libs []string
	if l, err := mf.ImportedLibraries(); err == nil {
		libs = l
	}
	f.Symbols = append(f.Symbols, machoImportSymbols(mf, f.raw, base, libs)...)

	f.entry = machoEntry(mf, textSeg, base)
	f.loadMachOInfo(mf) // reads mf.Symtab (Stripped), so before it is dropped below
	f.dwarfAvail = f.machoHasDWARF(mf)
	f.header = f.machoHeaderInfo(mf)
	f.rawHeader = f.machoRawHeader(mf)
	f.relocs = machoRelocs(mf, base) // eager: needs mf.Symtab, dropped below

	// Defer the DWARF decode (abbrev/section parse — a big slice of Open for debug
	// binaries) to the first source/line lookup. mf is retained for that, but its
	// parsed symbol table — the bulk of it — is dropped first, since we've copied
	// what we need into f.Symbols.
	mf.Symtab = nil
	f.dwarfBuild = func() *dwarf.Data { return f.machoDWARF(mf) }
	return nil
}

// machoHasDWARF reports whether DWARF is available without parsing it: an
// embedded __DWARF segment, an explicit --debug path, or a companion .dSYM.
func (f *File) machoHasDWARF(mf *macho.File) bool {
	if mf.Segment("__DWARF") != nil || f.debugPath != "" {
		return true
	}
	if _, err := os.Stat(f.Path + ".dSYM/Contents/Resources/DWARF/" + filepath.Base(f.Path)); err == nil {
		return true
	}
	if entries, err := os.ReadDir(filepath.Dir(f.Path)); err == nil {
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".dSYM") {
				return true
			}
		}
	}
	return false
}

// parseMachO opens raw as a thin or fat Mach-O. It returns the chosen slice's
// *macho.File, the file offset that slice starts at (0 for thin files), a summary
// of every architecture (nil for thin), and the chosen slice's name. want selects
// a fat slice by name (e.g. "x86_64"); "" picks the host arch, else the first.
func parseMachO(raw []byte, want string) (mf *macho.File, base uint64, arches []FatArchInfo, chosen string, err error) {
	ra := bytes.NewReader(raw)
	if isFatMachO(raw) {
		ff, ferr := macho.NewFatFile(ra)
		if ferr != nil {
			return nil, 0, nil, "", ferr
		}
		if len(ff.Arches) == 0 {
			return nil, 0, nil, "", fmt.Errorf("fat Mach-O has no architectures")
		}
		for _, fa := range ff.Arches {
			bits := 32
			if fa.File != nil && fa.File.Magic == macho.Magic64 {
				bits = 64
			}
			typ := ""
			if fa.File != nil {
				typ = fa.File.Type.String()
			}
			arches = append(arches, FatArchInfo{
				Name:   machoArchName(fa.Cpu, fa.SubCpu),
				Type:   typ,
				Bits:   bits,
				Offset: uint64(fa.Offset),
				Size:   uint64(fa.Size),
			})
		}
		fa := pickFatArch(ff, want)
		return fa.File, uint64(fa.Offset), arches, machoArchName(fa.Cpu, fa.SubCpu), nil
	}
	mf, err = macho.NewFile(ra)
	if err != nil {
		return nil, 0, nil, "", err
	}
	return mf, 0, nil, machoArchName(mf.Cpu, mf.SubCpu), nil
}

// machoDWARF returns DWARF for the binary: embedded if present, otherwise from
// a companion .dSYM bundle next to the file. On macOS the linker leaves debug
// info in a separate <binary>.dSYM rather than the executable, so without this
// the source pane would almost never have anything to show.
func (f *File) machoDWARF(mf *macho.File) *dwarf.Data {
	if d, err := mf.DWARF(); err == nil {
		return d
	}
	base := filepath.Base(f.Path)
	dir := filepath.Dir(f.Path)

	// An explicit --debug path wins: it may be a DWARF/Mach-O file directly, a
	// .dSYM bundle, or a directory to search for one.
	var cands []string
	cands = append(cands, f.dsymDebugCandidates(base)...)
	// Then the conventional <binary>.dSYM, then any sibling *.dSYM bundle (Xcode
	// names it after the .app, e.g. Ghostty.app.dSYM, next to the executable).
	cands = append(cands, f.Path+".dSYM/Contents/Resources/DWARF/"+base)
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".dSYM") {
				cands = append(cands, filepath.Join(dir, e.Name(), "Contents/Resources/DWARF", base))
			}
		}
	}
	for _, cand := range cands {
		raw, err := os.ReadFile(cand)
		if err != nil {
			continue
		}
		dm, _, _, _, err := parseMachO(raw, f.FatArch)
		if err != nil {
			continue
		}
		if d, err := dm.DWARF(); err == nil {
			return d
		}
	}
	return nil
}

// dsymDebugCandidates expands an explicit --debug path into candidate Mach-O
// DWARF files: the path itself, the DWARF binary inside a .dSYM bundle, or a
// search of a plain directory for one.
func (f *File) dsymDebugCandidates(base string) []string {
	if f.debugPath == "" {
		return nil
	}
	dsymDWARF := func(bundle string) []string {
		dir := filepath.Join(bundle, "Contents/Resources/DWARF")
		entries, err := os.ReadDir(dir)
		if err != nil {
			// Fall back to the binary's own name inside the bundle.
			return []string{filepath.Join(dir, base)}
		}
		var out []string
		for _, e := range entries {
			if !e.IsDir() {
				out = append(out, filepath.Join(dir, e.Name()))
			}
		}
		return out
	}

	st, err := os.Stat(f.debugPath)
	switch {
	case err != nil:
		return nil
	case strings.HasSuffix(f.debugPath, ".dSYM") && st.IsDir():
		return dsymDWARF(f.debugPath)
	case st.IsDir():
		// A plain directory: try any .dSYM bundle inside, else treat its files as
		// candidate DWARF Mach-O files.
		var out []string
		if entries, err := os.ReadDir(f.debugPath); err == nil {
			for _, e := range entries {
				if strings.HasSuffix(e.Name(), ".dSYM") {
					out = append(out, dsymDWARF(filepath.Join(f.debugPath, e.Name()))...)
				}
			}
		}
		out = append(out, filepath.Join(f.debugPath, base))
		return out
	default:
		return []string{f.debugPath}
	}
}

func pickFatArch(ff *macho.FatFile, want string) macho.FatArch {
	if want != "" {
		for _, fa := range ff.Arches {
			if machoArchName(fa.Cpu, fa.SubCpu) == want {
				return fa
			}
		}
	}
	host := hostCPU()
	for _, fa := range ff.Arches {
		if fa.Cpu == host {
			return fa
		}
	}
	return ff.Arches[0]
}

func hostCPU() macho.Cpu {
	switch runtime.GOARCH {
	case "amd64":
		return macho.CpuAmd64
	case "386":
		return macho.Cpu386
	case "arm64":
		return macho.CpuArm64
	}
	return 0
}

func machoArch(c macho.Cpu) arch.Arch {
	switch c {
	case macho.CpuAmd64:
		return arch.ArchAMD64
	case macho.Cpu386:
		return arch.ArchX86
	case macho.CpuArm64:
		return arch.ArchARM64
	}
	return arch.ArchUnknown
}

func machoBind(s macho.Symbol) SymBind {
	if s.Desc&nWeakDef != 0 {
		return BindWeak
	}
	if s.Type&nExt != 0 {
		return BindGlobal
	}
	return BindLocal
}

func isZerofill(flags uint32) bool {
	switch flags & 0xff { // section type lives in the low byte
	case 0x1, 0xc, 0x11: // S_ZEROFILL, S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL
		return true
	}
	return false
}

func machoCategory(s *macho.Section, seg *macho.Segment, exec, write, zerofill bool) SectionCategory {
	if seg != nil && (seg.Name == "__DWARF" || strings.Contains(strings.ToLower(s.Name), "debug")) {
		return CatDebug
	}
	if exec {
		return CatText
	}
	if zerofill {
		return CatBSS
	}
	if write {
		return CatData
	}
	if s.Addr != 0 {
		return CatRodata
	}
	return CatOther
}

// neutralFlags renders the alloc/write/exec triple in the same A/W/X letter
// vocabulary the ELF loader uses, so the sections table looks uniform.
func neutralFlags(alloc, write, exec bool) string {
	var b strings.Builder
	if alloc {
		b.WriteByte('A')
	}
	if write {
		b.WriteByte('W')
	}
	if exec {
		b.WriteByte('X')
	}
	if b.Len() == 0 {
		return "-"
	}
	return b.String()
}

// machoEntry resolves the entry point. LC_MAIN records an offset from the start
// of __TEXT; we add the segment's virtual base to recover the address.
func machoEntry(mf *macho.File, textSeg *macho.Segment, base uint64) uint64 {
	for _, l := range mf.Loads {
		lb, ok := l.(macho.LoadBytes)
		if !ok {
			continue
		}
		raw := lb.Raw()
		if len(raw) < 16 {
			continue
		}
		if mf.ByteOrder.Uint32(raw) != lcMain {
			continue
		}
		entryoff := mf.ByteOrder.Uint64(raw[8:16])
		if textSeg != nil {
			return textSeg.Addr + entryoff
		}
		return entryoff
	}
	// Only executables have an entry point. Dylibs, bundles and object files do
	// not, so don't invent one (a start symbol or __text address) for them — that
	// would mislead the Info view. The disasm view picks its own landing target.
	if mf.Type != macho.TypeExec {
		return 0
	}
	// An LC_MAIN-less executable (e.g. old/static, LC_UNIXTHREAD): fall back to a
	// likely start symbol, then the __text section.
	for _, name := range []string{"_main", "start", "_start", "__start"} {
		for _, s := range mfSyms(mf) {
			if s.Name == name && s.Value != 0 {
				return s.Value
			}
		}
	}
	for _, s := range mf.Sections {
		if s.Name == "__text" {
			return s.Addr
		}
	}
	return 0
}

func mfSyms(mf *macho.File) []macho.Symbol {
	if mf.Symtab == nil {
		return nil
	}
	return mf.Symtab.Syms
}

func (f *File) loadMachOInfo(mf *macho.File) {
	in := &Info{}
	if libs, err := mf.ImportedLibraries(); err == nil {
		in.DynamicLibs = libs
	}
	in.BuildID = machoUUID(mf)
	in.Stripped = mf.Symtab == nil || len(mf.Symtab.Syms) == 0
	in.StaticLinked = len(in.DynamicLibs) == 0
	in.Interp = machoInterp(mf)
	in.Libc = machoLibc(in)

	// Layout.
	in.WordBits = 32
	if mf.Magic == macho.Magic64 {
		in.WordBits = 64
	}
	in.ByteOrder = "little-endian"
	if mf.ByteOrder == binary.BigEndian {
		in.ByteOrder = "big-endian"
	}
	in.Segments = len(mf.Loads)

	// Hardening from header flags.
	in.PIE = TriNo
	if mf.Flags&macho.FlagPIE != 0 {
		in.PIE = TriYes
	} else if mf.Type == macho.TypeDylib || mf.Type == macho.TypeBundle {
		// Dylibs and bundles don't set MH_PIE but are always position-independent,
		// like an ELF shared object (ET_DYN). Reporting "no" would falsely suggest
		// a fixed load address.
		in.PIE = TriYes
	}
	in.NX = TriYes
	if mf.Flags&macho.FlagAllowStackExecution != 0 {
		in.NX = TriNo
	}

	f.machoLoadInfo(mf, in)
	// The compiler banner scan pages through __cstring/__const, which is costly on
	// a cold open of a large Mach-O; defer it to f.Compiler() (first Info access).
	f.Info = in
}

// machoLoadInfo scans load commands for code signing, encryption, and the
// build/min-OS version.
func (f *File) machoLoadInfo(mf *macho.File, in *Info) {
	bo := mf.ByteOrder
	for _, l := range mf.Loads {
		lb, ok := l.(macho.LoadBytes)
		if !ok {
			continue
		}
		raw := lb.Raw()
		if len(raw) < 8 {
			continue
		}
		switch bo.Uint32(raw) {
		case lcCodeSignature:
			in.CodeSigned = true
		case lcEncryptionInfo, lcEncryptionInfo64:
			if len(raw) >= 20 && bo.Uint32(raw[16:]) != 0 {
				in.Encrypted = true
			}
		case lcBuildVersion:
			if len(raw) >= 20 {
				in.MinOS = strings.TrimSpace(machoPlatform(bo.Uint32(raw[8:])) + " " + machoVersion(bo.Uint32(raw[12:])))
				in.SDK = machoVersion(bo.Uint32(raw[16:]))
			}
		case lcVersionMinMacos, lcVersionMinIos, lcVersionMinTvos, lcVersionMinWatch:
			if in.MinOS == "" && len(raw) >= 16 {
				in.MinOS = strings.TrimSpace(machoVersionMinName(bo.Uint32(raw)) + " " + machoVersion(bo.Uint32(raw[8:])))
				in.SDK = machoVersion(bo.Uint32(raw[12:]))
			}
		}
	}
}

func machoVersion(v uint32) string {
	x, y, z := v>>16, (v>>8)&0xff, v&0xff
	if z == 0 {
		return fmt.Sprintf("%d.%d", x, y)
	}
	return fmt.Sprintf("%d.%d.%d", x, y, z)
}

func machoPlatform(p uint32) string {
	switch p {
	case 1:
		return "macOS"
	case 2:
		return "iOS"
	case 3:
		return "tvOS"
	case 4:
		return "watchOS"
	case 6:
		return "Mac Catalyst"
	}
	return ""
}

func machoVersionMinName(cmd uint32) string {
	switch cmd {
	case lcVersionMinMacos:
		return "macOS"
	case lcVersionMinIos:
		return "iOS"
	case lcVersionMinTvos:
		return "tvOS"
	case lcVersionMinWatch:
		return "watchOS"
	}
	return ""
}

// Mach-O section types (low byte of flags) and indirect-symbol sentinels.
const (
	lcSegment   = 0x1
	lcSegment64 = 0x19

	sTypeNonLazyPtr = 0x6 // S_NON_LAZY_SYMBOL_POINTERS
	sTypeLazyPtr    = 0x7 // S_LAZY_SYMBOL_POINTERS
	sTypeStubs      = 0x8 // S_SYMBOL_STUBS

	indirectSymLocal = 0x80000000
	indirectSymAbs   = 0x40000000
)

type machoSecHdr struct {
	name      string
	addr      uint64
	size      uint64
	secType   uint32
	reserved1 uint32
	reserved2 uint32
}

// machoImportSymbols synthesises symbols at the addresses of the dyld stubs and
// lazy/non-lazy symbol pointers (__stubs, __got, __la_symbol_ptr, …), named
// after the imported symbol they resolve to. This is what turns a
// "bl 0x… (__stubs)" into "bl 0x… (_malloc)" and lets the user follow imports.
func machoImportSymbols(mf *macho.File, raw []byte, base uint64, libs []string) []Symbol {
	if mf.Dysymtab == nil || mf.Symtab == nil || len(mf.Dysymtab.IndirectSyms) == 0 {
		return nil
	}
	is64 := mf.Magic == macho.Magic64
	ptrSize := uint64(4)
	if is64 {
		ptrSize = 8
	}
	indirect := mf.Dysymtab.IndirectSyms
	syms := mf.Symtab.Syms

	var out []Symbol
	for _, s := range parseMachoSectionHeaders(raw, base, is64, mf.ByteOrder) {
		var stride uint64
		kind := SymObject
		switch s.secType {
		case sTypeStubs:
			stride = uint64(s.reserved2)
			kind = SymFunc
		case sTypeLazyPtr, sTypeNonLazyPtr:
			stride = ptrSize
		default:
			continue
		}
		if stride == 0 {
			continue
		}
		for j := uint64(0); j*stride < s.size; j++ {
			idx := uint64(s.reserved1) + j
			if idx >= uint64(len(indirect)) {
				break
			}
			symIdx := indirect[idx]
			if symIdx&(indirectSymLocal|indirectSymAbs) != 0 || int(symIdx) >= len(syms) {
				continue
			}
			name := syms[symIdx].Name
			if name == "" {
				continue
			}
			out = append(out, Symbol{
				Name:    name,
				Addr:    s.addr + j*stride,
				Kind:    kind,
				Bind:    BindGlobal,
				Section: s.name,
				Library: machoSymbolLibrary(syms[symIdx].Desc, libs),
			})
		}
	}
	return out
}

// machoSymbolLibrary maps a nlist Desc field to the imported library it binds
// to. The dylib ordinal lives in the high byte of Desc; ordinals are 1-based
// into the dylib load-command order (== ImportedLibraries), with a few special
// values (SELF/MAIN/FLAT_LOOKUP) that name no concrete library.
func machoSymbolLibrary(desc uint16, libs []string) string {
	ord := int((desc >> 8) & 0xff)
	if ord >= 1 && ord <= len(libs) {
		return libs[ord-1]
	}
	return ""
}

// parseMachoSectionHeaders re-reads the segment/section load commands from the
// raw image to recover each section's reserved1/reserved2 (the indirect-symbol
// index and stub size), which debug/macho doesn't expose.
func parseMachoSectionHeaders(raw []byte, base uint64, is64 bool, bo binary.ByteOrder) []machoSecHdr {
	hdrSize := uint64(28)
	if is64 {
		hdrSize = 32
	}
	if base+hdrSize > uint64(len(raw)) {
		return nil
	}
	ncmds := bo.Uint32(raw[base+16:])
	p := base + hdrSize
	var out []machoSecHdr
	for c := uint32(0); c < ncmds; c++ {
		if p+8 > uint64(len(raw)) {
			break
		}
		cmd := bo.Uint32(raw[p:])
		cmdsize := uint64(bo.Uint32(raw[p+4:]))
		if cmdsize < 8 || p+cmdsize > uint64(len(raw)) {
			break
		}
		var segCmdSize, secSize uint64
		if cmd == lcSegment64 {
			segCmdSize, secSize = 72, 80
		} else if cmd == lcSegment {
			segCmdSize, secSize = 56, 68
		} else {
			p += cmdsize
			continue
		}
		nsects := uint64(bo.Uint32(raw[p+segCmdSize-8:])) // nsects is the 2nd-to-last field
		sp := p + segCmdSize
		for s := uint64(0); s < nsects && sp+secSize <= p+cmdsize; s++ {
			b := raw[sp : sp+secSize]
			var addr, size uint64
			var flagsOff int
			if is64 {
				addr = bo.Uint64(b[32:])
				size = bo.Uint64(b[40:])
				flagsOff = 64
			} else {
				addr = uint64(bo.Uint32(b[32:]))
				size = uint64(bo.Uint32(b[36:]))
				flagsOff = 56
			}
			out = append(out, machoSecHdr{
				name:      cstr(b[0:16]),
				addr:      addr,
				size:      size,
				secType:   bo.Uint32(b[flagsOff:]) & 0xff,
				reserved1: bo.Uint32(b[flagsOff+4:]),
				reserved2: bo.Uint32(b[flagsOff+8:]),
			})
			sp += secSize
		}
		p += cmdsize
	}
	return out
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

// Compiler returns the compiler banner ("Apple clang …", "GCC …", "rustc …"),
// computed lazily on first call and cached. ELF fills Info.Compiler eagerly from
// .comment during Open (cheap); Mach-O defers the section scan to here so a cold
// Open doesn't page through __cstring/__const just to populate the Info view.
func (f *File) Compiler() string {
	if f.Info == nil {
		return ""
	}
	f.compilerOnce.Do(func() {
		if f.Info.Compiler == "" {
			f.Info.Compiler = f.scanCompilerString()
		}
	})
	return f.Info.Compiler
}

// scanCompilerString pulls a compiler banner out of likely string/comment
// sections. Scanning the whole Mach-O image is expensive for large frameworks
// and not needed for this optional metadata.
func (f *File) scanCompilerString() string {
	for i := range f.Sections {
		s := &f.Sections[i]
		if !isCompilerStringSection(s) {
			continue
		}
		if compiler := scanCompilerStringBytes(f.sectionData(s)); compiler != "" {
			return compiler
		}
	}
	return ""
}

func isCompilerStringSection(s *Section) bool {
	if s == nil || s.FileSize == 0 || s.Exec {
		return false
	}
	name := strings.ToLower(s.Name)
	return strings.Contains(name, "cstring") || strings.Contains(name, "comment")
}

// scanCompilerStringBytes pulls a compiler banner out of a byte slice. It is
// deliberately conservative: a real banner has a digit right after the version
// word and ends at the "(clang-…)" parenthesis group, so we don't run off the
// end into adjacent strings (Go string data isn't NUL-terminated).
func scanCompilerStringBytes(raw []byte) string {
	for _, needle := range []string{"Apple clang version ", "clang version ", "GCC "} {
		from := 0
		for {
			rel := bytes.Index(raw[from:], []byte(needle))
			if rel < 0 {
				break
			}
			i := from + rel
			vstart := i + len(needle)
			from = vstart
			if vstart >= len(raw) || raw[vstart] < '0' || raw[vstart] > '9' {
				continue // not a real version banner
			}
			end := vstart
			for end < len(raw) && end < i+100 {
				c := raw[end]
				if c < 0x20 || c > 0x7e {
					break
				}
				end++
				if c == ')' {
					break // banners end with the "(clang-…)" group
				}
			}
			return strings.TrimSpace(string(raw[i:end]))
		}
	}
	return ""
}

func machoLibc(in *Info) LibcInfo {
	for _, lib := range in.DynamicLibs {
		if strings.Contains(lib, "libSystem") {
			return LibcInfo{Kind: "libSystem", Source: "needed"}
		}
	}
	if in.StaticLinked {
		return LibcInfo{Kind: "unknown", Source: "static"}
	}
	return LibcInfo{Kind: "none", Source: "no-deps"}
}

// machoInterp returns the dynamic linker path from the LC_LOAD_DYLINKER load
// command, or "" when there is none. Only executables carry it; dylibs, bundles
// and object files are loaded by an already-running dyld and have no interpreter,
// so reporting one for them (as a hardcoded "/usr/lib/dyld" once did) is wrong.
func machoInterp(mf *macho.File) string {
	for _, l := range mf.Loads {
		lb, ok := l.(macho.LoadBytes)
		if !ok {
			continue
		}
		raw := lb.Raw()
		if len(raw) < 12 || mf.ByteOrder.Uint32(raw) != lcLoadDylinker {
			continue
		}
		off := mf.ByteOrder.Uint32(raw[8:12]) // lc_str union: offset within the command
		if int(off) >= len(raw) {
			continue
		}
		name := raw[off:]
		if i := bytes.IndexByte(name, 0); i >= 0 {
			name = name[:i]
		}
		return string(name)
	}
	return ""
}

// machoUUID extracts the LC_UUID load command as a hyphenated hex string.
func machoUUID(mf *macho.File) string {
	for _, l := range mf.Loads {
		lb, ok := l.(macho.LoadBytes)
		if !ok {
			continue
		}
		raw := lb.Raw()
		if len(raw) < 24 || mf.ByteOrder.Uint32(raw) != lcUUID {
			continue
		}
		u := raw[8:24]
		return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
	}
	return ""
}

func (f *File) machoHeaderInfo(mf *macho.File) []string {
	// Dylibs, bundles and object files have no entry point (f.entry == 0); say so
	// rather than printing a literal 0x0.
	entry := fmt.Sprintf("0x%x", f.entry)
	if f.entry == 0 {
		entry = "(none)"
	}
	return []string{
		fmt.Sprintf("Path:        %s", f.Path),
		fmt.Sprintf("Format:      %s", f.Format),
		fmt.Sprintf("CPU:         %s", mf.Cpu),
		fmt.Sprintf("Type:        %s", mf.Type),
		fmt.Sprintf("64-bit:      %v", mf.Magic == macho.Magic64),
		fmt.Sprintf("Entry:       %s", entry),
		fmt.Sprintf("Sections:    %d", len(f.Sections)),
		fmt.Sprintf("Symbols:     %d", len(f.Symbols)),
		fmt.Sprintf("DWARF info:  %v", f.dwarfAvail),
	}
}
