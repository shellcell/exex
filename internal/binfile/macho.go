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

	"github.com/psimonen/elf-explorer/internal/disasm"
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
	lcMain   = 0x80000028
	lcUUID   = 0x1b
	nStab    = 0xe0
	nType    = 0x0e
	nSect    = 0x0e // N_TYPE value meaning "defined in section number n_sect"
	nExt     = 0x01
	nWeakDef = 0x0080 // n_desc bit

	// Section attribute bits (high 24 bits of a section's flags field).
	machoAttrPureInstr = 0x80000000 // S_ATTR_PURE_INSTRUCTIONS
	machoAttrSomeInstr = 0x00000400 // S_ATTR_SOME_INSTRUCTIONS
)

func isMachO(raw []byte) bool {
	if len(raw) < 4 {
		return false
	}
	m := binary.BigEndian.Uint32(raw)
	switch m {
	case machoMagic32, machoMagic64, machoCigam32, machoCigam64,
		machoFatMagic, machoFatMagic2:
		return true
	}
	return false
}

func isFatMachO(raw []byte) bool {
	if len(raw) < 4 {
		return false
	}
	m := binary.BigEndian.Uint32(raw)
	return m == machoFatMagic || m == machoFatMagic2
}

// loadMachO parses f.raw as a Mach-O object and populates the neutral model.
// For universal ("fat") binaries it selects the host architecture's slice when
// present, otherwise the first slice.
func (f *File) loadMachO() error {
	mf, base, err := parseMachO(f.raw)
	if err != nil {
		return err
	}

	f.Format = FormatMachO
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

	if d := f.machoDWARF(mf); d != nil {
		f.dwarf = d
		f.lines = loadLines(d)
	}

	f.entry = machoEntry(mf, textSeg, base)
	f.loadMachOInfo(mf)
	f.header = f.machoHeaderInfo(mf)
	return nil
}

// parseMachO opens raw as a thin or fat Mach-O, returning the chosen slice's
// *macho.File and the file offset that slice starts at (0 for thin files).
func parseMachO(raw []byte) (*macho.File, uint64, error) {
	ra := bytes.NewReader(raw)
	if isFatMachO(raw) {
		ff, err := macho.NewFatFile(ra)
		if err != nil {
			return nil, 0, err
		}
		if len(ff.Arches) == 0 {
			return nil, 0, fmt.Errorf("fat Mach-O has no architectures")
		}
		fa := pickFatArch(ff)
		return fa.File, uint64(fa.Offset), nil
	}
	mf, err := macho.NewFile(ra)
	if err != nil {
		return nil, 0, err
	}
	return mf, 0, nil
}

// machoDWARF returns DWARF for the binary: embedded if present, otherwise from
// a companion .dSYM bundle next to the file. On macOS the linker leaves debug
// info in a separate <binary>.dSYM rather than the executable, so without this
// the source pane would almost never have anything to show.
func (f *File) machoDWARF(mf *macho.File) *dwarf.Data {
	if d, err := mf.DWARF(); err == nil {
		return d
	}
	cand := f.Path + ".dSYM/Contents/Resources/DWARF/" + filepath.Base(f.Path)
	raw, err := os.ReadFile(cand)
	if err != nil {
		return nil
	}
	dm, _, err := parseMachO(raw)
	if err != nil {
		return nil
	}
	if d, err := dm.DWARF(); err == nil {
		return d
	}
	return nil
}

func pickFatArch(ff *macho.FatFile) macho.FatArch {
	want := hostCPU()
	for _, fa := range ff.Arches {
		if fa.Cpu == want {
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

func machoArch(c macho.Cpu) disasm.Arch {
	switch c {
	case macho.CpuAmd64:
		return disasm.ArchAMD64
	case macho.Cpu386:
		return disasm.ArchX86
	case macho.CpuArm64:
		return disasm.ArchARM64
	}
	return disasm.ArchUnknown
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
	// Fall back to a likely start symbol, then the first exec section.
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
	if !in.StaticLinked {
		in.Interp = "/usr/lib/dyld"
	}
	in.Libc = machoLibc(in)
	f.Info = in
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
	return []string{
		fmt.Sprintf("Path:        %s", f.Path),
		fmt.Sprintf("Format:      %s", f.Format),
		fmt.Sprintf("CPU:         %s", mf.Cpu),
		fmt.Sprintf("Type:        %s", mf.Type),
		fmt.Sprintf("64-bit:      %v", mf.Magic == macho.Magic64),
		fmt.Sprintf("Entry:       0x%x", f.entry),
		fmt.Sprintf("Sections:    %d", len(f.Sections)),
		fmt.Sprintf("Symbols:     %d", len(f.Symbols)),
		fmt.Sprintf("DWARF info:  %v", f.dwarf != nil),
	}
}
