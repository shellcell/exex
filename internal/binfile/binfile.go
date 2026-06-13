// Package binfile loads an ELF file and exposes the bits the explorer needs:
// header info, sections, symbols, address→source mapping, and a section-aware
// virtual-address reader.
package binfile

import (
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type File struct {
	Path      string
	ELF       *elf.File
	Sections  []*elf.Section
	Symbols   []Symbol // sorted by Name
	symByAddr []Symbol // sorted by Addr
	dwarf     *dwarf.Data
	lines     []lineEntry         // sorted by Addr
	sources   map[string][]string // resolved file -> lines
}

type Symbol struct {
	Name    string
	Addr    uint64
	Size    uint64
	Type    elf.SymType
	Bind    elf.SymBind
	Section string
}

type lineEntry struct {
	Addr uint64
	File string
	Line int
}

func Open(path string) (*File, error) {
	ef, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	f := &File{
		Path:     path,
		ELF:      ef,
		Sections: ef.Sections,
		sources:  map[string][]string{},
	}

	// Symbols: merge static + dynamic, dedupe by (name, addr).
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
			Type:    elf.ST_TYPE(s.Info),
			Bind:    elf.ST_BIND(s.Info),
			Section: sec,
		})
	}
	for _, s := range staticSyms {
		add(s)
	}
	for _, s := range dynSyms {
		add(s)
	}
	sort.Slice(f.Symbols, func(i, j int) bool { return f.Symbols[i].Name < f.Symbols[j].Name })

	f.symByAddr = make([]Symbol, len(f.Symbols))
	copy(f.symByAddr, f.Symbols)
	sort.Slice(f.symByAddr, func(i, j int) bool { return f.symByAddr[i].Addr < f.symByAddr[j].Addr })

	// DWARF is optional.
	if d, err := ef.DWARF(); err == nil {
		f.dwarf = d
		f.lines = loadLines(d)
	}
	return f, nil
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

// SectionAt returns the section whose VM range covers addr.
func (f *File) SectionAt(addr uint64) *elf.Section {
	for _, s := range f.Sections {
		if s.Type == elf.SHT_NULL || s.Flags&elf.SHF_ALLOC == 0 {
			continue
		}
		if addr >= s.Addr && addr < s.Addr+s.Size {
			return s
		}
	}
	return nil
}

// ReadAt reads up to n bytes from the loaded image starting at virtual addr.
func (f *File) ReadAt(addr uint64, n int) ([]byte, error) {
	sec := f.SectionAt(addr)
	if sec == nil {
		return nil, fmt.Errorf("address 0x%x not mapped to any allocated section", addr)
	}
	off := int64(addr - sec.Addr)
	data, err := sec.Data()
	if err != nil {
		return nil, err
	}
	if off >= int64(len(data)) {
		return nil, fmt.Errorf("address 0x%x is past section end", addr)
	}
	end := off + int64(n)
	if end > int64(len(data)) {
		end = int64(len(data))
	}
	return data[off:end], nil
}

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
func (f *File) Entry() uint64 { return f.ELF.Entry }

// Machine returns the ELF machine field.
func (f *File) Machine() elf.Machine { return f.ELF.Machine }

// AddrHexWidth is the number of hex digits an address should be printed with
// for this binary: 8 for 32-bit ELF, 16 for 64-bit ELF.
func (f *File) AddrHexWidth() int {
	if f.ELF.Class == elf.ELFCLASS32 {
		return 8
	}
	return 16
}

// HeaderInfo returns the ELF header as a list of "Label: value" lines.
func (f *File) HeaderInfo() []string {
	h := f.ELF.FileHeader
	return []string{
		fmt.Sprintf("Path:        %s", f.Path),
		fmt.Sprintf("Class:       %s", h.Class),
		fmt.Sprintf("Data:        %s", h.Data),
		fmt.Sprintf("Version:     %s", h.Version),
		fmt.Sprintf("OS/ABI:      %s", h.OSABI),
		fmt.Sprintf("ABI version: %d", h.ABIVersion),
		fmt.Sprintf("Type:        %s", h.Type),
		fmt.Sprintf("Machine:     %s", h.Machine),
		fmt.Sprintf("Entry:       0x%x", h.Entry),
		fmt.Sprintf("Sections:    %d", len(f.Sections)),
		fmt.Sprintf("Symbols:     %d", len(f.Symbols)),
		fmt.Sprintf("DWARF info:  %v", f.dwarf != nil),
	}
}
