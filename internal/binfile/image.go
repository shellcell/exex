package binfile

import "sort"

// Image is a logical byte stream stitched together from several sections in
// virtual-address order, with the gaps between them removed. It lets the hex
// and disasm views scroll across *all* mapped (or all executable) sections as
// one stream while still recovering the real virtual address of any byte.
//
// The bytes are NOT copied into one buffer: each region keeps a slice into the
// original (mmap'd or read) file image, so building an Image is allocation-free
// and a 100 MB binary doesn't cost a second 50 MB of heap. Callers read bytes
// through At/Bytes/Window; Bytes is zero-copy when the range stays inside one
// region (the common case — one section usually dominates) and copies only a
// bounded range that straddles a region boundary.
//
// Regions are sorted by both Addr and Off (Off is assigned sequentially as
// regions are appended in address order, so the two orderings coincide).
type Image struct {
	Regions []Region
	size    int // total logical length (sum of region sizes)
}

// Window is a bounded slice of an Image. Start/End are byte positions within
// Image.Data; End is exclusive.
type Window struct {
	Addr  uint64
	Data  []byte
	Start int
	End   int
}

// Region records where one section landed inside the flattened image.
type Region struct {
	Addr uint64 // virtual address of the first byte
	Size uint64 // number of bytes (== len(b))
	Off  int    // offset of the first byte within the logical stream
	Name string
	b    []byte // the region's bytes — a slice into the file image, not a copy
}

// NewImage builds an Image from a single contiguous backing slice and its
// regions: each region's bytes are data[Off:Off+Size]. Used by tests and callers
// that already hold the bytes contiguously. buildImage uses the per-section
// slices directly instead.
func NewImage(data []byte, regions []Region) *Image {
	im := &Image{}
	for _, r := range regions {
		lo := min(r.Off, len(data))
		r.b = data[lo:min(r.Off+int(r.Size), len(data))]
		r.Size = uint64(len(r.b)) // keep Size == len(b) so At/Bytes can't over-read
		im.Regions = append(im.Regions, r)
		im.size = max(im.size, r.Off+len(r.b))
	}
	return im
}

// Run is one region's contiguous native bytes (zero-copy, a slice into the file
// image) with its logical start offset. Whole-image scans iterate Runs so
// bytes.Index/IndexByte run on the real bytes at full speed, region by region,
// instead of fixed-size chunks (which hit bytes.Index's small-slice slow path).
type Run struct {
	Off int
	B   []byte
}

// Runs returns the image's regions as native byte runs, in offset order.
func (im *Image) Runs() []Run {
	if im == nil {
		return nil
	}
	out := make([]Run, len(im.Regions))
	for i := range im.Regions {
		out[i] = Run{Off: im.Regions[i].Off, B: im.Regions[i].b}
	}
	return out
}

// Len is the total number of bytes in the image.
func (im *Image) Len() int {
	if im == nil {
		return 0
	}
	return im.size
}

// At returns the byte at logical position pos (0 when out of range).
func (im *Image) At(pos int) byte {
	r := im.RegionAt(pos)
	if r == nil {
		return 0
	}
	return r.b[pos-r.Off]
}

// Bytes returns the logical bytes in [start,end). It is zero-copy when the range
// lies within a single region (the common case); a range straddling a region
// boundary is copied into a fresh bounded buffer.
func (im *Image) Bytes(start, end int) []byte {
	if im == nil || start < 0 {
		start = 0
	}
	if end > im.size {
		end = im.size
	}
	if start >= end {
		return nil
	}
	if r := im.RegionAt(start); r != nil && end <= r.Off+int(r.Size) {
		return r.b[start-r.Off : end-r.Off] // within one region: no copy
	}
	out := make([]byte, end-start) // zero-filled; gaps between regions stay zero
	for i := start; i < end; {
		r := im.RegionAt(i)
		if r == nil {
			// In a gap (no region covers i): skip to the next region's start,
			// leaving zeros. (Images built from sections have no gaps; this only
			// arises for sparse/synthetic region maps.)
			k := sort.Search(len(im.Regions), func(k int) bool { return im.Regions[k].Off > i })
			if k >= len(im.Regions) {
				break
			}
			i = im.Regions[k].Off
			continue
		}
		n := copy(out[i-start:], r.b[i-r.Off:])
		if n == 0 {
			break
		}
		i += n
	}
	return out
}

// AddrAt maps a byte position within Data to its virtual address.
func (im *Image) AddrAt(pos int) uint64 {
	if im == nil || len(im.Regions) == 0 {
		return uint64(pos)
	}
	i := sort.Search(len(im.Regions), func(i int) bool { return im.Regions[i].Off > pos })
	if i == 0 {
		return im.Regions[0].Addr
	}
	r := im.Regions[i-1]
	return r.Addr + uint64(pos-r.Off)
}

// PosForAddr maps a virtual address to its byte position within Data, reporting
// whether addr falls inside any region.
func (im *Image) PosForAddr(addr uint64) (int, bool) {
	if im == nil || len(im.Regions) == 0 {
		return 0, false
	}
	i := sort.Search(len(im.Regions), func(i int) bool { return im.Regions[i].Addr > addr })
	if i == 0 {
		return 0, false
	}
	r := im.Regions[i-1]
	if addr >= r.Addr && addr < r.Addr+r.Size {
		return r.Off + int(addr-r.Addr), true
	}
	return 0, false
}

// RegionAt returns the region containing pos, or nil.
func (im *Image) RegionAt(pos int) *Region {
	if im == nil || len(im.Regions) == 0 || pos < 0 {
		return nil
	}
	i := sort.Search(len(im.Regions), func(i int) bool { return im.Regions[i].Off > pos })
	if i == 0 {
		return nil
	}
	r := &im.Regions[i-1]
	if uint64(pos-r.Off) >= r.Size {
		return nil
	}
	return r
}

// Window returns a clamped byte window into the image. Data is zero-copy when the
// window stays within one region (see Bytes).
func (im *Image) Window(start, size int) Window {
	if im == nil || im.size == 0 || size <= 0 {
		return Window{}
	}
	if start < 0 {
		start = 0
	}
	if start >= im.size {
		start = im.size
	}
	if size > im.size-start {
		size = im.size - start
	}
	end := max(start+size, start)
	return Window{
		Addr:  im.AddrAt(start),
		Data:  im.Bytes(start, end),
		Start: start,
		End:   end,
	}
}

// WindowContaining returns a clamped byte window that contains addr, with up
// to before bytes of context preceding it.
func (im *Image) WindowContaining(addr uint64, size, before int) (Window, bool) {
	pos, ok := im.PosForAddr(addr)
	if !ok {
		return Window{}, false
	}
	if size <= 0 || size > im.size {
		size = im.size
	}
	if size == 0 {
		return Window{}, false
	}
	if before < 0 {
		before = 0
	}
	if before >= size {
		before = size - 1
	}
	start := max(pos-before, 0)
	if start+size > im.size {
		start = max(im.size-size, 0)
	}
	return im.Window(start, size), true
}

// buildImage flattens the sections selected by keep (in VA order) into an Image.
func (f *File) buildImage(keep func(*Section) bool) *Image {
	var secs []*Section
	for i := range f.Sections {
		s := &f.Sections[i]
		if !s.Alloc || s.Size == 0 {
			continue
		}
		if !keep(s) {
			continue
		}
		if data := f.sectionData(s); len(data) > 0 {
			secs = append(secs, s)
		}
	}
	sort.Slice(secs, func(i, j int) bool { return secs[i].Addr < secs[j].Addr })

	im := &Image{}
	for _, s := range secs {
		data := f.sectionData(s) // a slice into f.raw — not copied
		im.Regions = append(im.Regions, Region{
			Addr: s.Addr,
			Size: uint64(len(data)),
			Off:  im.size,
			Name: s.Name,
			b:    data,
		})
		im.size += len(data)
	}
	return im
}

// VAImage returns the flattened image of every mapped section, built lazily.
func (f *File) VAImage() *Image {
	if f.vaImage == nil {
		f.vaImage = f.buildImage(func(*Section) bool { return true })
	}
	return f.vaImage
}

// ExecImage returns the byte source the disassembler sweeps: normally just the
// executable sections, but every section with file content when disasm-all mode
// is enabled (so object files and non-exec sections can still be decoded). Built
// lazily; both variants are cached.
func (f *File) ExecImage() *Image {
	if f.disasmAll {
		if f.allImage == nil {
			f.allImage = f.buildAllImage()
		}
		return f.allImage
	}
	if f.execImage == nil {
		f.execImage = f.buildImage(func(s *Section) bool { return s.Exec })
	}
	return f.execImage
}

// SetDisasmAll switches ExecImage between executable-only and all-sections-with-
// content. Disasm callers must rebuild any image-derived state after toggling.
func (f *File) SetDisasmAll(on bool) { f.disasmAll = on }

// DisasmAll reports whether disasm-all mode is active.
func (f *File) DisasmAll() bool { return f.disasmAll }

// HasPhysAddrs reports whether any section carries a distinct load/physical
// address (a higher-half kernel, say) — so a caller can offer to interpret a
// typed address as physical.
func (f *File) HasPhysAddrs() bool {
	for i := range f.Sections {
		if f.Sections[i].PhysAddr != 0 {
			return true
		}
	}
	return false
}

// PhysToVirtual maps a physical/load (LMA) address to its virtual address via the
// section whose load range contains it; ok is false when none does. Used to jump
// to a physical address in a binary whose VMA differs from its LMA.
func (f *File) PhysToVirtual(phys uint64) (uint64, bool) {
	for i := range f.Sections {
		s := &f.Sections[i]
		if s.PhysAddr == 0 || s.Size == 0 {
			continue
		}
		if phys >= s.PhysAddr && phys < s.PhysAddr+s.Size {
			return s.Addr + (phys - s.PhysAddr), true
		}
	}
	return 0, false
}

// SyntheticAddrs reports whether section/symbol addresses are a synthetic layout
// exex assigned because the file is a relocatable object whose sections all load
// at address 0 (so they'd otherwise collide). The real position of any address is
// section-relative: addr − SectionAt(addr).Addr within that section.
func (f *File) SyntheticAddrs() bool { return f.synthetic }

// AddrDisassemblable reports whether addr falls inside any section with file
// content (the disasm-all image) — i.e. it could be shown in disasm-all mode even
// if it isn't in an executable section (kernel/multiboot sections, data, …).
func (f *File) AddrDisassemblable(addr uint64) bool {
	if f.allImage == nil {
		f.allImage = f.buildAllImage()
	}
	_, ok := f.allImage.PosForAddr(addr)
	return ok
}

// HasExecCode reports whether the file has any executable section to disassemble
// in the normal (exec-only) image — false for most relocatable object files.
func (f *File) HasExecCode() bool {
	for i := range f.Sections {
		s := &f.Sections[i]
		if s.Alloc && s.Exec && s.Size != 0 && s.FileSize != 0 {
			return true
		}
	}
	return false
}

// IncludeInDisasmAll reports whether a section belongs in a disasm-all sweep.
//
// The disasm image is one monotonic address space, so it must stay coherent:
//   - Metadata (symbol/string/debug/note/dynamic/relocation) is never code and
//     lives at address 0; mixing it with real-VA code makes a window spanning the
//     0 → high-VA jump decode to junk. Always excluded.
//   - For a linked file (one with mapped executable code), include only the
//     ALLOCATED sections — the actual loaded image: code plus non-exec loaded
//     data (.multiboot, .rodata, .data). Non-allocated leftovers (.comment, …)
//     sit at address 0 and would poison the space, so they're dropped.
//   - For an object file (no mapped exec code; e.g. a Mach-O .o whose __text
//     isn't flagged allocated), include code/data content sections at their
//     sequential 0-based addresses — there's no real VA to conflict with.
func (f *File) IncludeInDisasmAll(s *Section) bool {
	switch s.Category {
	case CatDebug, CatNote, CatSymtab, CatDynamic, CatReloc:
		return false
	}
	if f.HasExecCode() && !s.Alloc {
		return false // a loadable image's non-allocated sections are metadata, not code
	}
	return true
}

// buildAllImage flattens the disasm-all sections (see IncludeInDisasmAll) that
// carry file bytes into one image, ordered by address then file offset.
func (f *File) buildAllImage() *Image {
	var secs []*Section
	for i := range f.Sections {
		s := &f.Sections[i]
		if s.Size == 0 || !f.IncludeInDisasmAll(s) {
			continue
		}
		if data := f.sectionData(s); len(data) > 0 {
			secs = append(secs, s)
		}
	}
	sort.SliceStable(secs, func(i, j int) bool {
		if secs[i].Addr != secs[j].Addr {
			return secs[i].Addr < secs[j].Addr
		}
		return secs[i].Offset < secs[j].Offset
	})

	im := &Image{}
	for _, s := range secs {
		data := f.sectionData(s)
		im.Regions = append(im.Regions, Region{
			Addr: s.Addr,
			Size: uint64(len(data)),
			Off:  im.size,
			Name: s.Name,
			b:    data,
		})
		im.size += len(data)
	}
	return im
}
