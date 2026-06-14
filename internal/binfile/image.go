package binfile

import "sort"

// Image is a continuous byte buffer stitched together from several sections in
// virtual-address order, with the gaps between them removed. It lets the hex
// and disasm views scroll across *all* mapped (or all executable) sections as
// one stream while still recovering the real virtual address of any byte.
//
// Regions are sorted by both Addr and Off (Off is assigned sequentially as
// regions are appended in address order, so the two orderings coincide).
type Image struct {
	Data    []byte
	Regions []Region
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
	Size uint64 // number of bytes (== len of the section's slice in Data)
	Off  int    // offset of the first byte within Image.Data
	Name string
}

// Len is the total number of bytes in the image.
func (im *Image) Len() int {
	if im == nil {
		return 0
	}
	return len(im.Data)
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
	if im == nil || len(im.Regions) == 0 {
		return nil
	}
	i := sort.Search(len(im.Regions), func(i int) bool { return im.Regions[i].Off > pos })
	if i == 0 {
		return nil
	}
	return &im.Regions[i-1]
}

// Window returns a clamped byte window into the image.
func (im *Image) Window(start, size int) Window {
	if im == nil || len(im.Data) == 0 || size <= 0 {
		return Window{}
	}
	if start < 0 {
		start = 0
	}
	if start >= len(im.Data) {
		start = len(im.Data)
	}
	if size > len(im.Data)-start {
		size = len(im.Data) - start
	}
	end := start + size
	if end < start {
		end = start
	}
	return Window{
		Addr:  im.AddrAt(start),
		Data:  im.Data[start:end],
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
	if size <= 0 || size > len(im.Data) {
		size = len(im.Data)
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
	start := pos - before
	if start < 0 {
		start = 0
	}
	if start+size > len(im.Data) {
		start = len(im.Data) - size
		if start < 0 {
			start = 0
		}
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
		data := f.sectionData(s)
		im.Regions = append(im.Regions, Region{
			Addr: s.Addr,
			Size: uint64(len(data)),
			Off:  len(im.Data),
			Name: s.Name,
		})
		im.Data = append(im.Data, data...)
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

// ExecImage returns the flattened image of every executable section, built
// lazily. This is the byte source the disassembler sweeps.
func (f *File) ExecImage() *Image {
	if f.execImage == nil {
		f.execImage = f.buildImage(func(s *Section) bool { return s.Exec })
	}
	return f.execImage
}
