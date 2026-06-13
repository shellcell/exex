package binfile

// Printable-string extraction over the raw file, à la strings(1), annotated
// with the mapped virtual address and section when the bytes live in one.

// StringEntry is one printable run found in the file.
type StringEntry struct {
	Offset  uint64 // file offset of the first byte
	Addr    uint64 // mapped virtual address, when HasAddr
	HasAddr bool
	Section string // owning section name, when known
	Text    string
}

// minString is the shortest run of printable bytes reported as a string.
const minString = 4

// Strings scans the whole file for runs of printable ASCII at least minString
// bytes long. The result is cached. Each entry is mapped back to a virtual
// address / section when its offset falls inside a section's file bytes.
func (f *File) Strings() []StringEntry {
	if f.strings != nil {
		return f.strings
	}
	f.strings = f.extractStrings()
	return f.strings
}

func (f *File) extractStrings() []StringEntry {
	var out []StringEntry
	data := f.raw
	start := -1
	flush := func(end int) {
		if start < 0 || end-start < minString {
			start = -1
			return
		}
		e := StringEntry{Offset: uint64(start), Text: string(data[start:end])}
		if sec := f.sectionAtFileOffset(uint64(start)); sec != nil {
			e.Section = sec.Name
			if sec.Alloc {
				e.Addr = sec.Addr + (uint64(start) - sec.Offset)
				e.HasAddr = true
			}
		}
		out = append(out, e)
		start = -1
	}
	for i := 0; i < len(data); i++ {
		if b := data[i]; b >= 0x20 && b < 0x7f {
			if start < 0 {
				start = i
			}
			continue
		}
		flush(i)
	}
	flush(len(data))
	return out
}

// sectionAtFileOffset returns the section whose file bytes cover off.
func (f *File) sectionAtFileOffset(off uint64) *Section {
	for i := range f.Sections {
		s := &f.Sections[i]
		if s.FileSize == 0 {
			continue
		}
		if off >= s.Offset && off < s.Offset+s.FileSize {
			return s
		}
	}
	return nil
}
