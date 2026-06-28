package binfile

import (
	"runtime"
	"sort"
	"sync"
)

// Printable-string extraction over the raw file, à la strings(1), annotated
// with the mapped virtual address and section when the bytes live in one.

// StringEntry is one printable run found in the file. The bytes themselves are
// not copied: Offset+Len point into the file image (f.raw), and StringText /
// StringBytes recover the text on demand. This keeps the strings list cheap even
// on binaries with millions of strings (a Text copy would duplicate tens of MB
// of the file on the heap).
type StringEntry struct {
	Offset  uint64 // file offset of the first byte
	Addr    uint64 // mapped virtual address, when HasAddr
	Len     uint32 // length of the run in bytes
	HasAddr bool
	Section string // owning section name, when known
}

// StringBytes returns e's bytes as a zero-copy slice into the file image. Valid
// only while f is open (its raw bytes are still mapped/retained); for scanning
// many entries (the filter) this avoids any allocation.
func (f *File) StringBytes(e StringEntry) []byte {
	end := e.Offset + uint64(e.Len)
	if e.Offset > uint64(len(f.raw)) || end > uint64(len(f.raw)) {
		return nil
	}
	return f.raw[e.Offset:end]
}

// StringText returns e's text as a string (a copy). Use it for display of the
// visible rows and the clipboard; prefer StringBytes when scanning many entries.
func (f *File) StringText(e StringEntry) string {
	return string(f.StringBytes(e))
}

// NewRawFile returns a File backed by raw bytes with no parsed structure — for
// tests and callers that synthesize a byte image (e.g. to use Strings).
func NewRawFile(raw []byte) *File { return &File{raw: raw} }

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

// extractStrings performs the uncached printable-string scan. The file is split
// into per-CPU chunks scanned in parallel (the scan is the dominant cost on large
// binaries — hundreds of MB), then the per-chunk results are concatenated in
// order. Each worker owns the runs that *start* in its chunk: it skips a run that
// began in the previous chunk and follows a run that spills into the next, so no
// string is split or double-counted at a boundary.
func (f *File) extractStrings() []StringEntry {
	data := f.raw
	// Sort the file-backed sections once so each found string is mapped to its
	// section with a binary search instead of an O(sections) scan.
	secs := f.fileSectionsByOffset()
	n := max(runtime.NumCPU(), 1)
	if len(data) < 1<<20 || n == 1 {
		return f.extractStringsRange(data, secs, 0, len(data))
	}
	chunk := (len(data) + n - 1) / n
	parts := make([][]StringEntry, n)
	var wg sync.WaitGroup
	for w := 0; w*chunk < len(data); w++ {
		lo := w * chunk
		hi := min(lo+chunk, len(data))
		wg.Add(1)
		go func(w, lo, hi int) {
			defer wg.Done()
			parts[w] = f.extractStringsRange(data, secs, lo, hi)
		}(w, lo, hi)
	}
	wg.Wait()
	total := 0
	for _, p := range parts {
		total += len(p)
	}
	out := make([]StringEntry, 0, total) // one alloc for the merge, not log(n) reallocs
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// extractStringsRange scans data[lo:hi] for printable runs, emitting those that
// *start* within [lo,hi). A run already in progress at lo (data[lo-1] printable)
// belongs to the previous chunk and is skipped; a run still open at hi is
// followed past the boundary so it is captured whole exactly once.
func (f *File) extractStringsRange(data []byte, secs []*Section, lo, hi int) []StringEntry {
	printable := func(b byte) bool { return b >= 0x20 && b < 0x7f }
	out := make([]StringEntry, 0, 4096) // a typical section holds thousands of runs
	start := -1
	flush := func(end int) {
		if start >= 0 && end-start >= minString {
			e := StringEntry{Offset: uint64(start), Len: uint32(end - start)}
			if sec := sectionAtSortedOffset(secs, uint64(start)); sec != nil {
				e.Section = sec.Name
				if sec.Alloc {
					e.Addr = sec.Addr + (uint64(start) - sec.Offset)
					e.HasAddr = true
				}
			}
			out = append(out, e)
		}
		start = -1
	}
	i := lo
	if lo > 0 && printable(data[lo-1]) { // mid-run at the boundary: previous chunk owns it
		for i < hi && printable(data[i]) {
			i++
		}
	}
	for ; i < hi; i++ {
		if printable(data[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		flush(i)
	}
	if start >= 0 { // a run open at hi continues into the next chunk; finish it here
		end := hi
		for end < len(data) && printable(data[end]) {
			end++
		}
		flush(end)
	}
	return out
}

// fileSectionsByOffset returns the sections that occupy file bytes, sorted by
// file offset, for binary-searched offset→section lookups.
func (f *File) fileSectionsByOffset() []*Section {
	var secs []*Section
	for i := range f.Sections {
		if f.Sections[i].FileSize > 0 {
			secs = append(secs, &f.Sections[i])
		}
	}
	sort.Slice(secs, func(i, j int) bool { return secs[i].Offset < secs[j].Offset })
	return secs
}

// sectionAtSortedOffset returns the section whose file bytes cover off, from a
// slice sorted by file offset (well-formed section file ranges don't overlap).
func sectionAtSortedOffset(secs []*Section, off uint64) *Section {
	i := sort.Search(len(secs), func(i int) bool { return secs[i].Offset > off })
	if i == 0 {
		return nil
	}
	s := secs[i-1]
	if off < s.Offset+s.FileSize {
		return s
	}
	return nil
}
