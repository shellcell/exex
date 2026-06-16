package binfile

import "fmt"

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
