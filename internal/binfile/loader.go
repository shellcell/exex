package binfile

import "fmt"

// Option customises how Open loads a binary.
type Option func(*openOptions)

type openOptions struct {
	debugPath  string
	arch       string
	layoutOnly bool
}

// WithDebugPath points the loader at an explicit external debug-symbols file or
// directory (an ELF .debug companion, or a .dSYM bundle / DWARF file for
// Mach-O), tried before the conventional auto-discovered locations.
func WithDebugPath(p string) Option {
	return func(o *openOptions) { o.debugPath = p }
}

// WithArch selects which slice of a universal (fat) Mach-O to load, by name
// (e.g. "x86_64", "arm64"). Empty (the default) picks the host architecture, or
// the first slice. Ignored for thin Mach-O and other formats.
func WithArch(name string) Option {
	return func(o *openOptions) { o.arch = name }
}

// WithLayoutOnly loads just the container layout: architecture, entry, sections,
// segments and raw bytes. It skips symbols, imports, relocations, DWARF and the
// overview fields, for views that do not need them.
func WithLayoutOnly() Option {
	return func(o *openOptions) { o.layoutOnly = true }
}

// Open reads path, detects its container format, and builds the neutral model.
func Open(path string, opts ...Option) (*File, error) {
	var o openOptions
	for _, opt := range opts {
		opt(&o)
	}
	// mapFile mmaps the file where that's supported, otherwise it reads the file
	// into the heap. On macOS the mmap path uses MAP_RESILIENT_CODESIGN so signed
	// Mach-O pages do not SIGKILL the reader if code-signing validation fails.
	raw, closer, err := mapFile(path)
	if err != nil {
		return nil, err
	}
	f := &File{
		Path:       path,
		debugPath:  o.debugPath,
		reqArch:    o.arch,
		layoutOnly: o.layoutOnly,
		raw:        raw,
		unmap:      closer,
		sources:    map[string][]string{},
	}
	if err := f.load(); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// OpenBytes builds the neutral model from an in-memory image (no file mapping),
// labelled by name. Used for objects that aren't standalone files — e.g. the
// members of a static-library (ar) archive. The caller owns raw and must keep it
// alive for the lifetime of the returned File (its sections slice into it).
func OpenBytes(name string, raw []byte) (*File, error) {
	f := &File{
		Path:    name,
		raw:     raw,
		sources: map[string][]string{},
	}
	if err := f.load(); err != nil {
		return nil, err
	}
	return f, nil
}

// load detects f.raw's container format, builds the model, and finalises it.
func (f *File) load() error {
	raw := f.raw
	switch {
	case len(raw) >= 4 && raw[0] == 0x7f && raw[1] == 'E' && raw[2] == 'L' && raw[3] == 'F':
		if err := f.loadELF(); err != nil {
			return err
		}
	case isMachO(raw):
		if err := f.loadMachO(); err != nil {
			return err
		}
	case len(raw) >= 2 && raw[0] == 'M' && raw[1] == 'Z':
		if err := f.loadPE(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unrecognised file format (not ELF, Mach-O, or PE)")
	}
	if !f.layoutOnly {
		f.finalizeSymbols()
		f.computeOverview()
	}
	return nil
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
