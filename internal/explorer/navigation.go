// Package explorer contains format-neutral navigation and service logic shared
// by the TUI.
package explorer

import "github.com/rabarbra/exex/internal/binfile"

// DefaultExecAddr resolves a guaranteed-executable address for the disasm view
// to land on, honouring the requested strategy and falling back down a sensible
// chain when the choice can't be resolved. Returns 0 only when the binary has no
// executable code at all.
//
// Strategies: "entry" (the entry point), "main"/"start" (those symbols),
// "text" (the .text/__text section), "lowest" (lowest executable address).
func DefaultExecAddr(f *binfile.File, strategy string) uint64 {
	if f == nil {
		return 0
	}
	inExec := func(a uint64) bool {
		if s := f.SectionAt(a); s != nil {
			return s.Exec && s.FileSize != 0
		}
		return false
	}
	try := func(s string) (uint64, bool) {
		switch s {
		case "entry":
			if entry := f.Entry(); entry != 0 && inExec(entry) {
				return entry, true
			}
		case "main":
			if a, ok := symbolAddr(f, "main", "_main"); ok {
				return a, true
			}
		case "start":
			if a, ok := symbolAddr(f, "_start", "start", "__start"); ok {
				return a, true
			}
		case "text":
			if a, ok := execSectionAddr(f, ".text", "__text"); ok {
				return a, true
			}
		case "lowest":
			var best uint64
			ok := false
			for i := range f.Sections {
				s := &f.Sections[i]
				if !s.Alloc || !s.Exec || s.Size == 0 || s.FileSize == 0 {
					continue
				}
				if !ok || s.Addr < best {
					best = s.Addr
					ok = true
				}
			}
			if ok {
				return best, true
			}
		}
		return 0, false
	}
	for _, s := range []string{strategy, "entry", "main", "start", "text", "lowest"} {
		if a, ok := try(s); ok {
			return a
		}
	}
	return 0
}

// symbolAddr returns the first executable symbol matching one of names.
func symbolAddr(f *binfile.File, names ...string) (uint64, bool) {
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	for _, s := range f.Symbols {
		if want[s.Name] {
			if sec := f.SectionAt(s.Addr); sec != nil && sec.Exec && sec.FileSize != 0 {
				return s.Addr, true
			}
		}
	}
	return 0, false
}

// execSectionAddr returns the address of a named executable section.
func execSectionAddr(f *binfile.File, names ...string) (uint64, bool) {
	for i := range f.Sections {
		s := &f.Sections[i]
		if !s.Exec || s.Size == 0 || s.FileSize == 0 {
			continue
		}
		for _, n := range names {
			if s.Name == n {
				return s.Addr, true
			}
		}
	}
	return 0, false
}
