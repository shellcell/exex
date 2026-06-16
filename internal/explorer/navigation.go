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
		_, ok := f.ExecImage().PosForAddr(a)
		return ok
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
			if im := f.ExecImage(); len(im.Regions) > 0 {
				return im.Regions[0].Addr, true
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

func symbolAddr(f *binfile.File, names ...string) (uint64, bool) {
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	for _, s := range f.Symbols {
		if want[s.Name] {
			if _, ok := f.ExecImage().PosForAddr(s.Addr); ok {
				return s.Addr, true
			}
		}
	}
	return 0, false
}

func execSectionAddr(f *binfile.File, names ...string) (uint64, bool) {
	for i := range f.Sections {
		s := &f.Sections[i]
		if !s.Exec || s.Size == 0 {
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
