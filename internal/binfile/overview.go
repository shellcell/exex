package binfile

import (
	"debug/buildinfo"
	"debug/dwarf"
	"strings"
)

// computeOverview fills the format-neutral overview fields of f.Info: file size,
// mapped address range, code size, stack-protector / FORTIFY presence, Go build
// info, and source language. The format loaders fill the rest (word size,
// hardening flags, toolchain). Called once at Open time after the loaders and
// symbol finalisation.
func (f *File) computeOverview() {
	if f.Info == nil {
		f.Info = &Info{}
	}
	in := f.Info
	in.FileSize = uint64(len(f.raw))

	var lo, hi, code uint64
	first := true
	for i := range f.Sections {
		s := &f.Sections[i]
		if !s.Alloc || s.Size == 0 {
			continue
		}
		if first || s.Addr < lo {
			lo = s.Addr
			first = false
		}
		if s.Addr+s.Size > hi {
			hi = s.Addr + s.Size
		}
		if s.Exec {
			code += s.Size
		}
	}
	in.MappedLo, in.MappedHi, in.CodeSize = lo, hi, code

	for _, s := range f.Symbols {
		if strings.Contains(s.Name, "stack_chk_fail") {
			in.Canary = true
		}
		if strings.HasSuffix(s.Name, "_chk") {
			in.Fortify = true
		}
	}

	if bi, err := buildinfo.ReadFile(f.Path); err == nil {
		in.GoVersion = bi.GoVersion
		in.GoModule = bi.Main.Path
		if in.GoModule == "" {
			in.GoModule = bi.Path
		}
		dirty := false
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				in.GoVCS = s.Value
			case "vcs.modified":
				dirty = s.Value == "true"
			}
		}
		if in.GoVCS != "" && dirty {
			in.GoVCS += " (dirty)"
		}
	}

	in.SourceLang = f.sourceLanguage()
}

// sourceLanguage reports the implementation language from DWARF when present,
// otherwise infers it from symbol manglings and Go build info.
func (f *File) sourceLanguage() string {
	if f.dwarf != nil {
		if l := dwarfLanguage(f.dwarf); l != "" {
			return l
		}
	}
	if f.Info != nil && f.Info.GoVersion != "" {
		return "Go"
	}
	var cxx, rust, swift bool
	for _, s := range f.Symbols {
		switch {
		case strings.HasPrefix(s.Name, "_$s") || strings.HasPrefix(s.Name, "$s"):
			swift = true
		case strings.HasPrefix(s.Name, "__R") || strings.HasPrefix(s.Name, "_R"):
			rust = true
		case s.Demangled != "":
			cxx = true
		}
	}
	switch {
	case swift:
		return "Swift"
	case rust:
		return "Rust"
	case cxx:
		return "C/C++"
	}
	return ""
}

func dwarfLanguage(d *dwarf.Data) string {
	r := d.Reader()
	for {
		e, err := r.Next()
		if err != nil || e == nil {
			return ""
		}
		if e.Tag == dwarf.TagCompileUnit {
			if v, ok := e.Val(dwarf.AttrLanguage).(int64); ok {
				return dwarfLangName(v)
			}
			return ""
		}
	}
}

// dwarfLangName maps the common DW_LANG_* constants to a readable name.
func dwarfLangName(v int64) string {
	switch v {
	case 0x0001, 0x0002, 0x000c, 0x001d, 0x0024, 0x0027, 0x0029, 0x002b:
		return "C"
	case 0x0004, 0x0019, 0x001a, 0x0021, 0x0022, 0x002a:
		return "C++"
	case 0x0010:
		return "Objective-C"
	case 0x0011:
		return "Objective-C++"
	case 0x0016:
		return "Go"
	case 0x001c:
		return "Rust"
	case 0x001e:
		return "Swift"
	case 0x000d:
		return "Python"
	}
	return ""
}
