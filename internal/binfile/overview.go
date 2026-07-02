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
		if !in.Canary && (strings.Contains(s.Name, "stack_chk_fail") || strings.Contains(s.Name, "security_cookie")) {
			in.Canary = true
		}
		if !in.Fortify && strings.HasSuffix(s.Name, "_chk") {
			in.Fortify = true
		}
		if in.Canary && in.Fortify {
			break // both found — no need to scan the rest of the symbols
		}
	}

	// buildinfo.ReadFile re-opens and re-parses the whole file (~100 ms+, more for a
	// fat Mach-O). ELF/Mach-O Go binaries carry a ".go.buildinfo"/"__go_buildinfo"
	// section, so skip the call entirely for non-Go ones; PE Go binaries have no
	// such section (build info is scanned from .data), so always try there.
	if f.Format == FormatPE || f.hasGoBuildInfo() {
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
	}

	in.SourceLang = f.sourceLanguage()
}

// hasGoBuildInfo reports whether the binary carries a Go build-info section, so
// computeOverview only pays buildinfo.ReadFile for actual Go binaries.
func (f *File) hasGoBuildInfo() bool {
	for i := range f.Sections {
		switch f.Sections[i].Name {
		case "__go_buildinfo", ".go.buildinfo":
			return true
		}
	}
	return false
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
	// Match on the raw mangled-name prefixes: computeOverview runs at Open time,
	// before the background demangle pass, so s.Demangled isn't populated yet.
	// Itanium C++ is "_Z" ("__Z" on Mach-O's extra-underscore convention).
	var cxx, rust, swift bool
	for _, s := range f.Symbols {
		switch {
		case strings.HasPrefix(s.Name, "_$s") || strings.HasPrefix(s.Name, "$s"):
			swift = true
		case strings.HasPrefix(s.Name, "__R") || strings.HasPrefix(s.Name, "_R"):
			rust = true
		case strings.HasPrefix(s.Name, "_Z") || strings.HasPrefix(s.Name, "__Z"):
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

// dwarfLanguage returns the first compile unit's source language.
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
	case 0x0001, 0x0002, 0x000c, 0x001d, 0x002c:
		return "C"
	case 0x0004, 0x0019, 0x001a, 0x0021, 0x002a, 0x002b:
		return "C++"
	case 0x0003, 0x000d, 0x002e, 0x002f:
		return "Ada"
	case 0x0005, 0x0006:
		return "COBOL"
	case 0x0007, 0x0008, 0x000e, 0x0022, 0x0023, 0x002d:
		return "Fortran"
	case 0x0009:
		return "Pascal"
	case 0x000a:
		return "Modula-2"
	case 0x000b:
		return "Java"
	case 0x0010:
		return "Objective-C"
	case 0x0011:
		return "Objective-C++"
	case 0x0012:
		return "UPC"
	case 0x0013:
		return "D"
	case 0x0014:
		return "Python"
	case 0x0015:
		return "OpenCL"
	case 0x0016:
		return "Go"
	case 0x0017:
		return "Modula-3"
	case 0x0018:
		return "Haskell"
	case 0x001b:
		return "OCaml"
	case 0x001c:
		return "Rust"
	case 0x001e:
		return "Swift"
	case 0x001f:
		return "Julia"
	case 0x0020:
		return "Dylan"
	case 0x0024:
		return "RenderScript"
	case 0x0025:
		return "BLISS"
	case 0x0026:
		return "Kotlin"
	case 0x0027:
		return "Zig"
	case 0x0028:
		return "Crystal"
	case 0x0030:
		return "HIP"
	case 0x0031, 0x8001:
		return "Assembly"
	case 0x0032:
		return "C#"
	case 0x0033:
		return "Mojo"
	case 0x0034:
		return "GLSL"
	case 0x0035:
		return "GLSL ES"
	case 0x0036:
		return "HLSL"
	case 0x0037:
		return "OpenCL C++"
	case 0x0038:
		return "C++ for OpenCL"
	case 0x0039:
		return "SYCL"
	case 0x003d:
		return "Metal"
	case 0x0040:
		return "Ruby"
	case 0x0041:
		return "Move"
	case 0x0042:
		return "Hylo"
	case 0xb000:
		return "Delphi"
	}
	return ""
}
