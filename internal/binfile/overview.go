package binfile

import (
	"debug/buildinfo"
	"debug/dwarf"
	"sort"
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

// dwarfLangNames maps the DW_LANG_* constants to a readable name. Several codes
// share a language (C and Fortran each span multiple standard revisions). Keeping
// this as data (rather than a switch) lets DwarfLanguageNames enumerate the set,
// which the syntax-coverage test cross-checks against the curated Chroma lexers.
var dwarfLangNames = map[int64]string{
	0x0001: "C", 0x0002: "C", 0x000c: "C", 0x001d: "C", 0x002c: "C",
	0x0004: "C++", 0x0019: "C++", 0x001a: "C++", 0x0021: "C++", 0x002a: "C++", 0x002b: "C++",
	0x0003: "Ada", 0x000d: "Ada", 0x002e: "Ada", 0x002f: "Ada",
	0x0005: "COBOL", 0x0006: "COBOL",
	0x0007: "Fortran", 0x0008: "Fortran", 0x000e: "Fortran", 0x0022: "Fortran", 0x0023: "Fortran", 0x002d: "Fortran",
	0x0009: "Pascal",
	0x000a: "Modula-2",
	0x000b: "Java",
	0x0010: "Objective-C",
	0x0011: "Objective-C++",
	0x0012: "UPC",
	0x0013: "D",
	0x0014: "Python",
	0x0015: "OpenCL",
	0x0016: "Go",
	0x0017: "Modula-3",
	0x0018: "Haskell",
	0x001b: "OCaml",
	0x001c: "Rust",
	0x001e: "Swift",
	0x001f: "Julia",
	0x0020: "Dylan",
	0x0024: "RenderScript",
	0x0025: "BLISS",
	0x0026: "Kotlin",
	0x0027: "Zig",
	0x0028: "Crystal",
	0x0030: "HIP",
	0x0031: "Assembly", 0x8001: "Assembly",
	0x0032: "C#",
	0x0033: "Mojo",
	0x0034: "GLSL",
	0x0035: "GLSL ES",
	0x0036: "HLSL",
	0x0037: "OpenCL C++",
	0x0038: "C++ for OpenCL",
	0x0039: "SYCL",
	0x003d: "Metal",
	0x0040: "Ruby",
	0x0041: "Move",
	0x0042: "Hylo",
	0xb000: "Delphi",
}

// dwarfLangName maps a DW_LANG_* constant to a readable name, or "" if unknown.
func dwarfLangName(v int64) string {
	return dwarfLangNames[v]
}

// DwarfLanguageNames returns the distinct, sorted set of source-language names
// exex can identify from DWARF. Exposed so the syntax package's coverage test can
// verify each has a curated highlighter (or an explicit minimal-fallback).
func DwarfLanguageNames() []string {
	seen := map[string]bool{}
	var out []string
	for _, name := range dwarfLangNames {
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}
