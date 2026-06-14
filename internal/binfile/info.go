package binfile

import (
	"strings"
)

// Info holds dynamic-linking and identity bits collected at Open() time.
// Everything is best-effort: missing data leaves the corresponding field zero.
// The set of fields is format-neutral; each loader fills what its container
// can provide (e.g. Mach-O has no .interp, so Interp stays empty there).
type Info struct {
	Interp       string   // program interpreter / dynamic linker
	DynamicLibs  []string // shared libraries this binary depends on
	RPath        []string // rpath search entries (legacy DT_RPATH)
	RunPath      []string // runpath search entries (DT_RUNPATH / LC_RPATH)
	SoName       string   // own install name / SONAME if this is a library
	BuildID      string   // hex build-id / UUID
	Stripped     bool     // no symbol table present
	StaticLinked bool     // no interpreter / no dynamic libs
	Libc         LibcInfo

	// Overview / triage (format-neutral; filled by computeOverview).
	FileSize uint64 // on-disk size in bytes
	MappedLo uint64 // lowest mapped virtual address
	MappedHi uint64 // end of the highest mapped section
	CodeSize uint64 // sum of executable section sizes

	// Layout details filled by the format loaders.
	WordBits  int    // 32 or 64
	ByteOrder string // "little-endian" / "big-endian"
	Segments  int    // ELF program headers / Mach-O load commands

	// Hardening.
	PIE     Tristate
	NX      Tristate // non-executable stack
	RELRO   string   // "none" | "partial" | "full" (ELF only)
	Canary  bool     // stack-protector present
	Fortify bool     // _FORTIFY_SOURCE (*_chk) present

	// Mach-O specifics.
	CodeSigned bool
	Encrypted  bool
	MinOS      string // e.g. "macOS 13.0"
	SDK        string // e.g. "13.1"

	// Toolchain / provenance.
	Compiler   string // .comment / "Apple clang version …"
	GoVersion  string // from Go build info
	GoModule   string
	GoVCS      string // VCS revision (+ " (dirty)")
	SourceLang string // from DWARF, else inferred from symbols
}

// LibcInfo identifies the C runtime the binary links against.
type LibcInfo struct {
	Kind    string // "glibc" | "musl" | "uClibc" | "bionic" | "libSystem" | "unknown" | "none"
	Source  string // how we identified it ("interp", "needed", "symbol", "rodata-fingerprint")
	Version string // optional, e.g. "2.35"
}

// Tristate is a yes/no/unknown flag for hardening features we can't always
// determine.
type Tristate uint8

const (
	TriUnknown Tristate = iota
	TriYes
	TriNo
)

func (t Tristate) String() string {
	switch t {
	case TriYes:
		return "yes"
	case TriNo:
		return "no"
	}
	return "unknown"
}

// splitColon mirrors the way the loader splits rpath/runpath strings.
func splitColon(v []string) []string {
	var out []string
	for _, s := range v {
		for _, part := range strings.Split(s, ":") {
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

func align4(n int) int {
	if r := n & 3; r != 0 {
		return n + (4 - r)
	}
	return n
}

// extractGlibcVersion pulls "release version X.Y" from a glibc banner like
// "GNU C Library (Ubuntu GLIBC ...) stable release version 2.35.".
func extractGlibcVersion(s []byte) string {
	end := len(s)
	if end > 512 {
		end = 512
	}
	chunk := string(s[:end])
	const marker = "release version "
	i := strings.Index(chunk, marker)
	if i < 0 {
		return ""
	}
	rest := chunk[i+len(marker):]
	j := strings.IndexAny(rest, ".\n,)")
	for j >= 0 && j+1 < len(rest) && rest[j] == '.' && rest[j+1] >= '0' && rest[j+1] <= '9' {
		k := strings.IndexAny(rest[j+1:], ".\n,)")
		if k < 0 {
			j = -1
			break
		}
		j = j + 1 + k
	}
	if j < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:j])
}

func extractMuslVersion(data []byte) string {
	idx := indexBytes(data, "musl libc")
	if idx < 0 {
		return ""
	}
	end := idx + 200
	if end > len(data) {
		end = len(data)
	}
	tail := string(data[idx:end])
	for i := 0; i < len(tail)-3; i++ {
		if tail[i] >= '0' && tail[i] <= '9' && i+1 < len(tail) && tail[i+1] == '.' {
			j := i
			for j < len(tail) && (tail[j] == '.' || (tail[j] >= '0' && tail[j] <= '9')) {
				j++
			}
			return tail[i:j]
		}
	}
	return ""
}

func indexBytes(haystack []byte, needle string) int {
	return strings.Index(string(haystack), needle)
}
