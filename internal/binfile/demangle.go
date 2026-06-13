package binfile

import (
	"strings"

	"github.com/ianlancetaylor/demangle"
)

// demangleName returns a human-readable form of a mangled C++/Rust symbol, or
// "" when name isn't a recognised mangling. Mach-O prefixes the platform's C
// symbols with an extra underscore, so an Itanium/Rust symbol shows up as
// "__Z…" / "__R…"; we drop that leading underscore before demangling.
func demangleName(name string) string {
	if name == "" {
		return ""
	}
	cand := name
	if strings.HasPrefix(name, "__Z") || strings.HasPrefix(name, "__R") {
		cand = name[1:]
	}
	if !strings.HasPrefix(cand, "_Z") && !strings.HasPrefix(cand, "_R") {
		return ""
	}
	d := demangle.Filter(cand)
	if d == "" || d == cand {
		return ""
	}
	return d
}
