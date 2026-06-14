package binfile

import (
	"os/exec"
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

// isSwiftMangled reports whether name uses Swift's mangling scheme, which the
// Itanium/Rust demangler doesn't cover.
func isSwiftMangled(name string) bool {
	for _, p := range []string{"$s", "_$s", "$S", "_$S"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// demangleSwift resolves Swift-mangled names that the in-process demangler left
// alone, by piping them through swift-demangle in a single batch. Best-effort:
// it's a no-op when the tool isn't installed or there are no Swift symbols.
func (f *File) demangleSwift() {
	var idx []int
	var names []string
	for i := range f.Symbols {
		if f.Symbols[i].Demangled == "" && isSwiftMangled(f.Symbols[i].Name) {
			idx = append(idx, i)
			names = append(names, f.Symbols[i].Name)
		}
	}
	if len(names) == 0 {
		return
	}
	out := swiftDemangleBatch(names)
	for _, i := range idx {
		if d, ok := out[f.Symbols[i].Name]; ok {
			f.Symbols[i].Demangled = d
		}
	}
}

func swiftDemangleBatch(names []string) map[string]string {
	var cmd *exec.Cmd
	if p, err := exec.LookPath("swift-demangle"); err == nil {
		cmd = exec.Command(p)
	} else if xc, err := exec.LookPath("xcrun"); err == nil {
		cmd = exec.Command(xc, "swift-demangle")
	} else {
		return nil
	}
	// In stdin mode swift-demangle substitutes mangled names inline, so one
	// symbol per line yields one demangled name per line.
	cmd.Stdin = strings.NewReader(strings.Join(names, "\n") + "\n")
	outBytes, err := cmd.Output()
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimRight(string(outBytes), "\n"), "\n")
	if len(lines) != len(names) {
		return nil
	}
	res := make(map[string]string, len(names))
	for i, n := range names {
		if d := strings.TrimSpace(lines[i]); d != "" && d != n {
			res[n] = d
		}
	}
	return res
}
