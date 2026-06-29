// Package syscalls maps system-call numbers to names per OS/architecture. The
// built-in tables are embedded text files named "<os>-<arch>" (e.g. linux-amd64,
// darwin-arm64), one "<number> <name>" per line. A user can supply additional or
// replacement tables in the same format from a directory (LoadOverrideDir), which
// take precedence — so an incomplete built-in table can always be extended without
// rebuilding.
package syscalls

import (
	"bufio"
	"bytes"
	"embed"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/rabarbra/exex/internal/arch"
)

//go:embed tables
var builtinFS embed.FS

// Table maps a syscall number to its name for one os/arch.
type Table map[int64]string

var (
	mu       sync.Mutex
	builtin  = map[string]Table{} // lazily parsed built-in tables, keyed "os-arch"
	override = map[string]Table{} // user-supplied tables (LoadOverrideDir), higher priority
)

// Key returns the "<os>-<arch>" table key for a container format and architecture.
// Mach-O ⇒ darwin, PE ⇒ windows, everything else ⇒ linux (the dominant ELF OS).
func Key(format string, a arch.Arch) string {
	goos := "linux"
	switch format {
	case "Mach-O":
		goos = "darwin"
	case "PE":
		goos = "windows"
	}
	return goos + "-" + archName(a)
}

func archName(a arch.Arch) string {
	switch a {
	case arch.ArchAMD64:
		return "amd64"
	case arch.ArchX86:
		return "386"
	case arch.ArchARM64:
		return "arm64"
	case arch.ArchARM:
		return "arm"
	case arch.ArchRISCV64:
		return "riscv64"
	case arch.ArchPPC64, arch.ArchPPC64LE:
		return "ppc64"
	case arch.ArchS390X:
		return "s390x"
	case arch.ArchLoong64:
		return "loong64"
	}
	return "unknown"
}

// Name resolves num to a syscall name for the os/arch table key, consulting any
// user override first, then the built-in table. Darwin numbers carry a class in
// their high byte (0x2000000 = BSD/Unix on x86-64); it is masked off before lookup.
func Name(key string, num int64) (string, bool) {
	if strings.HasPrefix(key, "darwin-") && num >= 0x1000000 {
		num &= 0x00ffffff
	}
	mu.Lock()
	defer mu.Unlock()
	if t := override[key]; t != nil {
		if n, ok := t[num]; ok {
			return n, true
		}
	}
	t := builtinTable(key)
	if t == nil {
		return "", false
	}
	n, ok := t[num]
	return n, ok
}

// Available reports whether any table (built-in or override) covers key.
func Available(key string) bool {
	mu.Lock()
	defer mu.Unlock()
	return override[key] != nil || builtinTable(key) != nil
}

// builtinTable returns the parsed built-in table for key (mu held).
func builtinTable(key string) Table {
	if t, ok := builtin[key]; ok {
		return t
	}
	data, err := builtinFS.ReadFile("tables/" + key)
	if err != nil {
		builtin[key] = nil
		return nil
	}
	t := parseTable(data)
	builtin[key] = t
	return t
}

// LoadOverrideDir loads every "<os>-<arch>" table file in dir as a user override
// (replacing/extending the built-ins). Returns the number of tables loaded.
func LoadOverrideDir(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	mu.Lock()
	defer mu.Unlock()
	n := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		override[e.Name()] = parseTable(data)
		n++
	}
	return n, nil
}

// parseTable parses "<number> <name>" lines (number in any Go base; '#' comments
// and blank lines skipped) into a Table.
func parseTable(data []byte) Table {
	t := Table{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.IndexAny(line, " \t")
		if i < 0 {
			continue
		}
		num, err := strconv.ParseInt(strings.TrimSpace(line[:i]), 0, 64)
		if err != nil {
			continue
		}
		if name := strings.TrimSpace(line[i+1:]); name != "" {
			t[num] = name
		}
	}
	return t
}
