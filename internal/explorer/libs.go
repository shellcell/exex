package explorer

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/shellcell/exex/internal/binfile"
)

// FileExists abstracts filesystem probes for tests and alternate resolvers.
type FileExists func(string) bool

// ResolveLibPath resolves a dynamic-library reference to an on-disk path.
// Mach-O @loader_path, @executable_path, and @rpath tokens are expanded using
// the binary path and loader-provided runpath/rpath entries.
func ResolveLibPath(lib, binaryPath string, info *binfile.Info, exists FileExists) (string, bool) {
	if exists == nil {
		exists = diskFileExists
	}
	loaderDir := filepath.Dir(binaryPath)
	subst := func(p string) string {
		p = strings.ReplaceAll(p, "@loader_path", loaderDir)
		p = strings.ReplaceAll(p, "@executable_path", loaderDir)
		return p
	}

	var rpaths []string
	if info != nil {
		rpaths = append(rpaths, info.RunPath...)
		rpaths = append(rpaths, info.RPath...)
	}

	if rest, ok := strings.CutPrefix(lib, "@rpath/"); ok {
		for _, rp := range rpaths {
			if cand := filepath.Join(subst(rp), rest); exists(cand) {
				return cand, true
			}
		}
		return "", false
	}
	if strings.HasPrefix(lib, "@loader_path") || strings.HasPrefix(lib, "@executable_path") {
		if cand := subst(lib); exists(cand) {
			return cand, true
		}
		return "", false
	}

	if exists(lib) {
		return lib, true
	}

	base := filepath.Base(lib)
	for _, rp := range rpaths {
		if cand := filepath.Join(subst(rp), base); exists(cand) {
			return cand, true
		}
	}
	for _, dir := range defaultLibDirs {
		if cand := filepath.Join(dir, base); exists(cand) {
			return cand, true
		}
	}
	return "", false
}

// IsDyldSharedCacheLib reports whether lib is normally served from Apple's dyld
// shared cache instead of as a standalone user-openable file.
func IsDyldSharedCacheLib(lib string) bool {
	return strings.HasPrefix(lib, "/usr/lib/") ||
		strings.HasPrefix(lib, "/System/Library/") ||
		strings.HasPrefix(lib, "/Library/Apple/")
}

// defaultLibDirs are fallback ELF-style library search directories.
var defaultLibDirs = []string{
	"/lib",
	"/usr/lib",
	"/lib64",
	"/usr/lib64",
	"/usr/local/lib",
	"/lib/x86_64-linux-gnu",
	"/usr/lib/x86_64-linux-gnu",
	"/lib/aarch64-linux-gnu",
	"/usr/lib/aarch64-linux-gnu",
}

// diskFileExists reports whether p names an existing non-directory file.
func diskFileExists(p string) bool {
	if p == "" {
		return false
	}
	if st, err := os.Stat(p); err == nil && !st.IsDir() {
		return true
	}
	return false
}
