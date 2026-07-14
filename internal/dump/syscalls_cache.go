package dump

// Scanning cache-resident system libraries for syscall sites. On macOS the
// libraries that actually contain the `svc` instructions (chiefly
// libsystem_kernel) are not standalone files — they live in the dyld shared
// cache — so `syscalls-full` used to report nothing for a Mac binary: the app's
// own code makes no direct syscalls, and its one visible dependency
// (libSystem.B) is a re-export umbrella with no code. cacheScanner extracts
// those libraries straight out of the host cache so their syscalls surface.

import (
	"os"

	"github.com/shellcell/exex/internal/binfile"
	"github.com/shellcell/exex/internal/dyldcache"
)

// cacheScanner lazily opens the host dyld shared cache matching a binary's
// architecture and extracts its images as parseable Mach-O files, memoising by
// install path so a diamond dependency is extracted once.
type cacheScanner struct {
	arch     string
	opened   bool
	cache    *dyldcache.Cache
	files    map[string]*binfile.File
	openErr  bool
	openHook func(archName string) (*dyldcache.Cache, bool) // overridable in tests
}

func newCacheScanner(arch string) *cacheScanner {
	return &cacheScanner{arch: arch, files: map[string]*binfile.File{}}
}

// ensure opens the host cache on first need. It returns false (once) when no
// cache is present, so callers fall back to the "can't be scanned" note.
func (cs *cacheScanner) ensure() bool {
	if cs.opened {
		return cs.cache != nil
	}
	cs.opened = true
	open := cs.openHook
	if open == nil {
		open = openHostCache
	}
	c, ok := open(cs.arch)
	if !ok {
		cs.openErr = true
		return false
	}
	cs.cache = c
	return true
}

// openHostCache locates and opens the running system's dyld shared cache for
// architecture arch.
func openHostCache(arch string) (*dyldcache.Cache, bool) {
	path, ok := dyldcache.HostCachePath(arch, func(p string) bool {
		_, err := os.Stat(p)
		return err == nil
	})
	if !ok {
		return nil, false
	}
	c, err := dyldcache.Open(path)
	if err != nil {
		return nil, false
	}
	return c, true
}

// file extracts and parses the cache image named by lib (an install path or a
// unique basename). ok is false when the cache is absent, the image isn't in it,
// or extraction/parse fails — the caller then records a note.
func (cs *cacheScanner) file(lib string) (*binfile.File, bool) {
	if !cs.ensure() {
		return nil, false
	}
	im, found := cs.cache.FindImage(lib)
	if !found {
		return nil, false
	}
	if f, ok := cs.files[im.Path]; ok {
		return f, f != nil
	}
	buf, err := cs.cache.ExtractImage(im)
	if err != nil {
		cs.files[im.Path] = nil
		return nil, false
	}
	f, err := binfile.OpenBytes(im.Path, buf)
	if err != nil {
		cs.files[im.Path] = nil
		return nil, false
	}
	cs.files[im.Path] = f
	return f, true
}

// deps returns the install paths a cache image itself depends on, so the scan
// can follow the app → libSystem.B → libsystem_kernel chain.
func (cs *cacheScanner) deps(f *binfile.File) []string {
	if f == nil || f.Info == nil {
		return nil
	}
	return f.Info.DynamicLibs
}

// available reports whether a host cache could be opened (for the summary note).
func (cs *cacheScanner) available() bool {
	return cs.opened && cs.cache != nil
}

// close releases the mapped cache. The extracted *binfile.File buffers are
// independent copies, so sites collected from them stay valid afterwards.
func (cs *cacheScanner) close() {
	if cs.cache != nil {
		cs.cache.Close()
		cs.cache = nil
	}
	cs.files = nil
}
