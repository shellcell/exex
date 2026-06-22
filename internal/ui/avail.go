package ui

import "github.com/rabarbra/exex/internal/explorer"

// availFilter is the availability lens applied to the Sources and Libs lists.
type availFilter uint8

const (
	availAll     availFilter = iota // show everything
	availPresent                    // sources: file on disk; libs: openable on disk
	availMissing                    // sources: not found on disk
	availCache                      // libs: served from the dyld shared cache
)

// availKind classifies one library's on-disk availability.
type availKind uint8

const (
	libOnDisk  availKind = iota // resolves to a real file we can open
	libInCache                  // a system lib served from the dyld shared cache
	libMissing                  // neither — can't be located
)

// libAvail classifies a library path, caching the (filesystem-touching) result.
func (m *Model) libAvail(lib string) availKind {
	if m.libsAvailKind == nil {
		m.libsAvailKind = map[string]availKind{}
	}
	if k, ok := m.libsAvailKind[lib]; ok {
		return k
	}
	var k availKind
	switch {
	case func() bool { _, ok := explorer.ResolveLibPath(lib, m.file.Path, m.file.Info, nil); return ok }():
		k = libOnDisk
	case explorer.IsDyldSharedCacheLib(lib):
		k = libInCache
	default:
		k = libMissing
	}
	m.libsAvailKind[lib] = k
	return k
}

// availLabel is the short status-line label for an availability filter, given the
// per-view name for the "present" state.
func availLabel(f availFilter) string {
	switch f {
	case availPresent:
		return "present"
	case availMissing:
		return "missing"
	case availCache:
		return "cache"
	default:
		return "all"
	}
}
