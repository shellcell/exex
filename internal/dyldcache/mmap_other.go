//go:build !darwin && !linux

package dyldcache

import "os"

// mapFile falls back to reading the whole file where mmap isn't wired up. dyld
// shared caches are a macOS/iOS artefact, so this path exists only to keep the
// package building on other platforms.
func mapFile(path string) ([]byte, func() error, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	return data, func() error { return nil }, nil
}
