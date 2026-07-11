//go:build darwin || linux

package dyldcache

import (
	"fmt"
	"os"
	"syscall"
)

// mapFile memory-maps path read-only. Shared caches are multi-gigabyte, so mmap
// (paged in on access) is essential — reading them into the heap would be
// prohibitive when the reader only touches the header, image table and a few
// image regions.
func mapFile(path string) ([]byte, func() error, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	size := fi.Size()
	if size <= 0 {
		return nil, nil, fmt.Errorf("dyld cache %s: empty file", path)
	}
	data, err := syscall.Mmap(int(f.Fd()), 0, int(size), syscall.PROT_READ, syscall.MAP_PRIVATE)
	if err != nil {
		return nil, nil, fmt.Errorf("mmap %s: %w", path, err)
	}
	return data, func() error { return syscall.Munmap(data) }, nil
}
