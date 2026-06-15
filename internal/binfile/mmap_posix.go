//go:build unix

package binfile

import (
	"os"

	"golang.org/x/sys/unix"
)

// mmapShared memory-maps path read-only using the platform's mmapFlags. The
// returned slice aliases the mapping and stays valid until closer is called, so
// keep it for the File's lifetime. Empty files and any mmap failure fall back to
// a plain read.
func mmapShared(path string) (data []byte, closer func() error, err error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer fh.Close()
	fi, err := fh.Stat()
	if err != nil {
		return nil, nil, err
	}
	size := fi.Size()
	if size <= 0 {
		return readWhole(path)
	}
	b, err := unix.Mmap(int(fh.Fd()), 0, int(size), unix.PROT_READ, mmapFlags)
	if err != nil {
		return readWhole(path)
	}
	return b, func() error { return unix.Munmap(b) }, nil
}

// readWhole is the non-mmap fallback: read the file into the heap. The closer is
// a no-op.
func readWhole(path string) (data []byte, closer func() error, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	return b, func() error { return nil }, nil
}
