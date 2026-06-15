//go:build darwin

package binfile

import "golang.org/x/sys/unix"

// On macOS the kernel enforces code-signing on mmap'd pages of signed Mach-O
// binaries and SIGKILLs the reader (uncatchable). MAP_RESILIENT_CODESIGN opts
// out of that: a page that fails the code-signing check reads as zero-fill
// instead of killing the process. Valid (untampered) signed binaries still read
// correctly — only tampered pages would zero-fill — so we can map any binary,
// signed or not, including system frameworks and notarised apps.
const mmapFlags = unix.MAP_PRIVATE | unix.MAP_RESILIENT_CODESIGN

func mapFile(path string) (data []byte, closer func() error, err error) {
	return mmapShared(path)
}
