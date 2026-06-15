//go:build unix && !darwin

package binfile

import "golang.org/x/sys/unix"

// Linux/BSD don't enforce per-process code-signing on mapped pages, so a plain
// private read-only mapping of any binary is safe.
const mmapFlags = unix.MAP_PRIVATE

func mapFile(path string) (data []byte, closer func() error, err error) {
	return mmapShared(path)
}
