package testbin

import (
	"os"
	"path/filepath"
	"testing"
)

// WriteTinyELF64 writes the fixture into t.TempDir() and returns its path.
func WriteTinyELF64(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tiny.elf")
	if err := os.WriteFile(path, TinyELF64(), 0o755); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}
