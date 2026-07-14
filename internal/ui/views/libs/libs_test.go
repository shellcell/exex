package libs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/shellcell/exex/internal/binfile"
	"github.com/shellcell/exex/internal/ui/view"
)

func TestLibAvailClassification(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "libreal.dylib")
	if err := os.WriteFile(real, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := view.Context{File: &binfile.File{Path: filepath.Join(dir, "bin"), Info: &binfile.Info{}}}
	st := &State{}
	cases := []struct {
		lib  string
		want availKind
	}{
		{real, libOnDisk},
		{"/usr/lib/libSystem.B.dylib", libInCache}, // dyld shared cache
		{"/no/such/path/libx.dylib", libMissing},
	}
	for _, c := range cases {
		if got := st.libAvail(ctx, c.lib); got != c.want {
			t.Errorf("libAvail(%q) = %d, want %d", c.lib, got, c.want)
		}
	}
}
