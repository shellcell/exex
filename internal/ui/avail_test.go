package ui

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rabarbra/exex/internal/binfile"
)

func TestLibAvailClassification(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "libreal.dylib")
	if err := os.WriteFile(real, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := &Model{file: &binfile.File{Path: filepath.Join(dir, "bin"), Info: &binfile.Info{}}}
	cases := []struct {
		lib  string
		want availKind
	}{
		{real, libOnDisk},
		{"/usr/lib/libSystem.B.dylib", libInCache}, // dyld shared cache
		{"/no/such/path/libx.dylib", libMissing},
	}
	for _, c := range cases {
		if got := m.libAvail(c.lib); got != c.want {
			t.Errorf("libAvail(%q) = %d, want %d", c.lib, got, c.want)
		}
	}
}

func TestSourcesAvailFilter(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "here.c")
	if err := os.WriteFile(present, []byte("int main(){}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "gone.c")
	m := &Model{
		file:         binfile.NewRawFile(nil),
		sourcesState: sourcesState{sourcesFiles: []string{present, missing}},
	}
	m.file.Path = filepath.Join(dir, "bin")
	m.sourcesFilter = newPromptInput("", "/ ")

	count := func(a availFilter) int {
		m.sourcesAvail = a
		m.recomputeSourceFiles()
		return len(m.sourcesFiltered)
	}
	if got := count(availAll); got != 2 {
		t.Fatalf("all = %d, want 2", got)
	}
	if got := count(availPresent); got != 1 {
		t.Fatalf("present = %d, want 1", got)
	}
	if got := count(availMissing); got != 1 {
		t.Fatalf("missing = %d, want 1", got)
	}
}
