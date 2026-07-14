package ui

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/shellcell/exex/internal/binfile"
	"github.com/shellcell/exex/internal/ui/view"
	"github.com/shellcell/exex/internal/ui/views/sources"
)

func TestSourcesAvailFilter(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "here.c")
	if err := os.WriteFile(present, []byte("int main(){}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "gone.c")
	m := &Model{
		file:    binfile.NewRawFile(nil),
		sources: sources.State{Files: []string{present, missing}},
	}
	m.file.Path = filepath.Join(dir, "bin")
	m.sources.Filter = newPromptInput("", "/ ")

	count := func(a view.AvailFilter) int {
		m.sources.Avail = a
		m.sources.Recompute(m.viewContext())
		return len(m.sources.Filtered)
	}
	if got := count(view.AvailAll); got != 2 {
		t.Fatalf("all = %d, want 2", got)
	}
	if got := count(view.AvailPresent); got != 1 {
		t.Fatalf("present = %d, want 1", got)
	}
	if got := count(view.AvailMissing); got != 1 {
		t.Fatalf("missing = %d, want 1", got)
	}
}
