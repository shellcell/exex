package dump

import (
	"os"
	"strings"
	"testing"

	"github.com/rabarbra/exex/internal/binfile"
)

func TestRelocsDump(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip("no test executable path")
	}
	f, err := binfile.Open(exe)
	if err != nil {
		t.Skipf("open self: %v", err)
	}
	defer f.Close()
	out := Relocs(f)
	// Either a populated table (with a header) or the explained empty case.
	if strings.Contains(out, "Offset") {
		if !strings.Contains(out, "Type") {
			t.Errorf("relocs table missing Type column:\n%s", out)
		}
	} else if !strings.Contains(out, "no relocations") {
		t.Errorf("unexpected relocs output:\n%s", out)
	}
}
