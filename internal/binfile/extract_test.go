package binfile

import (
	"os"
	"testing"
)

// openSelf opens the running test binary, skipping when it can't be read.
func openSelf(t *testing.T) *File {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("no executable path: %v", err)
	}
	f, err := Open(exe)
	if err != nil {
		t.Skipf("open self: %v", err)
	}
	return f
}

func TestRawHeaderELF(t *testing.T) {
	f := openSelf(t)
	defer f.Close()
	if f.Format != FormatELF {
		t.Skip("self is not ELF")
	}
	fields := f.RawHeader()
	if len(fields) == 0 {
		t.Fatal("RawHeader returned no fields for an ELF")
	}
	want := map[string]bool{"e_ident": false, "Type": false, "Machine": false, "Program headers": false}
	for _, fl := range fields {
		if _, ok := want[fl.Name]; ok {
			want[fl.Name] = true
		}
		if fl.Name == "e_ident" && len(fl.Value) < 8 {
			t.Errorf("e_ident value too short: %q", fl.Value)
		}
	}
	for k, seen := range want {
		if !seen {
			t.Errorf("RawHeader missing field %q", k)
		}
	}
}

func TestRelocationsELF(t *testing.T) {
	f := openSelf(t)
	defer f.Close()
	if f.Format != FormatELF {
		t.Skip("self is not ELF")
	}
	rels := f.Relocations()
	// A dynamically or position-independently linked Go binary carries dynamic
	// relocations; a fully static non-PIE one may not, so only check coherence.
	for i, r := range rels {
		if r.Type == "" {
			t.Errorf("reloc %d has empty type", i)
		}
		if i > 200 {
			break
		}
	}
	// Relocations() must be idempotent (built once, lazily).
	if n2 := len(f.Relocations()); n2 != len(rels) {
		t.Errorf("Relocations not stable: %d then %d", len(rels), n2)
	}
}
