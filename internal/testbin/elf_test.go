package testbin_test

import (
	"bytes"
	"debug/elf"
	"testing"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/testbin"
)

// TestTinyELF64IsDeterministic is the property the golden-frame tests rest on.
func TestTinyELF64IsDeterministic(t *testing.T) {
	if !bytes.Equal(testbin.TinyELF64(), testbin.TinyELF64()) {
		t.Fatal("TinyELF64 is not byte-for-byte reproducible")
	}
}

// TestTinyELF64ParsesAsELF checks the fixture against the standard library
// before asking exex to read it, so a malformed header fails here rather than as
// a confusing golden-frame diff.
func TestTinyELF64ParsesAsELF(t *testing.T) {
	f, err := elf.NewFile(bytes.NewReader(testbin.TinyELF64()))
	if err != nil {
		t.Fatalf("debug/elf rejected the fixture: %v", err)
	}
	defer f.Close()

	if f.Class != elf.ELFCLASS64 || f.Machine != elf.EM_X86_64 || f.Type != elf.ET_EXEC {
		t.Errorf("got class=%v machine=%v type=%v", f.Class, f.Machine, f.Type)
	}
	for _, name := range []string{".text", ".rodata", ".data", ".symtab", ".strtab", ".shstrtab"} {
		if f.Section(name) == nil {
			t.Errorf("missing section %s", name)
		}
	}
	syms, err := f.Symbols()
	if err != nil {
		t.Fatalf("Symbols: %v", err)
	}
	if len(syms) < 3 {
		t.Fatalf("got %d symbols, want _start/helper/msg", len(syms))
	}
}

// TestTinyELF64OpensInBinfile pins the parts the UI actually renders: an entry
// point inside the executable image, symbols, sections, and extractable strings.
func TestTinyELF64OpensInBinfile(t *testing.T) {
	f, err := binfile.Open(testbin.WriteTinyELF64(t))
	if err != nil {
		t.Fatalf("binfile.Open: %v", err)
	}
	defer f.Close()

	if f.Format != binfile.FormatELF {
		t.Errorf("format = %v, want ELF", f.Format)
	}
	if f.Entry() == 0 {
		t.Error("entry is zero")
	}
	if _, ok := f.ExecImage().PosForAddr(f.Entry()); !ok {
		t.Errorf("entry 0x%x is not inside the executable image", f.Entry())
	}
	if _, ok := f.SymbolAt(f.Entry()); !ok {
		t.Error("no symbol covers the entry point")
	}
	if len(f.Sections) == 0 {
		t.Error("no sections")
	}
	if len(f.Strings()) == 0 {
		t.Error("no strings extracted from .rodata")
	}
}
