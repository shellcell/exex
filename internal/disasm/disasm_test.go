package disasm

import (
	"strings"
	"testing"
)

// TestAMD64DecodesCommonPrologue decodes a hand-assembled x86-64 function
// prologue. Keeping the bytes inline makes the test independent of any host
// compiler or object-file container (the explorer runs on both ELF and
// Mach-O hosts, so reaching for a real binary here would be fragile).
func TestAMD64DecodesCommonPrologue(t *testing.T) {
	d, err := For(ArchAMD64)
	if err != nil {
		t.Fatal(err)
	}
	if d.Name() != "x86-64" {
		t.Fatalf("unexpected disassembler: %s", d.Name())
	}

	// push %rbp; mov %rsp,%rbp; xor %eax,%eax; pop %rbp; ret
	code := []byte{0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3}
	insts := Range(d, code, 0x1000, 0)
	if len(insts) == 0 {
		t.Fatal("no instructions decoded")
	}
	var joined string
	for _, i := range insts {
		joined += " " + i.Text
	}
	if !strings.Contains(joined, "push") || !strings.Contains(joined, "mov") {
		t.Fatalf("expected push/mov in decoded stream, got:%s", joined)
	}

	// The classifier should flag the trailing ret.
	if got := insts[len(insts)-1].Class; got != ClassRet {
		t.Fatalf("expected last instruction classified as ret, got %v", got)
	}
}

func TestUnsupportedArch(t *testing.T) {
	if _, err := For(ArchUnknown); err == nil {
		t.Fatal("expected error for unknown arch")
	}
}
