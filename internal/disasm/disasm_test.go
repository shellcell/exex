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

func TestResolveRelTargets(t *testing.T) {
	cases := map[string]string{
		"bl .+0xfffffffffffffc58": "bl 0xc58",     // negative (two's complement) → 0x1000-0x3a8
		"b .+0x40":                "b 0x1040",     // forward
		"b.gt .-0x10":             "b.gt 0xff0",   // explicit minus
		"mov x0, #0x5":            "mov x0, #0x5", // nothing to rewrite
	}
	for in, want := range cases {
		if got := resolveRelTargets(in, 0x1000); got != want {
			t.Errorf("resolveRelTargets(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAMD64RangeRecoversFromDecoderPanic(t *testing.T) {
	d, err := For(ArchAMD64)
	if err != nil {
		t.Fatal(err)
	}
	// These bytes have triggered x/arch x86 AVX decoder panics in the wild when
	// decoding from a mid-stream offset. Range must degrade them to bad bytes
	// instead of letting the panic escape into the UI.
	code := []byte{0xc5, 0xf5, 0x00, 0x00, 0x62, 0x61, 0x7d, 0x08, 0x00, 0x00}
	insts := Range(d, code, 0x1000, 0)
	if len(insts) == 0 {
		t.Fatal("expected placeholder instructions for undecodable bytes")
	}
	if insts[0].Text != "(bad)" {
		t.Fatalf("first instruction = %q, want (bad)", insts[0].Text)
	}
}

func TestClassifyBranches(t *testing.T) {
	cond := []string{"cbz x0, 0x100", "cbnz w1, 0x100", "tbz x0, #1, 0x100", "tbnz x0, #1, 0x100", "b.gt 0x100", "je 0x100"}
	for _, s := range cond {
		if c := Classify(s); c != ClassJumpCond {
			t.Errorf("Classify(%q)=%v, want ClassJumpCond", s, c)
		}
	}
	if c := Classify("b 0x100"); c != ClassJumpUnc {
		t.Errorf("Classify(b)=%v, want ClassJumpUnc", c)
	}
}
