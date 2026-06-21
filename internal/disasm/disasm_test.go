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

// TestRangeFuncStreamsAndStops checks the streaming primitive: it yields the
// same instructions as Range, and stops early when the callback returns false
// (the property the disassembly dump relies on for `| head`).
func TestRangeFuncStreamsAndStops(t *testing.T) {
	d, err := For(ArchAMD64)
	if err != nil {
		t.Fatal(err)
	}
	code := []byte{0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3}

	var streamed []Inst
	RangeFunc(d, code, 0x1000, func(in Inst) bool {
		streamed = append(streamed, in)
		return true
	})
	if want := Range(d, code, 0x1000, 0); len(streamed) != len(want) {
		t.Fatalf("RangeFunc yielded %d, Range yielded %d", len(streamed), len(want))
	}

	n := 0
	RangeFunc(d, code, 0x1000, func(Inst) bool {
		n++
		return n < 2 // stop after the second instruction
	})
	if n != 2 {
		t.Fatalf("RangeFunc kept going after stop: %d", n)
	}
}

func TestUnsupportedArch(t *testing.T) {
	if _, err := For(ArchUnknown); err == nil {
		t.Fatal("expected error for unknown arch")
	}
}

func TestForSupportedArchitecturesDecodeNop(t *testing.T) {
	tests := []struct {
		arch Arch
		name string
		code []byte
	}{
		{arch: ArchAMD64, name: "x86-64", code: []byte{0x90}},
		{arch: ArchX86, name: "x86", code: []byte{0x90}},
		{arch: ArchARM64, name: "arm64", code: []byte{0x1f, 0x20, 0x03, 0xd5}},
		{arch: ArchRISCV64, name: "riscv64", code: []byte{0x13, 0x00, 0x00, 0x00}},
		{arch: ArchARM, name: "arm", code: []byte{0x00, 0xf0, 0x8e, 0xe2}},         // add pc, lr, #0
		{arch: ArchPPC64, name: "ppc64", code: []byte{0x4e, 0x80, 0x00, 0x20}},     // blr (big-endian)
		{arch: ArchPPC64LE, name: "ppc64le", code: []byte{0x20, 0x00, 0x80, 0x4e}}, // blr (little-endian)
		{arch: ArchS390X, name: "s390x", code: []byte{0x07, 0xfe}},                 // br %r14
		{arch: ArchLoong64, name: "loong64", code: []byte{0x20, 0x00, 0x00, 0x4c}}, // ret
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := For(tt.arch)
			if err != nil {
				t.Fatal(err)
			}
			if got := d.Name(); got != tt.name {
				t.Fatalf("Name = %q, want %q", got, tt.name)
			}
			inst, err := d.Decode(tt.code, 0x1000)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if inst.Addr != 0x1000 || len(inst.Bytes) == 0 || inst.Text == "" {
				t.Fatalf("decoded instruction = %#v", inst)
			}
		})
	}
}

func TestClassifyBLRAmbiguity(t *testing.T) {
	// PowerPC "blr" (no operand) is branch-to-link-register, i.e. a return;
	// ARM64 "blr <reg>" is an indirect call. Classify must tell them apart.
	if c := Classify("blr"); c != ClassRet {
		t.Errorf("Classify(bare blr) = %v, want ClassRet", c)
	}
	if c := Classify("blr x16"); c != ClassCall {
		t.Errorf("Classify(blr x16) = %v, want ClassCall", c)
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

func TestResolveRiscvBranch(t *testing.T) {
	cases := map[string]string{
		"j 50":            "j 0x1032",        // 0x1000 + 50
		"j -40":           "j 0xfd8",         // 0x1000 - 40
		"bnez x10,12":     "bnez x10,0x100c", // last operand is the PC-rel target
		"jal x1,16":       "jal x1,0x1010",   // two-operand jal
		"jalr x1,528(x1)": "jalr x1,528(x1)", // register-relative: untouched
		"addi x2,x2,-48":  "addi x2,x2,-48",  // immediate, not a branch: untouched
		"ret":             "ret",             // no operand
	}
	for in, want := range cases {
		if got := resolveRiscvBranch(in, 0x1000); got != want {
			t.Errorf("resolveRiscvBranch(%q) = %q, want %q", in, got, want)
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

func TestRangeHonorsMaxInst(t *testing.T) {
	d, err := For(ArchAMD64)
	if err != nil {
		t.Fatal(err)
	}
	insts := Range(d, []byte{0x90, 0x90, 0x90}, 0x1000, 2)
	if len(insts) != 2 {
		t.Fatalf("Range maxInst length = %d, want 2", len(insts))
	}
	if insts[0].Addr != 0x1000 || insts[1].Addr != 0x1001 {
		t.Fatalf("instruction addresses = %#v", insts)
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
	if c := Classify("syscall"); c != ClassSyscall {
		t.Errorf("Classify(syscall)=%v, want ClassSyscall", c)
	}
	if c := Classify("nop"); c != ClassNop {
		t.Errorf("Classify(nop)=%v, want ClassNop", c)
	}
	if c := Classify("callq 0x100"); c != ClassCall {
		t.Errorf("Classify(callq)=%v, want ClassCall", c)
	}
}

func TestClassifyLiteHighlightCategories(t *testing.T) {
	move := []string{"mov %rsp,%rbp", "lea 0x20(%rip),%rax", "ldr x0, [sp]", "sd x1, 0(x2)"}
	for _, s := range move {
		if c := Classify(s); c != ClassMove {
			t.Errorf("Classify(%q)=%v, want ClassMove", s, c)
		}
	}
	arith := []string{"add $1,%eax", "cmp %rax,%rbx", "subs x0, x0, #1", "slli x1, x1, 2"}
	for _, s := range arith {
		if c := Classify(s); c != ClassArithmetic {
			t.Errorf("Classify(%q)=%v, want ClassArithmetic", s, c)
		}
	}
}
