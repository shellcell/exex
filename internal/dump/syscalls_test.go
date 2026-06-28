package dump

import (
	"os"
	"strings"
	"testing"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/disasm"
)

func TestIsSyscallInstr(t *testing.T) {
	yes := []string{"syscall", "sysenter", "svc #0", "svc 0", "ecall", "int $0x80", "int 0x80", "int $0x2e"}
	for _, s := range yes {
		if !isSyscallInstr(s) {
			t.Errorf("%q should be a syscall instruction", s)
		}
	}
	no := []string{"int3", "into", "brk #0x1", "ebreak", "int $0x3", "mov %rax,%rbx", "call 0x1000", "nop"}
	for _, s := range no {
		if isSyscallInstr(s) {
			t.Errorf("%q should NOT be a syscall instruction", s)
		}
	}
}

func TestIsVDSOName(t *testing.T) {
	for _, n := range []string{"__vdso_clock_gettime", "__kernel_gettimeofday"} {
		if !IsVDSOName(n) {
			t.Errorf("%q should be a vDSO name", n)
		}
	}
	for _, n := range []string{"clock_gettime", "vdso_thing", "__vdsox"} {
		if IsVDSOName(n) {
			t.Errorf("%q should NOT be a vDSO name", n)
		}
	}
}

func TestResolveSyscallNum(t *testing.T) {
	insts := func(texts ...string) []disasm.Inst {
		out := make([]disasm.Inst, len(texts))
		for i, s := range texts {
			out[i] = disasm.Inst{Text: s}
		}
		return out
	}
	cases := []struct {
		name string
		arch disasm.Arch
		prev []disasm.Inst
		want int64
		ok   bool
	}{
		{"amd64 mov eax", disasm.ArchAMD64, insts("mov $0x1,%eax"), 1, true},
		{"amd64 mov rax", disasm.ArchAMD64, insts("mov $0x3c,%rax"), 60, true},
		{"amd64 xor zero", disasm.ArchAMD64, insts("xor %eax,%eax"), 0, true},
		{"amd64 most recent wins", disasm.ArchAMD64, insts("mov $0x9,%eax", "mov $0x0,%rdi"), 9, true},
		{"amd64 nothing", disasm.ArchAMD64, insts("mov $0x0,%rdi"), 0, false},
		{"arm64 mov x8", disasm.ArchARM64, insts("mov x8, #0x2c"), 44, true},
		{"arm64 movz w8", disasm.ArchARM64, insts("movz w8, #0x5d"), 93, true},
		{"riscv li a7", disasm.ArchRISCV64, insts("li a7,93"), 93, true},
		{"riscv addi a7", disasm.ArchRISCV64, insts("addi a7,zero,40"), 40, true},
		{"arm mov r7", disasm.ArchARM, insts("mov r7, #4"), 4, true},
		{"unsupported arch", disasm.ArchPPC64, insts("li 0,1"), 0, false},
	}
	for _, c := range cases {
		got, ok := ResolveSyscallNum(c.prev, c.arch)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("%s: ResolveSyscallNum = (%d,%v), want (%d,%v)", c.name, got, ok, c.want, c.ok)
		}
	}
}

func TestClassifySyscallSite(t *testing.T) {
	// A real syscall instruction.
	if ok, vdso := ClassifySyscallSite(disasm.Inst{Text: "syscall", Class: disasm.ClassSyscall}, nil); !ok || vdso {
		t.Errorf("syscall insn: got (%v,%v), want (true,false)", ok, vdso)
	}
	// int3 padding is classified ClassSyscall by the decoder but is not a syscall.
	if ok, _ := ClassifySyscallSite(disasm.Inst{Text: "int3", Class: disasm.ClassSyscall}, nil); ok {
		t.Error("int3 should not be a syscall site")
	}
	// A call to a vDSO symbol is flagged as a vDSO site.
	symAt := func(a uint64) (binfile.Symbol, bool) {
		if a == 0x2000 {
			return binfile.Symbol{Name: "__vdso_clock_gettime", Addr: 0x2000}, true
		}
		return binfile.Symbol{}, false
	}
	if ok, vdso := ClassifySyscallSite(disasm.Inst{Text: "call 0x2000", Class: disasm.ClassCall}, symAt); !ok || !vdso {
		t.Errorf("vdso call: got (%v,%v), want (true,true)", ok, vdso)
	}
	// A call to a normal symbol is not a syscall site.
	if ok, _ := ClassifySyscallSite(disasm.Inst{Text: "call 0x3000", Class: disasm.ClassCall}, symAt); ok {
		t.Error("ordinary call should not be a syscall site")
	}
}

func TestSyscallsDumpFormats(t *testing.T) {
	// The test binary itself is a Go ELF whose runtime makes raw syscalls with
	// immediate numbers — a good end-to-end check that both dump views work and
	// that numbers are recovered. Skip where that doesn't hold (non-ELF/amd64).
	exe, err := os.Executable()
	if err != nil {
		t.Skip("no test executable path")
	}
	f, err := binfile.Open(exe)
	if err != nil {
		t.Skipf("open self: %v", err)
	}
	defer f.Close()
	if f.Format != binfile.FormatELF || f.Arch() != disasm.ArchAMD64 {
		t.Skip("self is not ELF amd64")
	}
	full := Syscalls(f, true)
	if !strings.Contains(full, "syscall") || !strings.Contains(full, "#") {
		t.Errorf("full dump missing syscalls or recovered numbers:\n%s", first(full, 400))
	}
	uniq := Syscalls(f, false)
	if !strings.Contains(uniq, "distinct system calls") {
		t.Errorf("unique dump wrong:\n%s", first(uniq, 400))
	}
}

func TestVsyscallTrampoline(t *testing.T) {
	// The i386 vsyscall trampoline is a syscall site (number in eax), not vDSO.
	if ok, vdso := ClassifySyscallSite(disasm.Inst{Text: "call *%gs:0x10", Class: disasm.ClassCall}, nil); !ok || vdso {
		t.Errorf("vsyscall trampoline: got (%v,%v), want (true,false)", ok, vdso)
	}
	// An ordinary gs-relative data load is not a call and must not match.
	if ok, _ := ClassifySyscallSite(disasm.Inst{Text: "mov %gs:0x14,%eax", Class: disasm.ClassMove}, nil); ok {
		t.Error("gs data load wrongly classified as a syscall")
	}
}

func TestResolveStopsAtWriterAndCall(t *testing.T) {
	insts := func(texts ...string) []disasm.Inst {
		out := make([]disasm.Inst, len(texts))
		for i, s := range texts {
			out[i] = disasm.Inst{Text: s}
		}
		return out
	}
	// eax written by a non-immediate just before: unresolved (must not scan past
	// it to an earlier, unrelated value).
	if _, ok := ResolveSyscallNum(insts("mov $0x5,%eax", "mov (%edx),%eax"), disasm.ArchX86); ok {
		t.Error("resolved past a non-immediate write to eax")
	}
	// A call clobbers eax (cdecl): an earlier mov must not be used.
	if _, ok := ResolveSyscallNum(insts("mov $0x5,%eax", "call 0x1234"), disasm.ArchX86); ok {
		t.Error("resolved past a call that clobbers eax")
	}
	// The immediate immediately before resolves.
	if v, ok := ResolveSyscallNum(insts("call 0x1234", "mov $0x4,%eax"), disasm.ArchX86); !ok || v != 4 {
		t.Errorf("got (%d,%v), want (4,true)", v, ok)
	}
}

func TestSyscallsFull(t *testing.T) {
	// /bin/ls makes its syscalls through libc, so syscalls-full should find them
	// in a library and tag the origin even when the binary has none of its own.
	f, err := binfile.Open(firstExisting("/bin/ls", "/usr/bin/true", "/bin/cat"))
	if err != nil {
		t.Skipf("open: %v", err)
	}
	defer f.Close()
	if f.Format != binfile.FormatELF || f.Arch() != disasm.ArchAMD64 {
		t.Skip("not ELF amd64")
	}
	sites, objs, _ := CollectSyscallsFull(f)
	if objs < 1 {
		t.Fatalf("scanned %d objects, want >= 1", objs)
	}
	out := SyscallsFull(f)
	if !strings.Contains(out, "distinct system calls") {
		t.Errorf("syscalls-full missing summary:\n%s", first(out, 300))
	}
	// At least some sites should carry a library origin (unless statically linked).
	if objs > 1 {
		hasOrigin := false
		for _, s := range sites {
			if s.Origin != "" && s.Origin != "this binary" {
				hasOrigin = true
				break
			}
		}
		if !hasOrigin {
			t.Error("no library-origin syscall sites despite scanning libraries")
		}
	}
}

func firstExisting(paths ...string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return paths[0]
}

func first(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
