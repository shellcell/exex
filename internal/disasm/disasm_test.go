package disasm

import (
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAMD64SampleHasCommonInstruction(t *testing.T) {
	cc, err := exec.LookPath("gcc")
	if err != nil {
		cc, err = exec.LookPath("cc")
	}
	if err != nil {
		t.Skip("no C compiler")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "s.c")
	bin := filepath.Join(dir, "s")
	if err := os.WriteFile(src, []byte("int main(void){return 0;}"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(cc, "-O0", "-o", bin, src).CombinedOutput()
	if err != nil {
		t.Fatalf("compile failed: %v\n%s", err, out)
	}

	ef, err := elf.Open(bin)
	if err != nil {
		t.Fatal(err)
	}
	defer ef.Close()
	if ef.Machine != elf.EM_X86_64 {
		t.Skipf("host is %s, not x86-64", ef.Machine)
	}
	d, err := For(ef.Machine)
	if err != nil {
		t.Fatal(err)
	}
	if d.Name() != "x86-64" {
		t.Fatalf("unexpected disassembler: %s", d.Name())
	}

	// Find .text and decode a slice; expect at least one "mov" or "push".
	for _, s := range ef.Sections {
		if s.Name != ".text" {
			continue
		}
		data, err := s.Data()
		if err != nil {
			t.Fatal(err)
		}
		if len(data) > 256 {
			data = data[:256]
		}
		insts := Range(d, data, s.Addr, 0)
		if len(insts) == 0 {
			t.Fatal("no instructions decoded from .text")
		}
		joined := ""
		for _, i := range insts {
			joined += " " + i.Text
		}
		if !(strings.Contains(joined, "push") || strings.Contains(joined, "mov")) {
			t.Fatalf("expected push/mov in decoded .text, got: %s", joined)
		}
		return
	}
	t.Fatal(".text section not found")
}
