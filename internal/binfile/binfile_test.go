package binfile

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// buildSample compiles a small C program with -g into a temp dir and returns
// the path. Tests are skipped if no C compiler is on PATH.
func buildSample(t *testing.T) string {
	t.Helper()
	cc, err := exec.LookPath("gcc")
	if err != nil {
		cc, err = exec.LookPath("cc")
	}
	if err != nil {
		t.Skip("no C compiler available")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "sample.c")
	bin := filepath.Join(dir, "sample")
	const code = `
#include <stdio.h>
int multiply(int a, int b) {
    return a * b;
}
int main(int argc, char **argv) {
    int r = multiply(argc, 7);
    printf("r=%d\n", r);
    return r;
}
`
	if err := os.WriteFile(src, []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(cc, "-g", "-O0", "-o", bin, src).CombinedOutput()
	if err != nil {
		t.Fatalf("compile failed: %v\n%s", err, out)
	}
	return bin
}

func TestOpenAndProbeSampleBinary(t *testing.T) {
	path := buildSample(t)
	f, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !f.HasDWARF() {
		t.Fatal("expected DWARF info in sample binary")
	}
	if f.Entry() == 0 {
		t.Fatal("expected non-zero entry")
	}

	var foundMain, foundMultiply bool
	for _, s := range f.Symbols {
		if s.Name == "main" {
			foundMain = true
		}
		if s.Name == "multiply" {
			foundMultiply = true
		}
	}
	if !foundMain || !foundMultiply {
		t.Fatalf("missing expected symbols: main=%v multiply=%v", foundMain, foundMultiply)
	}

	// Sanity-check section lookup over the entry address.
	if sec := f.SectionAt(f.Entry()); sec == nil {
		t.Fatalf("entry 0x%x not mapped to any section", f.Entry())
	}

	// DWARF should map main's address to sample.c.
	var mainAddr uint64
	for _, s := range f.Symbols {
		if s.Name == "main" {
			mainAddr = s.Addr
			break
		}
	}
	file, line := f.LookupAddr(mainAddr)
	if file == "" || line == 0 {
		t.Fatalf("addr→source lookup failed for main at 0x%x", mainAddr)
	}
	if !strings.HasSuffix(file, "sample.c") {
		t.Fatalf("unexpected source file: %s", file)
	}
}
