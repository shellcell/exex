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
	if f.Entry() == 0 {
		t.Fatal("expected non-zero entry")
	}

	// Symbol names may carry a leading underscore (Mach-O / macОS).
	sym := func(name string) (Symbol, bool) {
		for _, s := range f.Symbols {
			if s.Name == name || s.Name == "_"+name {
				return s, true
			}
		}
		return Symbol{}, false
	}
	mainSym, foundMain := sym("main")
	_, foundMultiply := sym("multiply")
	if !foundMain || !foundMultiply {
		t.Fatalf("missing expected symbols: main=%v multiply=%v", foundMain, foundMultiply)
	}

	// Sanity-check section lookup over the entry address.
	if sec := f.SectionAt(f.Entry()); sec == nil {
		t.Fatalf("entry 0x%x not mapped to any section", f.Entry())
	}

	// The executable image should cover the entry point.
	if _, ok := f.ExecImage().PosForAddr(f.Entry()); !ok {
		t.Fatalf("entry 0x%x not present in the executable image", f.Entry())
	}

	// DWARF is optional: linked Mach-O executables keep their debug info in
	// separate .o/dSYM bundles. Only assert source mapping when DWARF is
	// actually embedded (e.g. ELF builds with -g).
	if f.HasDWARF() {
		file, line := f.LookupAddr(mainSym.Addr)
		if file == "" || line == 0 {
			t.Fatalf("addr→source lookup failed for main at 0x%x", mainSym.Addr)
		}
		if !strings.HasSuffix(file, "sample.c") {
			t.Fatalf("unexpected source file: %s", file)
		}
	}
}

func TestImageWindowContainingBoundsAndPreservesTarget(t *testing.T) {
	im := &Image{Data: []byte("abcdefghijklmnopqrstuvwxyz")}
	im.Regions = []Region{{Addr: 0x1000, Size: uint64(len(im.Data)), Off: 0, Name: ".text"}}

	win, ok := im.WindowContaining(0x1008, 10, 3)
	if !ok {
		t.Fatal("expected window containing target")
	}
	if win.Start != 5 || win.End != 15 {
		t.Fatalf("window bounds = [%d,%d), want [5,15)", win.Start, win.End)
	}
	if win.Addr != 0x1005 {
		t.Fatalf("window addr = 0x%x, want 0x1005", win.Addr)
	}

	win, ok = im.WindowContaining(0x1018, 10, 3)
	if !ok {
		t.Fatal("expected trailing window containing target")
	}
	if win.Start != 16 || win.End != 26 {
		t.Fatalf("trailing bounds = [%d,%d), want [16,26)", win.Start, win.End)
	}
	if win.Addr > 0x1018 || win.Addr+uint64(len(win.Data)) <= 0x1018 {
		t.Fatalf("window [0x%x,0x%x) does not contain target", win.Addr, win.Addr+uint64(len(win.Data)))
	}
}
