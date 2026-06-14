package binfile

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/rabarbra/exex/internal/disasm"
)

// TestOpenPE cross-compiles a tiny Go program to a Windows PE and opens it,
// exercising the PE loader end to end. Skipped if the Go toolchain can't build
// for windows/amd64.
func TestOpenPE(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	bin := filepath.Join(dir, "prog.exe")
	if err := os.WriteFile(src, []byte("package main\nfunc main(){ println(\"hi\") }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-o", bin, src)
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cross-compile failed: %v\n%s", err, out)
	}

	f, err := Open(bin)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if f.Format != FormatPE {
		t.Fatalf("format = %q, want PE", f.Format)
	}
	if f.Arch() != disasm.ArchAMD64 {
		t.Fatalf("arch = %d, want AMD64", f.Arch())
	}
	if f.Entry() == 0 {
		t.Fatal("entry is zero")
	}
	if len(f.Sections) == 0 {
		t.Fatal("no sections")
	}
	if _, ok := f.ExecImage().PosForAddr(f.Entry()); !ok {
		t.Fatalf("entry 0x%x not in executable image", f.Entry())
	}
	// A Go binary records its build info regardless of container.
	if f.Info == nil || f.Info.GoVersion == "" {
		t.Error("expected Go build info")
	}
	t.Logf("PE: arch=%d entry=0x%x sections=%d symbols=%d go=%s",
		f.Arch(), f.Entry(), len(f.Sections), len(f.Symbols), f.Info.GoVersion)
}
