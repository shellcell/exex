package binfile

import (
	"os"
	"testing"
)

// TestOpenSystemMachO exercises the Mach-O path against a real (usually fat)
// system binary. Skipped where the file isn't present.
func TestOpenSystemMachO(t *testing.T) {
	const path = "/bin/ls"
	if _, err := os.Stat(path); err != nil {
		t.Skipf("%s not present", path)
	}
	f, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if f.Format != FormatMachO {
		t.Fatalf("format = %q, want Mach-O", f.Format)
	}
	if f.Entry() == 0 {
		t.Fatal("entry is zero")
	}
	if len(f.Sections) == 0 {
		t.Fatal("no sections")
	}
	if len(f.Symbols) == 0 {
		t.Fatal("no symbols")
	}

	// The entry point must live inside the executable image we'll disassemble.
	if _, ok := f.ExecImage().PosForAddr(f.Entry()); !ok {
		t.Fatalf("entry 0x%x not in executable image", f.Entry())
	}
	// Every byte of the file must be addressable in the raw view.
	if got := len(f.Raw()); got == 0 {
		t.Fatal("raw file is empty")
	}
	if f.VAImage().Len() == 0 {
		t.Fatal("virtual-address image is empty")
	}

	t.Logf("format=%s arch=%d entry=0x%x sections=%d symbols=%d raw=%d va-image=%d exec-image=%d",
		f.Format, f.Arch(), f.Entry(), len(f.Sections), len(f.Symbols),
		len(f.Raw()), f.VAImage().Len(), f.ExecImage().Len())
}
