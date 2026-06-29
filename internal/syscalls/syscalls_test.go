package syscalls

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rabarbra/exex/internal/arch"
)

func TestKey(t *testing.T) {
	cases := map[string]struct {
		format string
		a      arch.Arch
	}{
		"linux-amd64":  {"ELF", arch.ArchAMD64},
		"linux-arm64":  {"ELF", arch.ArchARM64},
		"linux-386":    {"ELF", arch.ArchX86},
		"linux-arm":    {"ELF", arch.ArchARM},
		"darwin-arm64": {"Mach-O", arch.ArchARM64},
		"darwin-amd64": {"Mach-O", arch.ArchAMD64},
	}
	for want, c := range cases {
		if got := Key(c.format, c.a); got != want {
			t.Errorf("Key(%q,%v) = %q, want %q", c.format, c.a, got, want)
		}
	}
}

func TestBuiltinNames(t *testing.T) {
	// A few well-known numbers per platform that must resolve from the embedded
	// tables (different numbering per arch is the whole point).
	cases := []struct {
		key  string
		num  int64
		want string
	}{
		{"linux-amd64", 1, "write"},
		{"linux-amd64", 0, "read"},
		{"linux-amd64", 59, "execve"},
		{"linux-arm64", 64, "write"},
		{"linux-arm64", 63, "read"},
		{"linux-arm64", 221, "execve"},
		{"linux-386", 4, "write"},
		{"linux-arm", 4, "write"},
		{"darwin-arm64", 4, "write"},
		{"darwin-arm64", 1, "exit"},
		// x86-64 Darwin numbers carry the 0x2000000 BSD class — must be masked off.
		{"darwin-amd64", 0x2000004, "write"},
	}
	for _, c := range cases {
		if got, ok := Name(c.key, c.num); !ok || got != c.want {
			t.Errorf("Name(%q,%d) = %q,%v; want %q", c.key, c.num, got, ok, c.want)
		}
	}
	if _, ok := Name("linux-amd64", 999999); ok {
		t.Error("unknown number should not resolve")
	}
	if !Available("linux-amd64") || Available("plan9-amd64") {
		t.Error("Available wrong")
	}
}

func TestOverrideDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "linux-amd64"), []byte("# custom\n1\tMY_WRITE\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if n, err := LoadOverrideDir(dir); err != nil || n != 1 {
		t.Fatalf("LoadOverrideDir = %d, %v", n, err)
	}
	if got, ok := Name("linux-amd64", 1); !ok || got != "MY_WRITE" {
		t.Errorf("override Name(1) = %q,%v; want MY_WRITE", got, ok)
	}
	// A number not in the override still falls through to the built-in.
	if got, ok := Name("linux-amd64", 0); !ok || got != "read" {
		t.Errorf("fallthrough Name(0) = %q,%v; want read", got, ok)
	}
	override = map[string]Table{} // reset for other tests
}
