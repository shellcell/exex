package integration

import (
	"os"
	"strings"
	"testing"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/disasm"
	"github.com/rabarbra/exex/internal/dump"
	"github.com/rabarbra/exex/internal/dyldcache"
	"github.com/rabarbra/exex/internal/explorer"
)

// TestExtractedDylibParses is the end-to-end check for dyld-cache un-sharing:
// extract real system dylibs, parse each with binfile, and confirm the compact
// rebuilt __LINKEDIT keeps every symbol name at a few-hundred-KB size.
func TestExtractedDylibParses(t *testing.T) {
	path, ok := dyldcache.HostCachePath("arm64", func(p string) bool { _, err := os.Stat(p); return err == nil })
	if !ok {
		t.Skip("no host dyld shared cache")
	}
	c, err := dyldcache.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	for _, lib := range []string{
		"/usr/lib/system/libsystem_kernel.dylib",
		"/usr/lib/libSystem.B.dylib",
		"/usr/lib/libc++.1.dylib",
	} {
		im, ok := c.FindImage(lib)
		if !ok {
			t.Errorf("%s: not in image table", lib)
			continue
		}
		buf, err := c.ExtractImage(im)
		if err != nil {
			t.Errorf("%s: extract: %v", lib, err)
			continue
		}
		if len(buf) > 16<<20 {
			t.Errorf("%s: extracted %d MB, expected a few hundred KB (compact linkedit failed)", lib, len(buf)>>20)
		}
		f, err := binfile.OpenBytes(lib, buf)
		if err != nil {
			t.Errorf("%s: parse: %v", lib, err)
			continue
		}
		named := 0
		for _, s := range f.Symbols {
			if s.Name != "" {
				named++
			}
		}
		t.Logf("%s: %d KB, %d sections, %d/%d named symbols, exec=%v",
			lib, len(buf)>>10, len(f.Sections), named, len(f.Symbols), f.HasExecCode())
		if len(f.Sections) == 0 || named == 0 || !f.HasExecCode() {
			t.Errorf("%s: stitched image incomplete", lib)
		}
	}
}

// TestExtractedDylibDisassembles proves the stitched cache dylib is browsable:
// its executable section decodes to instructions like any on-disk Mach-O.
func TestExtractedDylibDisassembles(t *testing.T) {
	path, ok := dyldcache.HostCachePath("arm64", func(p string) bool { _, err := os.Stat(p); return err == nil })
	if !ok {
		t.Skip("no host dyld shared cache")
	}
	c, err := dyldcache.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	im, ok := c.FindImage("/usr/lib/system/libsystem_kernel.dylib")
	if !ok {
		t.Skip("libsystem_kernel not in cache")
	}
	buf, err := c.ExtractImage(im)
	if err != nil {
		t.Fatal(err)
	}
	f, err := binfile.OpenBytes(im.Path, buf)
	if err != nil {
		t.Fatal(err)
	}
	dis, err := disasm.For(f.Arch())
	if err != nil {
		t.Skipf("no disassembler for %v", f.Arch())
	}
	svc := explorer.NewDisasmService(f, dis, 1<<20, 0)
	addr := explorer.DefaultExecAddr(f, "lowest")
	if addr == 0 {
		t.Fatal("no executable entry address")
	}
	win, insts := svc.DecodeAt(addr, 0)
	if len(insts) == 0 {
		t.Fatalf("decoded no instructions at %#x (window %#x..%#x)", addr, win.Start, win.End)
	}
	t.Logf("decoded %d instructions from %#x", len(insts), addr)
}

// TestSyscallsFullThroughCache is the end-to-end check for roadmap #33's second
// half: a macOS binary's real syscall surface comes from libsystem_kernel, which
// lives only in the dyld shared cache and is reached transitively through the
// libSystem.B re-export umbrella. The full scan must extract it from the cache
// and report its svc sites.
func TestSyscallsFullThroughCache(t *testing.T) {
	if _, err := os.Stat("/bin/ls"); err != nil {
		t.Skip("no /bin/ls")
	}
	if _, ok := dyldcache.HostCachePath("arm64", func(p string) bool { _, e := os.Stat(p); return e == nil }); !ok {
		if _, ok := dyldcache.HostCachePath("x86-64", func(p string) bool { _, e := os.Stat(p); return e == nil }); !ok {
			t.Skip("no host dyld shared cache")
		}
	}
	f, err := binfile.Open("/bin/ls")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sites, objs, _ := dump.CollectSyscallsFull(f)
	if objs < 5 {
		t.Fatalf("only %d objects scanned — dependency walk didn't reach the cache", objs)
	}
	fromKernel := 0
	for _, s := range sites {
		if strings.Contains(s.Origin, "libsystem_kernel") {
			fromKernel++
		}
	}
	t.Logf("%d objects scanned, %d sites, %d from libsystem_kernel", objs, len(sites), fromKernel)
	if fromKernel < 100 {
		t.Fatalf("expected 100+ syscall sites from libsystem_kernel via the cache, got %d", fromKernel)
	}
}
