package explorer

import (
	"path/filepath"
	"testing"

	"github.com/rabarbra/exex/internal/binfile"
)

func TestResolveLibPathWithRPath(t *testing.T) {
	root := t.TempDir()
	binPath := filepath.Join(root, "bin", "app")
	want := filepath.Join(root, "lib", "libfoo.dylib")
	exists := existsSet(want)

	got, ok := ResolveLibPath("@rpath/libfoo.dylib", binPath, &binfile.Info{RunPath: []string{"@loader_path/../lib"}}, exists)
	if !ok || got != want {
		t.Fatalf("ResolveLibPath = %q, %v; want %q, true", got, ok, want)
	}
}

func TestResolveLibPathSearchesDefaultBasename(t *testing.T) {
	want := filepath.Join("/usr/lib", "libc.so.6")
	got, ok := ResolveLibPath("libc.so.6", "/bin/app", nil, existsSet(want))
	if !ok || got != want {
		t.Fatalf("ResolveLibPath = %q, %v; want %q, true", got, ok, want)
	}
}

func TestIsDyldSharedCacheLib(t *testing.T) {
	if !IsDyldSharedCacheLib("/System/Library/Frameworks/AppKit.framework/AppKit") {
		t.Fatal("expected system framework to be reported as dyld shared cache lib")
	}
	if IsDyldSharedCacheLib("/opt/homebrew/lib/libfoo.dylib") {
		t.Fatal("expected homebrew library to be openable on disk")
	}
}

func existsSet(paths ...string) FileExists {
	set := map[string]bool{}
	for _, p := range paths {
		set[p] = true
	}
	return func(p string) bool { return set[p] }
}
