package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReorderArgs(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		// flag after the positional binary path
		{[]string{"/bin/ls", "-s", "Main window"}, "-s|Main window|/bin/ls"},
		// flag value kept attached, positionals preserved in order
		{[]string{"bin", "-debug", "d.dSYM", "0x1000"}, "-debug|d.dSYM|bin|0x1000"},
		// -s=value form is self-contained
		{[]string{"bin", "-s=foo"}, "-s=foo|bin"},
		// already flags-first is unchanged
		{[]string{"-s", "foo", "bin"}, "-s|foo|bin"},
		// everything after -- is positional
		{[]string{"-s", "x", "--", "-weirdname"}, "-s|x|-weirdname"},
	}
	for _, c := range cases {
		if got := strings.Join(reorderArgs(c.in), "|"); got != c.want {
			t.Errorf("reorderArgs(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestResolveTargetKeepsExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app")
	if err := os.WriteFile(path, []byte("binary"), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := resolveTarget(path); got != path {
		t.Fatalf("resolveTarget(existing file) = %q, want %q", got, path)
	}
}

func TestResolveTargetLooksUpPathCommand(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "exex-test-command")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)

	if got := resolveTarget("exex-test-command"); got != path {
		t.Fatalf("resolveTarget(PATH command) = %q, want %q", got, path)
	}
}

func TestResolveTargetPassesThroughUnresolvedPath(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing")
	if got := resolveTarget(missing); got != missing {
		t.Fatalf("resolveTarget(missing path) = %q, want %q", got, missing)
	}
	if got := resolveTarget(dir); got != dir {
		t.Fatalf("resolveTarget(directory) = %q, want %q", got, dir)
	}
}
