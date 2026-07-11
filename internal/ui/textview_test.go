package ui

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
)

func TestLooksLikeText(t *testing.T) {
	if !LooksLikeText([]byte("#!/bin/sh\necho hi\n")) {
		t.Fatal("shell script should be text")
	}
	if LooksLikeText([]byte{0x7f, 'E', 'L', 'F', 0, 0, 1, 2}) {
		t.Fatal("ELF magic (has NUL) should not be text")
	}
	if LooksLikeText(nil) {
		t.Fatal("empty should not be text")
	}
}

func TestReadFilePrefixStopsAtLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large.txt")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 1024)), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := readFilePrefix(path, 17)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 17 {
		t.Fatalf("read %d bytes, want 17", len(got))
	}
}

func TestExtractPathsExistingOnly(t *testing.T) {
	dir := t.TempDir()
	// A real relative file the script references, plus a real absolute one.
	if err := os.WriteFile(filepath.Join(dir, "helper.sh"), []byte("echo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	abs := filepath.Join(dir, "data.txt")
	if err := os.WriteFile(abs, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Bare path tokens only (no command verbs, which now match via $PATH) so the
	// file-resolution behaviour is tested deterministically.
	lines := []string{
		"./helper.sh",  // relative-to-dir, exists  -> match
		abs,            // absolute, exists         -> match
		"./missing.sh", // relative, does not exist -> no match
		"then fi done", // shell keywords, not on $PATH, not paths -> no match
		"x=helper.sh",  // bare name with a dot -> path-ish -> match (dedupes with line 0)
	}
	spans, picks := extractPaths(lines, dir)

	if len(spans[0]) != 1 || lines[0][spans[0][0].start:spans[0][0].end] != "./helper.sh" {
		t.Fatalf("line 0 spans = %+v", spans[0])
	}
	if len(spans[2]) != 0 {
		t.Fatalf("missing path should not match: %+v", spans[2])
	}
	if len(spans[3]) != 0 {
		t.Fatalf("shell keywords matched: %+v", spans[3])
	}
	// helper.sh (lines 0 and 4) dedupes to one, plus data.txt.
	if len(picks) != 2 {
		t.Fatalf("picks = %v, want 2 unique (helper.sh, data.txt)", picks)
	}
}

func TestExtractPathsCommandsFromPATH(t *testing.T) {
	shp, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not on PATH")
	}
	dir := t.TempDir()
	// "sh" is a bare command on $PATH -> matched and resolved to its location;
	// "frobnicate_xyz" is neither a file nor a command -> not matched.
	lines := []string{"sh ./run.sh frobnicate_xyz"}
	spans, picks := extractPaths(lines, dir)

	matched := false
	for _, sp := range spans[0] {
		if sp.resolved == shp {
			matched = true
		}
	}
	if !matched {
		t.Fatalf("expected 'sh' resolved to %s in %+v", shp, spans[0])
	}
	for _, p := range picks {
		if strings.Contains(p, "frobnicate") {
			t.Fatalf("non-command/non-file matched: %v", picks)
		}
	}
}

func TestUnderlineRanges(t *testing.T) {
	// Plain text: underline the middle span, leave the rest untouched.
	got := underlineRanges("hello", []pathSpan{{start: 1, end: 3}})
	if got != "h\x1b[4mel\x1b[24mlo" {
		t.Fatalf("plain underline = %q", got)
	}
	if ansi.Strip(got) != "hello" {
		t.Fatalf("visible text changed: %q", ansi.Strip(got))
	}

	// A reset inside the span (as a syntax highlighter emits between tokens) must
	// re-assert the underline so it doesn't drop mid-span.
	colored := "\x1b[31mab\x1b[0mcd" // visible "abcd"; reset after "ab"
	out := underlineRanges(colored, []pathSpan{{start: 1, end: 3}})
	if ansi.Strip(out) != "abcd" {
		t.Fatalf("visible text changed: %q", ansi.Strip(out))
	}
	if c := strings.Count(out, "\x1b[4m"); c < 2 {
		t.Fatalf("underline not re-asserted after reset (count=%d): %q", c, out)
	}
	if !strings.Contains(out, "\x1b[24m") {
		t.Fatalf("missing underline-off: %q", out)
	}
}

func TestResolveExistingPathShape(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "f.txt"), []byte("x"), 0o644)
	// A bare word with no separator/dot/~ is rejected even if a file by that name
	// exists, to avoid matching common words.
	os.WriteFile(filepath.Join(dir, "build"), []byte("x"), 0o644)
	if got := resolveExistingPath("build", dir); got != "" {
		t.Fatalf("bare word should not resolve, got %q", got)
	}
	if got := resolveExistingPath("./f.txt", dir); got == "" {
		t.Fatal("./f.txt should resolve")
	}
	if got := resolveExistingPath("f.txt", dir); got == "" {
		t.Fatal("f.txt (has a dot) should resolve")
	}
}
