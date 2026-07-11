package ui

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/rabarbra/exex/internal/binfile"
)

// buildResolvableDebugSample is buildDebugSample compiled from inside the
// temp directory with a relative source name, so the DWARF comp-dir + name
// join to a path that actually exists on disk — SourceLines must resolve the
// file for any source-pane behavior to be testable.
func buildResolvableDebugSample(t *testing.T) string {
	t.Helper()
	cc, err := exec.LookPath("gcc")
	if err != nil {
		cc, err = exec.LookPath("cc")
	}
	if err != nil {
		t.Skip("no C compiler available")
	}
	dir := t.TempDir()
	const code = `
#include <stdio.h>
static int twice(int x) {
    return x * 2;
}
int main(int argc, char **argv) {
    int value = twice(argc);
    printf("%d\n", value);
    return value;
}
`
	if err := os.WriteFile(filepath.Join(dir, "sample.c"), []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(cc, "-g", "-O0", "-o", "sample", "sample.c")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile failed: %v\n%s", err, out)
	}
	return filepath.Join(dir, "sample")
}

// TestSourceFirstCursorDrivesTheDisasmPane pins the source-first contract:
// opening a file at a mapped line decodes a window and parks the disasm cursor
// on that line's instruction, and stepping to the next mapped line moves it.
// Nothing else asserts the follower actually follows — the wheel test only
// checks the scroll offset — so a dead SyncSourceAsm passed every test.
func TestSourceFirstCursorDrivesTheDisasmPane(t *testing.T) {
	path := buildResolvableDebugSample(t)
	f, err := binfile.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()
	if !f.HasDWARF() {
		t.Skip("debug sample has no DWARF")
	}
	m, err := New(f)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m.width, m.height = 120, 40

	var main binfile.Symbol
	for _, s := range f.Symbols {
		if s.Name == "main" || s.Name == "_main" {
			main = s
			break
		}
	}
	if main.Name == "" {
		t.Skip("debug sample has no main symbol")
	}
	file, line := f.LookupAddr(main.Addr)
	if file == "" || line == 0 {
		t.Skip("main has no line mapping")
	}
	if f.SourceLines(file) == nil {
		t.Skipf("DWARF path %q does not resolve on this system", file)
	}

	m.openSourceFileInDisasm(file, line)
	if m.mode != modeDisasm || !m.dasm.SourceFirst {
		t.Fatalf("open did not enter source-first disasm (mode=%v sourceFirst=%v)", m.mode, m.dasm.SourceFirst)
	}
	if len(m.dasm.Inst) == 0 {
		t.Fatal("opening a mapped source line decoded no disasm window")
	}
	want, ok := f.LineToAddr(file, m.dasm.SrcCur)
	if !ok {
		t.Fatalf("opened line %d has no mapped address", m.dasm.SrcCur)
	}
	got, ok := m.dasm.CurAddr()
	if !ok || got != want {
		t.Fatalf("disasm cursor at %#x, want the line's instruction %#x", got, want)
	}

	// Step the source cursor to the next mapped line; the pane must follow.
	prevLine := m.dasm.SrcCur
	m.gotoMappedLine(true)
	if m.dasm.SrcCur == prevLine {
		t.Fatal("gotoMappedLine did not advance the source cursor")
	}
	want2, ok := f.LineToAddr(file, m.dasm.SrcCur)
	if !ok {
		t.Fatalf("line %d has no mapped address", m.dasm.SrcCur)
	}
	got2, ok := m.dasm.CurAddr()
	if !ok || got2 != want2 {
		t.Fatalf("after stepping to line %d the cursor is at %#x, want %#x", m.dasm.SrcCur, got2, want2)
	}
	if got2 == got {
		t.Fatal("the disasm cursor did not move with the source cursor")
	}
}
