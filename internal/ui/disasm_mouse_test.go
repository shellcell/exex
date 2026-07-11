package ui

import (
	"testing"

	"github.com/rabarbra/exex/internal/binfile"
)

// TestDisasmRenderWidthMatchesTheRenderedSplit pins RenderWidth — which the
// scroll, click and row-height math all resolve rows at — to the width
// renderDisasm actually hands the scroller. If it drifts, rows are measured at
// one width and drawn at another, so a click lands on the wrong instruction.
// A golden frame cannot catch it: the frame still renders correctly.
func TestDisasmRenderWidthMatchesTheRenderedSplit(t *testing.T) {
	f := openDebugSample(t)
	m, err := New(f)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m.width, m.height = 120, 40
	m.setMode(modeDisasm)
	ctx := m.viewContextPtr()

	// Disasm-first with the source pane open: renderDisasm splits the screen in
	// half and renders the scroller into the left pane.
	m.dasm.ShowSource, m.dasm.SourceFirst = true, false
	if got, want := m.dasm.RenderWidth(ctx), m.width/2; got != want {
		t.Errorf("with the source pane open RenderWidth = %d, but the scroller is drawn at %d", got, want)
	}
	// No pane: the scroller has the full width.
	m.dasm.ShowSource = false
	if got, want := m.dasm.RenderWidth(ctx), m.width; got != want {
		t.Errorf("with no source pane RenderWidth = %d, want the full width %d", got, want)
	}
}

// openDebugSample opens a freshly built DWARF sample whose source resolves.
func openDebugSample(t *testing.T) *binfile.File {
	t.Helper()
	f, err := binfile.Open(buildResolvableDebugSample(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { f.Close() })
	if !f.HasDWARF() {
		t.Skip("debug sample has no DWARF")
	}
	return f
}

// TestClickRoutesBetweenTheSourceAndDisasmPanes pins which pane a click lands
// in when the source-first split is open: the left half moves the source cursor
// (and drags the disasm cursor with it), the right half moves the disasm cursor
// and leaves the source alone.
func TestClickRoutesBetweenTheSourceAndDisasmPanes(t *testing.T) {
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
	if file == "" || line == 0 || f.SourceLines(file) == nil {
		t.Skip("main has no resolvable source mapping")
	}
	m.openSourceFileInDisasm(file, line)
	_ = m.View() // the click math reads the tops the render recorded

	// Left half, a couple of rows down: the source cursor takes the click.
	const bodyRow = 3
	wantLine, ok := m.dasm.SourceLineAtRow(m.viewContextPtr(), bodyRow)
	if !ok {
		t.Skip("no source line under the test row")
	}
	srcBefore := m.dasm.SrcCur
	m.handleClick(4, bodyRow+1) // handleClick takes screen y (body starts at y=1)
	if m.dasm.SrcCur != wantLine {
		t.Errorf("click in the source pane set SrcCur = %d, want the line under it (%d)", m.dasm.SrcCur, wantLine)
	}
	if wantLine != srcBefore {
		// The disasm cursor follows the source cursor (SyncSourceAsm).
		if addr, ok := f.LineToAddr(file, m.dasm.SrcCur); ok {
			if cur, ok := m.dasm.CurAddr(); !ok || cur != addr {
				t.Errorf("the disasm cursor did not follow the clicked line: at %#x, want %#x", cur, addr)
			}
		}
	}

	// Right half: the disasm cursor takes the click, the source cursor stays.
	if len(m.dasm.Inst) < 2 {
		t.Skip("not enough instructions for the right-pane click")
	}
	srcNow := m.dasm.SrcCur
	wantInst, ok := m.dasm.InstAtRow(m.viewContextPtr(), bodyRow)
	if !ok {
		t.Skip("no instruction under the test row")
	}
	m.handleClick(m.width-4, bodyRow+1)
	if m.dasm.Cur != wantInst {
		t.Errorf("click in the asm pane set Cur = %d, want the instruction under it (%d)", m.dasm.Cur, wantInst)
	}
	if m.dasm.SrcCur != srcNow {
		t.Errorf("a click in the asm pane moved the source cursor: %d → %d", srcNow, m.dasm.SrcCur)
	}
}
