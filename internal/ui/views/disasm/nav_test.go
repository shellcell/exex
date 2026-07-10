package disasm

import (
	"testing"

	"github.com/rabarbra/exex/internal/binfile"
	dis "github.com/rabarbra/exex/internal/disasm"
	"github.com/rabarbra/exex/internal/explorer"
	"github.com/rabarbra/exex/internal/testbin"
)

type fakeHost struct {
	status   string
	isErr    bool
	swaps    int
	shows    int
	statuses int
}

func (h *fakeHost) SetStatus(msg string, isErr bool) { h.status, h.isErr = msg, isErr; h.statuses++ }
func (h *fakeHost) DisasmWindowSwapped()             { h.swaps++ }
func (h *fakeHost) ShowDisasmView()                  { h.shows++ }

func fixtureEnv(t *testing.T) (Env, *fakeHost) {
	t.Helper()
	f, err := binfile.Open(testbin.WriteTinyELF64(t))
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	t.Cleanup(func() { f.Close() })
	d, err := dis.For(f.Arch())
	if err != nil {
		t.Fatalf("disassembler: %v", err)
	}
	h := &fakeHost{}
	return Env{File: f, Svc: explorer.NewDisasmService(f, d, 1<<20, 0), Host: h}, h
}

// TestLoadWindowShowsTheViewOnlyOnAUsableInstall pins the contract that broke
// during extraction: the old shell buried "switch to the disasm view" inside
// every successful window load, so a boundary jump from another view also
// switched views. A refused install (empty decode over a good window) must NOT
// switch — the user stays where they are and reads the status line.
func TestLoadWindowShowsTheViewOnlyOnAUsableInstall(t *testing.T) {
	env, h := fixtureEnv(t)
	st := &State{}

	if !st.LoadWindow(env, 0x401000, 0) {
		t.Fatal("loading the fixture entry point failed")
	}
	if h.shows != 1 {
		t.Errorf("ShowDisasmView called %d times, want 1", h.shows)
	}
	if h.swaps != 1 {
		t.Errorf("DisasmWindowSwapped called %d times, want 1", h.swaps)
	}
	if len(st.Inst) == 0 {
		t.Fatal("no window installed")
	}

	// An address far outside the image decodes to nothing; the good window and
	// the current view must both survive.
	kept := len(st.Inst)
	if st.LoadWindow(env, 0xdead0000, 0) {
		t.Error("loading an unmapped address reported success")
	}
	if h.shows != 1 {
		t.Errorf("a refused install switched views (ShowDisasmView = %d)", h.shows)
	}
	if h.status == "" || !h.isErr {
		t.Errorf("no error status after a refused install (status %q)", h.status)
	}
	if len(st.Inst) != kept {
		t.Errorf("the refused install clobbered the window: %d insts, had %d", len(st.Inst), kept)
	}
}

func TestJumpBoundary(t *testing.T) {
	env, _ := fixtureEnv(t)
	st := &State{}
	rowH := func(int) int { return 1 }

	if !st.JumpBoundary(env, false, 10, rowH) {
		t.Fatal("jump to start failed")
	}
	if st.Cur != 0 || st.Top != 0 || st.RenderedTop != 0 {
		t.Errorf("start jump left cur=%d top=%d rendered=%d, want zeros", st.Cur, st.Top, st.RenderedTop)
	}

	st.Cur = 0
	if !st.JumpBoundary(env, true, 10, rowH) {
		t.Fatal("jump to end failed")
	}
	if st.Cur != len(st.Inst)-1 {
		t.Errorf("end jump left cur=%d, want the last instruction %d", st.Cur, len(st.Inst)-1)
	}
	if st.RenderedTop != st.Top {
		t.Errorf("end jump left RenderedTop=%d desynced from Top=%d", st.RenderedTop, st.Top)
	}
}

// TestStepWalksTheWholeFixture: stepping forward from the first instruction
// visits every instruction and stops (with a status, not a wrap or a panic) at
// the end of executable code.
func TestStepWalksTheWholeFixture(t *testing.T) {
	env, h := fixtureEnv(t)
	st := &State{}
	if !st.LoadWindow(env, 0x401000, 0) {
		t.Fatal("load failed")
	}
	st.Cur = 0
	steps := 0
	for st.Step(env, true, 10) {
		if steps++; steps > 10_000 {
			t.Fatal("stepping never reached the end")
		}
	}
	if st.Cur != len(st.Inst)-1 {
		t.Errorf("walk ended at %d of %d", st.Cur, len(st.Inst)-1)
	}
	if h.status != "at end of executable code" {
		t.Errorf("status = %q, want the end-of-code notice", h.status)
	}
	// And back to the start.
	for st.Step(env, false, 10) {
		if steps++; steps > 20_000 {
			t.Fatal("stepping never reached the start")
		}
	}
	if st.Cur != 0 {
		t.Errorf("backward walk ended at %d, want 0", st.Cur)
	}
	if h.status != "at start of executable code" {
		t.Errorf("status = %q, want the start-of-code notice", h.status)
	}
}
