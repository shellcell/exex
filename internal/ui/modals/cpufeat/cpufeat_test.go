package cpufeat

import (
	"testing"

	"github.com/rabarbra/exex/internal/dump"
	"github.com/rabarbra/exex/internal/ui/modal"
)

// fakeHost records what the modal asked the shell to do. Before the extraction
// this behaviour could only be exercised through a whole *ui.Model.
type fakeHost struct {
	loaded   []uint64
	statuses []string
}

func (h *fakeHost) SetStatus(msg string, isErr bool) { h.statuses = append(h.statuses, msg) }
func (h *fakeHost) LoadDisasmAt(addr uint64)         { h.loaded = append(h.loaded, addr) }

func testSet() dump.CPUFeatureSet {
	return dump.CPUFeatureSet{
		Total:    100,
		Baseline: "x86-64-v3",
		Counts:   map[string]int{"AVX": 2, "BMI2": 1, "SSE2": 3},
		FirstUse: map[string]uint64{"AVX": 0x1000, "BMI2": 0x2000, "SSE2": 0x3000},
	}
}

func openState() *State {
	s := &State{}
	s.Open(testSet())
	return s
}

func TestOpenSortsFeaturesAndMarksScanned(t *testing.T) {
	s := &State{}
	if s.Active() || s.Scanned() {
		t.Fatal("zero value should be closed and unscanned")
	}
	s.Open(testSet())
	if !s.Active() || !s.Scanned() {
		t.Fatal("Open should open the overlay and mark it scanned")
	}
	want := []string{"AVX", "BMI2", "SSE2"} // SortedFeatures order
	if got := s.Features(); len(got) != len(want) {
		t.Fatalf("features = %v, want %v", got, want)
	}
	// Closing must not discard the cached scan: reopening skips a rescan.
	s.Close()
	if s.Active() || !s.Scanned() {
		t.Errorf("Close dropped the cached scan: active=%v scanned=%v", s.Active(), s.Scanned())
	}
}

func TestUpdateNavigatesAndCloses(t *testing.T) {
	s := openState()
	ctx := modal.Context{}
	host := &fakeHost{}

	sel, _, n, wrap, ok := s.List()
	if !ok || n != 3 || wrap {
		t.Fatalf("List() = n=%d wrap=%v ok=%v, want n=3 wrap=false ok=true", n, wrap, ok)
	}

	// Up at the top is a no-op, not a wrap.
	s.Update(ctx, host, "up")
	if *sel != 0 {
		t.Errorf("up at top moved selection to %d", *sel)
	}
	s.Update(ctx, host, "down")
	s.Update(ctx, host, "down")
	if *sel != 2 {
		t.Errorf("selection = %d after two downs, want 2", *sel)
	}
	// Down at the bottom is a no-op too.
	s.Update(ctx, host, "down")
	if *sel != 2 {
		t.Errorf("down at bottom moved selection to %d", *sel)
	}

	s.Update(ctx, host, "esc")
	if s.Active() {
		t.Error("esc did not close the overlay")
	}
}

func TestActivateJumpsToFirstUseAndCloses(t *testing.T) {
	s := openState()
	host := &fakeHost{}

	s.Update(modal.Context{}, host, "down") // select BMI2
	if cmd := s.Activate(host); cmd != nil {
		t.Error("Activate returned a command; the jump is synchronous")
	}
	if len(host.loaded) != 1 || host.loaded[0] != 0x2000 {
		t.Errorf("jumped to %v, want [0x2000] (BMI2's first use)", host.loaded)
	}
	if s.Active() {
		t.Error("Activate did not close the overlay")
	}
}

// TestActivateOnEmptyIsInert: a scan that found no optional features renders a
// message and has nothing to jump to.
func TestActivateOnEmptyIsInert(t *testing.T) {
	s := &State{}
	s.Open(dump.CPUFeatureSet{Total: 10})
	host := &fakeHost{}
	if cmd := s.Activate(host); cmd != nil {
		t.Error("Activate on an empty set returned a command")
	}
	if len(host.loaded) != 0 {
		t.Errorf("Activate on an empty set jumped to %v", host.loaded)
	}
	if !s.Active() {
		t.Error("Activate on an empty set should leave the overlay open")
	}
}

// TestActivateWithoutFirstUseIsInert guards the FirstUse lookup: a feature
// counted but never located must not jump to address zero.
func TestActivateWithoutFirstUseIsInert(t *testing.T) {
	s := &State{}
	s.Open(dump.CPUFeatureSet{Counts: map[string]int{"AVX": 1}}) // no FirstUse entry
	host := &fakeHost{}
	s.Activate(host)
	if len(host.loaded) != 0 {
		t.Errorf("jumped to %v with no FirstUse entry", host.loaded)
	}
	if !s.Active() {
		t.Error("overlay closed despite having nowhere to jump")
	}
}
