package findresults

import (
	"strings"
	"testing"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/ui/modal"
)

type fakeHost struct {
	opened    []Hit
	cancelled int
	statuses  []string
}

func (h *fakeHost) SetStatus(msg string, isErr bool) { h.statuses = append(h.statuses, msg) }
func (h *fakeHost) LoadDisasmAt(uint64)              {}
func (h *fakeHost) OpenHit(hit Hit)                  { h.opened = append(h.opened, hit) }
func (h *fakeHost) CancelSearch()                    { h.cancelled++ }

func testCtx() modal.Context {
	id := func(s string) string { return s }
	return modal.Context{
		File:   &binfile.File{},
		Width:  100,
		Height: 30,
		Styles: &modal.Styles{Title: id, Frame: id, Hint: id},
	}
}

func key() tea.KeyMsg { return tea.KeyMsg(tea.KeyPressMsg{}) }

func opened() *State {
	s := &State{}
	in := textinput.New()
	in.Prompt = "/ "
	s.SetInput(in)
	s.Open("_start", 4)
	return s
}

func disasmHit(addr uint64) Hit {
	return Hit{Facet: FacetDisasm, Addr: addr, HasAddr: true, Text: "call", Sym: "caller"}
}
func dataHit(off uint64) Hit {
	return Hit{Facet: FacetData, Off: off, Text: "pointer word", Sym: ".data"}
}

func TestOpenStartsRunningWithEverySourcePending(t *testing.T) {
	s := opened()
	if !s.Active() || !s.Running() || s.Pending() != 4 {
		t.Fatalf("Open: active=%v running=%v pending=%d", s.Active(), s.Running(), s.Pending())
	}
	if s.Facet() != FacetAll {
		t.Errorf("facet = %v, want FacetAll", s.Facet())
	}
	// Every source facet is scanning; "all" reports the overall running flag.
	for _, f := range []Facet{FacetDisasm, FacetData, FacetStrings, FacetRelocs} {
		s.SetFacet(f)
		if !s.FacetStillScanning() {
			t.Errorf("facet %v should be scanning before any source reports", f)
		}
	}
}

// TestAddHitsFinishesOnlyOnTheLastSource: the "✓ N found" state and the final
// status line must wait for every source, not the first one back.
func TestAddHitsFinishesOnlyOnTheLastSource(t *testing.T) {
	s := opened()
	for i, f := range []Facet{FacetDisasm, FacetData, FacetStrings} {
		if finished := s.AddHits(f, nil); finished {
			t.Fatalf("source %d (%v) reported the scan finished early", i, f)
		}
		if !s.Running() {
			t.Fatalf("scan stopped running after source %d", i)
		}
	}
	if finished := s.AddHits(FacetRelocs, nil); !finished {
		t.Error("the last source did not finish the scan")
	}
	if s.Running() {
		t.Error("scan still running after every source reported")
	}
}

// TestFacetStillScanningIsPerSource: a reported facet stops "searching" even
// while other sources are still running — that distinction is the whole reason
// the overlay tracks per-facet state.
func TestFacetStillScanningIsPerSource(t *testing.T) {
	s := opened()
	s.AddHits(FacetData, []Hit{dataHit(0x10)})

	s.SetFacet(FacetData)
	if s.FacetStillScanning() {
		t.Error("data reported but still marked scanning")
	}
	s.SetFacet(FacetDisasm)
	if !s.FacetStillScanning() {
		t.Error("disasm has not reported but is not marked scanning")
	}
	s.SetFacet(FacetAll)
	if !s.FacetStillScanning() {
		t.Error("all should report scanning while any source runs")
	}
}

func TestFacetFiltersRowsAndCyclesBothWays(t *testing.T) {
	s := opened()
	s.AddHits(FacetDisasm, []Hit{disasmHit(0x1000), disasmHit(0x2000)})
	s.AddHits(FacetData, []Hit{dataHit(0x10)})

	if s.Shown() != 3 {
		t.Fatalf("all facet shows %d, want 3", s.Shown())
	}
	host := &fakeHost{}
	s.Update(host, key(), "tab") // → disasm
	if s.Facet() != FacetDisasm || s.Shown() != 2 {
		t.Errorf("after tab: facet=%v shown=%d, want disasm/2", s.Facet(), s.Shown())
	}
	s.Update(host, key(), "shift+tab") // → back to all
	if s.Facet() != FacetAll || s.Shown() != 3 {
		t.Errorf("after shift+tab: facet=%v shown=%d, want all/3", s.Facet(), s.Shown())
	}
	// shift+tab from "all" wraps to the last facet.
	s.Update(host, key(), "shift+tab")
	if s.Facet() != FacetRelocs {
		t.Errorf("shift+tab from all = %v, want relocs (wrap)", s.Facet())
	}
}

// TestRowsGroupByFacetThenAddress: hits stream in per source, so the display
// order must not depend on which source reported first.
func TestRowsGroupByFacetThenAddress(t *testing.T) {
	s := opened()
	s.AddHits(FacetData, []Hit{dataHit(0x20), dataHit(0x10)})
	s.AddHits(FacetDisasm, []Hit{disasmHit(0x2000), disasmHit(0x1000)})

	var got []Hit
	for _, i := range s.shown {
		got = append(got, s.hits[i])
	}
	if len(got) != 4 {
		t.Fatalf("shown %d rows, want 4", len(got))
	}
	if got[0].Facet != FacetDisasm || got[1].Facet != FacetDisasm {
		t.Errorf("disasm hits are not first: %v", got)
	}
	if got[0].Addr != 0x1000 || got[1].Addr != 0x2000 {
		t.Errorf("disasm hits are not address-ordered: %#x %#x", got[0].Addr, got[1].Addr)
	}
	if got[2].Off != 0x10 || got[3].Off != 0x20 {
		t.Errorf("data hits are not offset-ordered: %#x %#x", got[2].Off, got[3].Off)
	}
}

func TestFilterMatchesTextSymbolAndAddress(t *testing.T) {
	for _, tc := range []struct {
		needle string
		want   int
	}{
		{"call", 1},    // text
		{".data", 1},   // symbol
		{"0x1000", 1},  // address
		{"nothing", 0}, // no match
	} {
		t.Run(tc.needle, func(t *testing.T) {
			s := opened()
			s.AddHits(FacetDisasm, []Hit{disasmHit(0x1000)})
			s.AddHits(FacetData, []Hit{dataHit(0x10)})
			s.filter.SetValue(tc.needle)
			s.rebuild()
			if s.Shown() != tc.want {
				t.Errorf("filter %q shows %d rows, want %d", tc.needle, s.Shown(), tc.want)
			}
			if s.total != 2 {
				t.Errorf("total = %d, want 2 (pre-filter)", s.total)
			}
		})
	}
}

// TestActivateCancelsTheScan: the user found what they wanted, so the remaining
// sources should stop rather than keep decoding the image.
func TestActivateCancelsTheScan(t *testing.T) {
	s := opened()
	s.AddHits(FacetDisasm, []Hit{disasmHit(0x1000)})
	host := &fakeHost{}

	s.Update(host, key(), "enter")
	if len(host.opened) != 1 || host.opened[0].Addr != 0x1000 {
		t.Errorf("opened = %v, want the selected hit", host.opened)
	}
	if host.cancelled != 1 {
		t.Errorf("cancelled = %d, want 1", host.cancelled)
	}
	if s.Active() {
		t.Error("Enter did not close the overlay")
	}
}

func TestEscCancelsTheScanAndCloses(t *testing.T) {
	s := opened()
	host := &fakeHost{}
	s.Update(host, key(), "esc")
	if s.Active() {
		t.Error("esc did not close the overlay")
	}
	if host.cancelled != 1 {
		t.Errorf("esc did not cancel the scan (cancelled=%d)", host.cancelled)
	}
}

// TestEscInFilterOnlyClearsIt mirrors the xref overlay: two meanings for one key.
func TestEscInFilterOnlyClearsIt(t *testing.T) {
	s := opened()
	s.AddHits(FacetDisasm, []Hit{disasmHit(0x1000)})
	host := &fakeHost{}

	s.Update(host, key(), "/")
	if !s.Filtering() {
		t.Fatal("/ did not focus the filter")
	}
	s.filter.SetValue("nothing")
	s.rebuild()
	s.Update(host, key(), "esc")
	if s.Filtering() || !s.Active() {
		t.Errorf("esc in filter: filtering=%v active=%v", s.Filtering(), s.Active())
	}
	if host.cancelled != 0 {
		t.Error("esc in the filter cancelled the scan")
	}
	if s.Shown() != 1 {
		t.Errorf("esc did not clear the filter: shown=%d", s.Shown())
	}
}

func TestActivateWithNoRowsIsInert(t *testing.T) {
	s := opened()
	host := &fakeHost{}
	s.Activate(host)
	if len(host.opened) != 0 || host.cancelled != 0 {
		t.Errorf("activate with no rows: opened=%v cancelled=%d", host.opened, host.cancelled)
	}
}

func TestStopScanClearsRunning(t *testing.T) {
	s := opened()
	s.StopScan()
	if s.Running() {
		t.Error("StopScan left the overlay claiming to search")
	}
}

// TestRenderSearchingVsFinished: the header and the empty-state message both
// depend on whether the active facet's source has reported.
func TestRenderSearchingVsFinished(t *testing.T) {
	s := opened()
	out := s.Render(testCtx())
	if !strings.Contains(out, "● searching 4 sources") {
		t.Errorf("mid-scan header missing:\n%s", out)
	}
	if !strings.Contains(out, "searching …") {
		t.Error("mid-scan empty state should say searching, not 'no occurrences'")
	}

	for _, f := range []Facet{FacetDisasm, FacetData, FacetStrings, FacetRelocs} {
		s.AddHits(f, nil)
	}
	out = s.Render(testCtx())
	if !strings.Contains(out, "✓ 0 found") {
		t.Errorf("finished header missing:\n%s", out)
	}
	if !strings.Contains(out, "no occurrences found") {
		t.Error("finished empty state should say no occurrences")
	}
}

func TestRenderShowsFacetBarCounts(t *testing.T) {
	s := opened()
	s.AddHits(FacetDisasm, []Hit{disasmHit(0x1000), disasmHit(0x2000)})
	s.AddHits(FacetData, []Hit{dataHit(0x10)})
	out := s.Render(testCtx())
	for _, want := range []string{"all 3", "disasm 2", "data 1", "Find _start"} {
		if !strings.Contains(out, want) {
			t.Errorf("facet bar missing %q:\n%s", want, out)
		}
	}
	if s.ListRow() != 5 {
		t.Errorf("ListRow = %d, want 5", s.ListRow())
	}
}
