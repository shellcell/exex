package ui

import (
	tea "charm.land/bubbletea/v2"
	findtomodal "github.com/rabarbra/exex/internal/ui/modals/findto"
	"testing"
)

// TestFindModalSeedsAndSearch: f collects search seeds from the caret and, on
// selection, opens the global-search results modal for that seed.
func TestFindModalSeedsAndSearch(t *testing.T) {
	h := newKeyHarness(t, systemBinary(t))
	h.goView(modeDisasm, "4")
	h.press("f")
	if !h.m().find.Active() {
		t.Fatalf("f did not open the find modal; status=%q", h.m().status)
	}
	labels := map[string]findtomodal.Seed{}
	for _, s := range h.m().find.Seeds() {
		labels[s.Label] = s
	}
	if _, ok := labels["Address"]; !ok {
		t.Error("no Address seed from a code caret")
	}
	// Enter launches the search and opens the results modal (seed picker closes).
	cmd := h.m().find.Activate(h.m())
	if h.m().find.Active() {
		t.Error("seed picker still open after activate")
	}
	if !h.m().findResultsActive || !h.m().findRunning {
		t.Fatalf("Enter did not start the search: results=%v running=%v", h.m().findResultsActive, h.m().findRunning)
	}
	if cmd == nil {
		t.Fatal("no search command returned")
	}
	if h.m().findPending <= 0 {
		t.Errorf("findPending = %d, want > 0", h.m().findPending)
	}
	// As each source reports, its hits append and the pending count drops; the last
	// one ends the scan.
	pending := h.m().findPending
	for i := 0; i < pending; i++ {
		h.m().handleFindPartial(findPartialMsg{seq: h.m().findSeq, hits: []findHit{{facet: ffData, off: uint64(i)}}})
	}
	if h.m().findRunning {
		t.Error("scan still running after all sources reported")
	}
	if len(h.m().findHits) != pending {
		t.Errorf("got %d hits, want %d (one per source)", len(h.m().findHits), pending)
	}
}

// TestFindModalDigitSearch: a seed's number key selects and searches it directly.
func TestFindModalDigitSearch(t *testing.T) {
	h := newKeyHarness(t, systemBinary(t))
	h.goView(modeDisasm, "4")
	h.press("f")
	if !h.m().find.Active() || len(h.m().find.Seeds()) == 0 {
		t.Skip("no seeds")
	}
	h.m().find.SetSel(0)
	cmd := h.m().find.Activate(h.m())
	if h.m().find.Active() || !h.m().findResultsActive {
		t.Errorf("first seed did not open the results modal: picker=%v results=%v", h.m().find.Active(), h.m().findResultsActive)
	}
	if cmd == nil {
		t.Fatal("no search command")
	}
}

// TestFindModalCopyValue: c copies the highlighted seed's value (the symbol name,
// address, …) and closes.
func TestFindModalCopyValue(t *testing.T) {
	h := newKeyHarness(t, systemBinary(t))
	h.goView(modeDisasm, "4")
	h.press("f")
	if !h.m().find.Active() || len(h.m().find.Seeds()) == 0 {
		t.Skip("no seeds")
	}
	want := h.m().find.Seeds()[h.m().find.Sel()].Value
	h.press("c")
	if h.m().find.Active() {
		t.Error("find modal still open after c")
	}
	if h.m().lastCopy != want {
		t.Errorf("c copied %q, want the selected seed value %q", h.m().lastCopy, want)
	}
}

// TestFindFallbackToGoto: a view with no seeds (Info's has an address caret, so
// use a tree group with none) opens the goto portal directly rather than an empty
// picker. Here we assert the modal is never shown empty.
func TestFindModalNeverEmpty(t *testing.T) {
	h := newKeyHarness(t, systemBinary(t))
	h.goView(modeLibs, "8")
	h.press("f")
	// Either seeds were found (picker open) or it reported "nothing to search" —
	// never an empty picker.
	if h.m().find.Active() && len(h.m().find.Seeds()) == 0 {
		t.Error("find modal opened with no seeds")
	}
}

// TestFindSearchFacetsAndStreaming: hits stream in per source, the facet bar
// filters by view, and a facet still scanning reports "searching" not "empty".
func TestFindSearchFacetsAndStreaming(t *testing.T) {
	h := newKeyHarness(t, systemBinary(t))
	h.goView(modeDisasm, "4")
	h.press("f")
	if !h.m().find.Active() {
		t.Skip("no seeds")
	}
	for i, s := range h.m().find.Seeds() {
		if s.Label == "Address" {
			h.m().find.SetSel(i)
		}
	}
	if cmd := h.m().find.Activate(h.m()); cmd == nil {
		t.Fatal("no search cmd")
	}
	m := h.m()
	if !m.findRunning {
		t.Fatal("search not running")
	}
	// Before any source reports, the disasm facet (still scanning) must report as
	// scanning, not "no occurrences".
	m.findFacet = ffDisasm
	if !m.facetStillScanning() {
		t.Error("disasm facet should be scanning before its source reports")
	}
	// A data source reports two hits; they appear under the data facet.
	m.handleFindPartial(findPartialMsg{seq: m.findSeq, facet: ffData, hits: []findHit{
		{facet: ffData, off: 0x10}, {facet: ffData, off: 0x20},
	}})
	m.findFacet = ffData
	m.rebuildFindRows()
	if len(m.findShown) != 2 {
		t.Errorf("data facet shows %d hits, want 2", len(m.findShown))
	}
	if m.facetStillScanning() {
		t.Error("data facet reported but still marked scanning")
	}
}

// TestFindQueryFreeText: the `l` global search opens a prompt, interprets a hex
// literal as an address query (all address sources) and free text as a string
// query, then runs the same content scan.
func TestFindQueryFreeText(t *testing.T) {
	h := newKeyHarness(t, systemBinary(t))
	h.goView(modeDisasm, "4")
	h.press("l")
	if !h.m().findQueryActive {
		t.Fatal("l did not open the free-text search prompt")
	}
	for _, r := range "0x1000" {
		h.pump(tea.KeyPressMsg(tea.Key{Text: string(r), Code: r}))
	}
	h.press("enter")
	if h.m().findQueryActive {
		t.Error("prompt still open after Enter")
	}
	if !h.m().findResultsActive {
		t.Fatalf("Enter did not start the search; status=%q", h.m().status)
	}
	if !h.m().findQuery.hasAddr {
		t.Error("hex literal not interpreted as an address")
	}

	// Free text stays a string query.
	q := h.m().queryForText("hello")
	if q.text != "hello" {
		t.Errorf("text query text = %q, want hello", q.text)
	}
}
