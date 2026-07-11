package xref

import (
	"strings"
	"testing"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/ui/modal"
)

type fakeHost struct {
	loaded   []uint64
	statuses []string
}

func (h *fakeHost) SetStatus(msg string, isErr bool) { h.statuses = append(h.statuses, msg) }
func (h *fakeHost) LoadDisasmAt(addr uint64)         { h.loaded = append(h.loaded, addr) }

// testCtx needs a real (empty) File: Render asks it for the address column width.
func testCtx() modal.Context {
	id := func(s string) string { return s }
	return modal.Context{
		File:   &binfile.File{},
		Width:  100,
		Height: 30,
		Styles: &modal.Styles{Title: id, Frame: id, Hint: id},
	}
}

// hits spans the three sortable dimensions: address order, symbol order, and
// instruction kind — deliberately disagreeing so a sort key can be told apart.
func hits() []Hit {
	return []Hit{
		{Addr: 0x3000, Text: "lea rax, [rip+0x10]", Sym: "alpha"}, // kind 2 (load)
		{Addr: 0x1000, Text: "call 0x9000", Sym: "zeta"},          // kind 0 (call)
		{Addr: 0x2000, Text: "jmp 0x9000", Sym: "mid"},            // kind 1 (jump)
	}
}

func open(t *testing.T) *State {
	t.Helper()
	s := &State{}
	in := textinput.New()
	in.Prompt = "/ "
	s.SetInput(in)
	s.Open("target", hits())
	return s
}

func shownAddrs(s *State) []uint64 {
	out := make([]uint64, 0, len(s.shown))
	for _, i := range s.shown {
		out = append(out, s.results[i].Addr)
	}
	return out
}

func eq(a []uint64, b ...uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestOpenSortsByAddressAndActivates(t *testing.T) {
	s := open(t)
	if !s.Active() || s.Sel() != 0 {
		t.Fatalf("Open: active=%v sel=%d", s.Active(), s.Sel())
	}
	if got := shownAddrs(s); !eq(got, 0x1000, 0x2000, 0x3000) {
		t.Errorf("default order = %#x, want ascending address", got)
	}
}

func TestSortCyclesAddressLocationKind(t *testing.T) {
	s := open(t)
	host := &fakeHost{}

	s.Update(host, tea.KeyMsg(tea.KeyPressMsg{}), "s") // → location
	if got := shownAddrs(s); !eq(got, 0x3000, 0x2000, 0x1000) {
		t.Errorf("by location = %#x, want alpha/mid/zeta", got)
	}
	s.Update(host, tea.KeyMsg(tea.KeyPressMsg{}), "s") // → kind
	if got := shownAddrs(s); !eq(got, 0x1000, 0x2000, 0x3000) {
		t.Errorf("by kind = %#x, want call/jump/load", got)
	}
	s.Update(host, tea.KeyMsg(tea.KeyPressMsg{}), "s") // → back to address
	if got := shownAddrs(s); !eq(got, 0x1000, 0x2000, 0x3000) {
		t.Errorf("wrapped back to address = %#x", got)
	}
	// Each sort change reports the new key on the status line.
	if len(host.statuses) != 3 || !strings.Contains(host.statuses[0], "location") {
		t.Errorf("statuses = %v", host.statuses)
	}
}

func TestReverseSort(t *testing.T) {
	s := open(t)
	s.Update(&fakeHost{}, tea.KeyMsg(tea.KeyPressMsg{}), "r")
	if got := shownAddrs(s); !eq(got, 0x3000, 0x2000, 0x1000) {
		t.Errorf("reversed = %#x, want descending address", got)
	}
}

// TestFilterMatchesSymbolTextAndAddress: the filter box searches all three, so
// "0x2000" finds a row by address and "call" finds one by instruction text.
func TestFilterMatchesSymbolTextAndAddress(t *testing.T) {
	for _, tc := range []struct {
		needle string
		want   []uint64
	}{
		{"zeta", []uint64{0x1000}},   // symbol
		{"jmp", []uint64{0x2000}},    // instruction text
		{"0x3000", []uint64{0x3000}}, // address
		{"ZETA", []uint64{0x1000}},   // case-insensitive
		{"nothing", nil},
	} {
		t.Run(tc.needle, func(t *testing.T) {
			s := open(t)
			s.filter.SetValue(tc.needle)
			s.rebuild()
			if got := shownAddrs(s); !eq(got, tc.want...) {
				t.Errorf("filter %q = %#x, want %#x", tc.needle, got, tc.want)
			}
			if s.total != 3 {
				t.Errorf("total = %d, want 3 (the pre-filter count)", s.total)
			}
		})
	}
}

// TestFilterClampsSelection: filtering to fewer rows than the cursor index must
// not leave the selection past the end.
func TestFilterClampsSelection(t *testing.T) {
	s := open(t)
	s.sel = 2
	s.filter.SetValue("zeta")
	s.rebuild()
	if s.Sel() != 0 {
		t.Errorf("selection = %d after filtering to one row, want 0", s.Sel())
	}
}

func TestActivateJumpsToTheSelectedReference(t *testing.T) {
	s := open(t)
	host := &fakeHost{}
	s.Update(host, tea.KeyMsg(tea.KeyPressMsg{}), "down")
	s.Update(host, tea.KeyMsg(tea.KeyPressMsg{}), "enter")
	if len(host.loaded) != 1 || host.loaded[0] != 0x2000 {
		t.Errorf("jumped to %#x, want [0x2000]", host.loaded)
	}
	if s.Active() {
		t.Error("Enter did not close the overlay")
	}
}

// TestActivateOnEmptyResultsIsInert guards the index bounds when a filter has
// hidden every row.
func TestActivateOnEmptyResultsIsInert(t *testing.T) {
	s := open(t)
	s.filter.SetValue("nothing")
	s.rebuild()
	host := &fakeHost{}
	s.Activate(host)
	if len(host.loaded) != 0 {
		t.Errorf("jumped with no visible rows: %#x", host.loaded)
	}
}

func TestEscClosesButEscInFilterOnlyClearsIt(t *testing.T) {
	s := open(t)
	host := &fakeHost{}

	s.Update(host, tea.KeyMsg(tea.KeyPressMsg{}), "/")
	if !s.Filtering() {
		t.Fatal("/ did not focus the filter")
	}
	s.filter.SetValue("zeta")
	s.rebuild()

	s.Update(host, tea.KeyMsg(tea.KeyPressMsg{}), "esc")
	if s.Filtering() {
		t.Error("esc did not leave the filter")
	}
	if !s.Active() {
		t.Error("esc in the filter closed the whole overlay")
	}
	if got := shownAddrs(s); len(got) != 3 {
		t.Errorf("esc did not clear the filter: %#x", got)
	}

	// A second esc, now outside the filter, closes.
	s.Update(host, tea.KeyMsg(tea.KeyPressMsg{}), "esc")
	if s.Active() {
		t.Error("esc outside the filter did not close the overlay")
	}
}

func TestKindOf(t *testing.T) {
	for _, tc := range []struct {
		text string
		want int
	}{
		{"call 0x1000", 0},
		{"callq 0x1000", 0},
		{"bl #0x20", 0},
		{"jmp 0x1000", 1},
		{"je 0x1000", 1},
		{"b 0x1000", 1},
		{"b.eq 0x1000", 1},
		{"lea rax, [rip+8]", 2},
		{"adrp x0, #0x1000", 2},
		{"mov rax, 1", 3},
	} {
		if got := kindOf(tc.text); got != tc.want {
			t.Errorf("kindOf(%q) = %d, want %d", tc.text, got, tc.want)
		}
	}
}

// TestRelabelSymbolsResorts: the demangle toggle rewrites symbol names, and the
// location sort depends on them, so the rows must be rebuilt not just repainted.
func TestRelabelSymbolsResorts(t *testing.T) {
	s := open(t)
	s.Update(&fakeHost{}, tea.KeyMsg(tea.KeyPressMsg{}), "s") // sort by location
	if got := shownAddrs(s); !eq(got, 0x3000, 0x2000, 0x1000) {
		t.Fatalf("by location = %#x", got)
	}
	// Reverse the names: what was "alpha" becomes "zzz".
	s.RelabelSymbols(func(addr uint64) string {
		switch addr {
		case 0x3000:
			return "zzz"
		case 0x1000:
			return "aaa"
		}
		return "mmm"
	})
	if got := shownAddrs(s); !eq(got, 0x1000, 0x2000, 0x3000) {
		t.Errorf("after relabel = %#x, want re-sorted by the new names", got)
	}
}

func TestClickRowHonoursScrollTop(t *testing.T) {
	s := open(t)
	s.top = 1
	if !s.ClickRow(0) || s.Sel() != 1 {
		t.Errorf("ClickRow(0) with top=1 selected %d, want 1", s.Sel())
	}
	if s.ClickRow(5) {
		t.Error("ClickRow past the end reported a hit")
	}
}

func TestRenderShowsTargetLegendAndRows(t *testing.T) {
	s := open(t)
	out := s.Render(testCtx())
	for _, want := range []string{"Cross-references", "target", "call", "jump", "load", "sort: address", "zeta", "0x0000000000001000"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered overlay is missing %q", want)
		}
	}
	if s.ListRow() < 4 {
		t.Errorf("ListRow = %d, want at least title+target+filter+legend", s.ListRow())
	}
}
