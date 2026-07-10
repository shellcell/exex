package jumpto

import (
	"strings"
	"testing"

	"github.com/rabarbra/exex/internal/ui/modal"
)

type fakeHost struct {
	opened   []int
	statuses []string
	errs     []bool
}

func (h *fakeHost) SetStatus(msg string, isErr bool) {
	h.statuses = append(h.statuses, msg)
	h.errs = append(h.errs, isErr)
}
func (h *fakeHost) LoadDisasmAt(uint64) {}
func (h *fakeHost) OpenCaretIn(id int)  { h.opened = append(h.opened, id) }

// testCtx builds a Context whose styles are identity functions, so Render's
// output is plain text and assertions read as what the user sees.
func testCtx() modal.Context {
	id := func(s string) string { return s }
	return modal.Context{Width: 80, Height: 30, Styles: &modal.Styles{Title: id, Frame: id, Hint: id}}
}

func targets() []Target {
	return []Target{
		{ID: 5, Digit: "5", Label: "Hex", Preview: "0x1000 .text", Enabled: true},
		{ID: 6, Digit: "6", Label: "Raw", Preview: "offset 0x1000", Enabled: true},
		{ID: 7, Digit: "7", Label: "Strings", Preview: "no string here", Enabled: false},
	}
}

// disabledFirst puts a disabled row at index 0, so Open must not rest on it.
func disabledFirst() []Target {
	return []Target{
		{ID: 1, Digit: "1", Label: "Disasm", Preview: "not executable", Enabled: false},
		{ID: 5, Digit: "5", Label: "Hex", Preview: "0x1000", Enabled: true},
	}
}

func TestOpenLandsOnFirstEnabledTarget(t *testing.T) {
	s := &State{}
	if !s.Open(Header{Loc: "0x1000"}, disabledFirst()) {
		t.Fatal("Open reported no reachable target")
	}
	if !s.Active() {
		t.Error("Open did not activate the overlay")
	}
	if s.Sel() != 1 {
		t.Errorf("selection = %d, want 1 (the first enabled row)", s.Sel())
	}
}

// TestOpenWithNoEnabledTargetsStaysClosed: a menu where nothing is reachable is
// worse than a status line saying so.
func TestOpenWithNoEnabledTargetsStaysClosed(t *testing.T) {
	s := &State{}
	all := []Target{{Label: "Hex", Enabled: false}, {Label: "Raw", Enabled: false}}
	if s.Open(Header{}, all) {
		t.Error("Open reported a reachable target when none was enabled")
	}
	if s.Active() {
		t.Error("Open activated an overlay with nothing to select")
	}
}

func TestMoveSelSkipsDisabledRows(t *testing.T) {
	s := &State{}
	s.Open(Header{}, targets()) // sel = 0 (Hex)
	host := &fakeHost{}

	s.Update(host, "down") // → Raw (1)
	if s.Sel() != 1 {
		t.Fatalf("after down, sel = %d, want 1", s.Sel())
	}
	// Strings (2) is disabled, so the next down wraps past it back to Hex.
	s.Update(host, "down")
	if s.Sel() != 0 {
		t.Errorf("after second down, sel = %d, want 0 (skipped the disabled row)", s.Sel())
	}
	s.Update(host, "up")
	if s.Sel() != 1 {
		t.Errorf("after up, sel = %d, want 1 (skipped the disabled row backwards)", s.Sel())
	}
}

func TestActivateOpensAndCloses(t *testing.T) {
	s := &State{}
	s.Open(Header{}, targets())
	host := &fakeHost{}

	s.Update(host, "enter")
	if len(host.opened) != 1 || host.opened[0] != 5 {
		t.Errorf("opened = %v, want [5] (Hex's ID)", host.opened)
	}
	if s.Active() {
		t.Error("Activate did not close the overlay")
	}
}

// TestActivateOnDisabledRowReportsAndStaysOpen: the wheel can rest on a disabled
// row, so Enter there must explain rather than silently do nothing.
func TestActivateOnDisabledRowReportsAndStaysOpen(t *testing.T) {
	s := &State{}
	s.Open(Header{}, targets())
	// Land on the disabled row the way the mouse wheel does, bypassing moveSel.
	sel, _, _, _, _ := s.List()
	*sel = 2

	host := &fakeHost{}
	s.Activate(host)
	if len(host.opened) != 0 {
		t.Errorf("a disabled row navigated: %v", host.opened)
	}
	if len(host.statuses) != 1 || !strings.Contains(host.statuses[0], "no string here") {
		t.Errorf("statuses = %v, want the row's reason", host.statuses)
	}
	if !host.errs[0] {
		t.Error("the reason should be reported as an error")
	}
	if !s.Active() {
		t.Error("a disabled row closed the overlay")
	}
}

func TestDigitHotkeyOpensThatTarget(t *testing.T) {
	s := &State{}
	s.Open(Header{}, targets())
	host := &fakeHost{}

	s.Update(host, "6")
	if len(host.opened) != 1 || host.opened[0] != 6 {
		t.Errorf("opened = %v, want [6] (Raw's ID)", host.opened)
	}

	// A digit belonging to a disabled row does nothing.
	s2 := &State{}
	s2.Open(Header{}, targets())
	host2 := &fakeHost{}
	s2.Update(host2, "7")
	if len(host2.opened) != 0 {
		t.Errorf("a disabled row's digit navigated: %v", host2.opened)
	}
	if !s2.Active() {
		t.Error("a disabled row's digit closed the overlay")
	}
}

func TestEscCloses(t *testing.T) {
	s := &State{}
	s.Open(Header{}, targets())
	s.Update(&fakeHost{}, "esc")
	if s.Active() {
		t.Error("esc did not close the overlay")
	}
}

func TestClickRowSelectsAnyRowIncludingDisabled(t *testing.T) {
	s := &State{}
	s.Open(Header{}, targets())
	if !s.ClickRow(2) || s.Sel() != 2 {
		t.Errorf("ClickRow(2): hit=%v sel=%d, want true/2", s.ClickRow(2), s.Sel())
	}
	if s.ClickRow(99) {
		t.Error("ClickRow past the end reported a hit")
	}
	if s.ClickRow(-1) {
		t.Error("ClickRow before the start reported a hit")
	}
}

// TestRenderHeaderLinesDriveListRow: the mouse hit-test maps a click through
// ListRow, so the header's variable height has to be counted exactly.
func TestRenderHeaderLinesDriveListRow(t *testing.T) {
	for _, tc := range []struct {
		name    string
		header  Header
		wantRow int
	}{
		{"loc only", Header{Loc: "0x1000"}, 2},
		{"loc + context", Header{Loc: "0x1000", Context: "_start · .text"}, 3},
		{"loc + context + pointer", Header{Loc: "0x1000", Context: "_start · .text", Pointer: "→ 0x402000"}, 4},
		{"loc + pointer", Header{Loc: "0x1000", Pointer: "→ 0x402000"}, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &State{}
			s.Open(tc.header, targets())
			out := s.Render(testCtx())
			if s.ListRow() != tc.wantRow {
				t.Errorf("ListRow = %d, want %d", s.ListRow(), tc.wantRow)
			}
			if tc.header.Pointer != "" && !strings.Contains(out, tc.header.Pointer) {
				t.Errorf("pointer line missing from the header:\n%s", out)
			}
			if tc.header.Context != "" && !strings.Contains(out, tc.header.Context) {
				t.Errorf("context line missing from the header:\n%s", out)
			}
			if !strings.Contains(out, tc.header.Loc) {
				t.Errorf("location missing from the header:\n%s", out)
			}
		})
	}
}

func TestRenderMarksDisabledRows(t *testing.T) {
	s := &State{}
	s.Open(Header{Loc: "0x1000"}, targets())
	out := s.Render(testCtx())
	for _, want := range []string{"▸", "·", "Hex", "Raw", "Strings", "no string here"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered overlay is missing %q", want)
		}
	}
}
