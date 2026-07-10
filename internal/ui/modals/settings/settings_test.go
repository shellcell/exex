package settings

import (
	"fmt"
	"strings"
	"testing"

	"github.com/rabarbra/exex/internal/ui/modal"
)

// fakeHost records what the overlay asked the shell to do. Before the extraction
// none of this was reachable without a whole *ui.Model.
type fakeHost struct {
	cycles   [][2]int // {field, dir}
	persists int
	statuses []string
	values   map[int]string
}

func newHost() *fakeHost { return &fakeHost{values: map[int]string{}} }

func (h *fakeHost) SetStatus(msg string, isErr bool) { h.statuses = append(h.statuses, msg) }
func (h *fakeHost) LoadDisasmAt(uint64)              {}
func (h *fakeHost) CycleSetting(i, dir int)          { h.cycles = append(h.cycles, [2]int{i, dir}) }
func (h *fakeHost) PersistSettings()                 { h.persists++ }
func (h *fakeHost) SettingValue(i int) string {
	if v, ok := h.values[i]; ok {
		return v
	}
	return fmt.Sprintf("v%d", i)
}

func TestMetasCoverEveryField(t *testing.T) {
	if len(Metas) != FieldCount {
		t.Fatalf("Metas has %d entries, FieldCount is %d", len(Metas), FieldCount)
	}
	for i, m := range Metas {
		if m.Group == "" || m.Label == "" || m.Desc == "" {
			t.Errorf("field %d is incompletely described: %+v", i, m)
		}
	}
}

// TestGroupsAreContiguous: RowHeight draws one header per block, which is only
// correct if a group's fields are adjacent.
func TestGroupsAreContiguous(t *testing.T) {
	seen := map[string]bool{}
	for i := range FieldCount {
		g := Metas[i].Group
		if GroupLead(i) {
			if seen[g] {
				t.Errorf("group %q resumes at field %d after another group", g, i)
			}
			seen[g] = true
		}
	}
}

func TestRowHeightAccountsForHeadersAndSeparators(t *testing.T) {
	if got := RowHeight(0); got != 2 {
		t.Errorf("field 0 height = %d, want 2 (header + row, no leading separator)", got)
	}
	// The first field of any later group carries a header and a separator.
	for i := 1; i < FieldCount; i++ {
		want := 1
		if GroupLead(i) {
			want = 3
		}
		if got := RowHeight(i); got != want {
			t.Errorf("field %d height = %d, want %d", i, got, want)
		}
	}
}

func TestNavigationWrapsBothWays(t *testing.T) {
	s := &State{}
	s.Open()
	host := newHost()

	if !s.Active() || s.Cur() != 0 {
		t.Fatalf("Open: active=%v cur=%d", s.Active(), s.Cur())
	}
	// Up from the first field wraps to the last: the settings list cycles.
	s.Update(host, "up")
	if s.Cur() != FieldCount-1 {
		t.Errorf("up from field 0 = %d, want %d (wrap)", s.Cur(), FieldCount-1)
	}
	s.Update(host, "down")
	if s.Cur() != 0 {
		t.Errorf("down from the last field = %d, want 0 (wrap)", s.Cur())
	}
	s.Update(host, "tab")
	if s.Cur() != 1 {
		t.Errorf("tab = %d, want 1", s.Cur())
	}
}

func TestUpdateCyclesAndPersists(t *testing.T) {
	s := &State{}
	s.Open()
	host := newHost()

	s.Update(host, "right")
	s.Update(host, " ")
	s.Update(host, "left")
	want := [][2]int{{0, 1}, {0, 1}, {0, -1}}
	if len(host.cycles) != len(want) {
		t.Fatalf("cycles = %v, want %v", host.cycles, want)
	}
	for i := range want {
		if host.cycles[i] != want[i] {
			t.Errorf("cycle %d = %v, want %v", i, host.cycles[i], want[i])
		}
	}

	// Enter saves and closes; the overlay closes itself, the host only saves.
	s.Update(host, "enter")
	if host.persists != 1 {
		t.Errorf("persists = %d, want 1", host.persists)
	}
	if s.Active() {
		t.Error("Enter did not close the overlay")
	}
}

func TestEscAndCommaCloseWithoutSaving(t *testing.T) {
	for _, key := range []string{"esc", ","} {
		s := &State{}
		s.Open()
		host := newHost()
		s.Update(host, key)
		if s.Active() {
			t.Errorf("%q did not close the overlay", key)
		}
		if host.persists != 0 {
			t.Errorf("%q saved the config", key)
		}
	}
}

func TestActivateCyclesForward(t *testing.T) {
	s := &State{}
	s.Open()
	s.SetCur(5)
	host := newHost()
	s.Activate(host)
	if len(host.cycles) != 1 || host.cycles[0] != [2]int{5, 1} {
		t.Errorf("Activate cycles = %v, want [[5 1]]", host.cycles)
	}
	if !s.Active() {
		t.Error("double-click should not close the overlay")
	}
}

func TestSetCurClamps(t *testing.T) {
	s := &State{}
	s.SetCur(-5)
	if s.Cur() != 0 {
		t.Errorf("SetCur(-5) = %d, want 0", s.Cur())
	}
	s.SetCur(1000)
	if s.Cur() != FieldCount-1 {
		t.Errorf("SetCur(1000) = %d, want %d", s.Cur(), FieldCount-1)
	}
}

// TestClickRowBeforeRenderHitsNothing: lineFields is built during Render, so a
// click that somehow arrives first must not index into a stale/empty slice.
func TestClickRowBeforeRenderHitsNothing(t *testing.T) {
	s := &State{}
	s.Open()
	for _, row := range []int{-1, 0, 5, 999} {
		if s.ClickRow(row) {
			t.Errorf("ClickRow(%d) hit an item before any Render", row)
		}
	}
}

func TestCycleIndexWrapsAndToleratesUnknown(t *testing.T) {
	list := []string{"a", "b", "c"}
	if got := CycleIndex(list, "b", 1); got != 2 {
		t.Errorf("CycleIndex(b,+1) = %d, want 2", got)
	}
	if got := CycleIndex(list, "c", 1); got != 0 {
		t.Errorf("CycleIndex(c,+1) = %d, want 0 (wrap)", got)
	}
	if got := CycleIndex(list, "a", -1); got != 2 {
		t.Errorf("CycleIndex(a,-1) = %d, want 2 (wrap)", got)
	}
	// Case-insensitive, and an unknown value is treated as index 0.
	if got := CycleIndex(list, "B", 1); got != 2 {
		t.Errorf("CycleIndex(B,+1) = %d, want 2 (case-insensitive)", got)
	}
	if got := CycleIndex(list, "zzz", 1); got != 1 {
		t.Errorf("CycleIndex(unknown,+1) = %d, want 1", got)
	}
}

func TestCycleHexBytesPerRow(t *testing.T) {
	if got := CycleHexBytesPerRow(16, 1); got != 32 {
		t.Errorf("16+1 = %d, want 32", got)
	}
	if got := CycleHexBytesPerRow(32, 1); got != 8 {
		t.Errorf("32+1 = %d, want 8 (wrap)", got)
	}
	if got := CycleHexBytesPerRow(8, -1); got != 32 {
		t.Errorf("8-1 = %d, want 32 (wrap)", got)
	}
	// An unset (zero) preference behaves as the 16 default.
	if got := CycleHexBytesPerRow(0, 1); got != 32 {
		t.Errorf("0+1 = %d, want 32", got)
	}
}

func TestThemeListPutsBuiltinsFirstAndDedupes(t *testing.T) {
	list := ThemeList("nord")
	if len(list) < 4 {
		t.Fatalf("theme list too short: %v", list)
	}
	for i, want := range []string{"nord", "dark", "solarized-dark", "solarized-light"} {
		if list[i] != want {
			t.Errorf("list[%d] = %q, want %q", i, list[i], want)
		}
	}
	seen := map[string]int{}
	for _, n := range list {
		seen[n]++
	}
	for _, n := range []string{"nord", "solarized-dark", "solarized-light"} {
		if seen[n] != 1 {
			t.Errorf("%q appears %d times; built-ins that are also Chroma styles must be deduped", n, seen[n])
		}
	}
}

// lineWidth counts display columns, skipping ANSI escapes.
func lineWidth(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			continue
		}
		if s[i]&0xc0 != 0x80 { // count only UTF-8 lead bytes
			n++
		}
	}
	return n
}

// TestRenderNeverOverrunsTheTerminal: the footer hint used to be written without
// a width cap, so on a narrow terminal the footer — not the content — set the
// overlay's minimum width and pushed it past the right edge.
func TestRenderNeverOverrunsTheTerminal(t *testing.T) {
	id := func(s string) string { return s }
	for _, w := range []int{200, 100, 76, 60, 50, 40} {
		s := &State{}
		s.Open()
		ctx := modal.Context{Width: w, Height: 30, Styles: &modal.Styles{Title: id, Frame: id, Hint: id}}
		out := s.Render(ctx, newHost())
		for i, line := range strings.Split(out, "\n") {
			if got := lineWidth(line); got > w {
				t.Errorf("width %d: line %d is %d columns wide", w, i, got)
				break
			}
		}
	}
}
