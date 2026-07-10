package findto

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/rabarbra/exex/internal/ui/modal"
	"github.com/rabarbra/exex/internal/ui/scope"
)

type fakeHost struct {
	searched []Seed
	copied   [][2]string // {text, label}
	statuses []string
	cmd      tea.Cmd
}

func (h *fakeHost) SetStatus(msg string, isErr bool) { h.statuses = append(h.statuses, msg) }
func (h *fakeHost) LoadDisasmAt(uint64)              {}
func (h *fakeHost) CopyToClipboard(text, label string) {
	h.copied = append(h.copied, [2]string{text, label})
}
func (h *fakeHost) StartSearch(s Seed) tea.Cmd {
	h.searched = append(h.searched, s)
	return h.cmd
}

func testCtx() modal.Context {
	id := func(s string) string { return s }
	return modal.Context{Width: 80, Height: 30, Styles: &modal.Styles{Title: id, Frame: id, Hint: id}}
}

func seeds() []Seed {
	return []Seed{
		{Label: "Symbol", Value: "_start", Scope: scope.Symbols, Preview: "_start", Addr: 0x401000, HasAddr: true},
		{Label: "Section", Value: ".text", Scope: scope.Sections, Preview: ".text"},
		{Label: "Address", Value: "0x401000", Scope: scope.Addr, Preview: "0x401000"},
	}
}

func TestOpenWithSeeds(t *testing.T) {
	s := &State{}
	if !s.Open(seeds()) {
		t.Fatal("Open reported no seeds")
	}
	if !s.Active() || s.Sel() != 0 {
		t.Errorf("active=%v sel=%d, want true/0", s.Active(), s.Sel())
	}
	if len(s.Seeds()) != 3 {
		t.Errorf("Seeds() = %d entries, want 3", len(s.Seeds()))
	}
}

// TestOpenWithNoSeedsStaysClosed: an empty picker is a dead end; the caller says
// "nothing under the caret to search for" instead.
func TestOpenWithNoSeedsStaysClosed(t *testing.T) {
	s := &State{}
	if s.Open(nil) {
		t.Error("Open reported seeds when there were none")
	}
	if s.Active() {
		t.Error("Open activated an empty picker")
	}
}

func TestNavigationClampsAtBothEnds(t *testing.T) {
	s := &State{}
	s.Open(seeds())
	host := &fakeHost{}

	s.Update(host, "up") // already at the top
	if s.Sel() != 0 {
		t.Errorf("up at the top moved to %d", s.Sel())
	}
	s.Update(host, "down")
	s.Update(host, "down")
	s.Update(host, "down") // already at the bottom
	if s.Sel() != 2 {
		t.Errorf("down at the bottom moved to %d, want 2", s.Sel())
	}
}

func TestEnterStartsSearchForSelectedSeed(t *testing.T) {
	s := &State{}
	s.Open(seeds())
	host := &fakeHost{}

	s.Update(host, "down")
	s.Update(host, "enter")
	if len(host.searched) != 1 || host.searched[0].Value != ".text" {
		t.Errorf("searched = %v, want the .text seed", host.searched)
	}
}

// TestDigitSelectsAndSearches: 1-9 pick a seed directly; a digit past the end is
// ignored rather than searching the wrong thing.
func TestDigitSelectsAndSearches(t *testing.T) {
	s := &State{}
	s.Open(seeds())
	host := &fakeHost{}

	s.Update(host, "3")
	if len(host.searched) != 1 || host.searched[0].Value != "0x401000" {
		t.Errorf("searched = %v, want the address seed", host.searched)
	}
	if s.Sel() != 2 {
		t.Errorf("digit did not move the selection: sel=%d", s.Sel())
	}

	s2 := &State{}
	s2.Open(seeds())
	host2 := &fakeHost{}
	s2.Update(host2, "9") // only three seeds
	if len(host2.searched) != 0 {
		t.Errorf("an out-of-range digit searched: %v", host2.searched)
	}
}

// TestCopyCopiesValueNotPreview: the preview is decorated ("→ 0x…", quoted
// strings); the copied text must be the raw value.
func TestCopyCopiesValueNotPreview(t *testing.T) {
	s := &State{}
	s.Open([]Seed{{Label: "Pointer", Value: "0x402000", Scope: scope.Addr, Preview: "→ 0x402000  msg"}})
	host := &fakeHost{}

	s.Update(host, "c")
	if len(host.copied) != 1 {
		t.Fatalf("copied = %v, want one entry", host.copied)
	}
	if host.copied[0][0] != "0x402000" {
		t.Errorf("copied text = %q, want the raw value", host.copied[0][0])
	}
	if host.copied[0][1] != "pointer" {
		t.Errorf("copied label = %q, want the lowercased seed label", host.copied[0][1])
	}
	if s.Active() {
		t.Error("copy did not close the picker")
	}
	if len(host.searched) != 0 {
		t.Error("copy also started a search")
	}
}

func TestEscClosesWithoutSearching(t *testing.T) {
	s := &State{}
	s.Open(seeds())
	host := &fakeHost{}
	s.Update(host, "esc")
	if s.Active() {
		t.Error("esc did not close the picker")
	}
	if len(host.searched) != 0 {
		t.Error("esc started a search")
	}
}

func TestActivatePropagatesTheHostCommand(t *testing.T) {
	s := &State{}
	s.Open(seeds())
	want := tea.Cmd(func() tea.Msg { return nil })
	host := &fakeHost{cmd: want}
	if got := s.Activate(host); got == nil {
		t.Error("Activate dropped the host's command; the search would never run")
	}
}

func TestClickRow(t *testing.T) {
	s := &State{}
	s.Open(seeds())
	if !s.ClickRow(2) || s.Sel() != 2 {
		t.Errorf("ClickRow(2) did not select row 2 (sel=%d)", s.Sel())
	}
	if s.ClickRow(3) {
		t.Error("ClickRow past the end reported a hit")
	}
}

// TestRenderShowsSeedsAndScopes: each row names its value and the scope it would
// search, which is what makes the picker self-describing.
func TestRenderShowsSeedsAndScopes(t *testing.T) {
	s := &State{}
	s.Open(seeds())
	out := s.Render(testCtx())
	if s.ListRow() != 4 {
		t.Errorf("ListRow = %d, want 4 (title + blank + subtitle + blank)", s.ListRow())
	}
	for _, want := range []string{"Find", "Symbol", "_start", "in symbols", "Section", "in sections", "0x401000", "in address"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered picker is missing %q", want)
		}
	}
	// Rows are numbered from 1, matching the digit hotkeys.
	if !strings.Contains(out, " 1 ") || !strings.Contains(out, " 3 ") {
		t.Errorf("rows are not numbered 1..n:\n%s", out)
	}
}
