package help

import (
	"strings"
	"testing"

	"github.com/rabarbra/exex/internal/ui/modal"
)

func testCtx(w, h int) modal.Context {
	id := func(s string) string { return s }
	return modal.Context{Width: w, Height: h, Styles: &modal.Styles{Title: id, Frame: id, Hint: id}}
}

func TestOpenResetsScroll(t *testing.T) {
	s := &State{}
	if s.Active() {
		t.Fatal("zero value should be closed")
	}
	s.Scroll(20)
	s.Open()
	if !s.Active() || s.ScrollOffset() != 0 {
		t.Errorf("Open: active=%v scroll=%d, want true/0", s.Active(), s.ScrollOffset())
	}
}

func TestScrollKeysPageTheSheet(t *testing.T) {
	s := &State{}
	s.Open()

	s.Update("down")
	if s.ScrollOffset() != 1 {
		t.Errorf("down = %d, want 1", s.ScrollOffset())
	}
	s.Update("pgdown")
	if s.ScrollOffset() != 1+pageStep {
		t.Errorf("pgdown = %d, want %d", s.ScrollOffset(), 1+pageStep)
	}
	s.Update("home")
	if s.ScrollOffset() != 0 {
		t.Errorf("home = %d, want 0", s.ScrollOffset())
	}
	// Every scroll key must leave the overlay open, or it would vanish mid-read.
	if !s.Active() {
		t.Error("a scroll key closed the overlay")
	}
}

// TestAnyOtherKeyDismisses is the documented behaviour of the cheat sheet: it is
// a glance, not a mode.
func TestAnyOtherKeyDismisses(t *testing.T) {
	for _, key := range []string{"esc", "q", "?", "x", "enter"} {
		s := &State{}
		s.Open()
		s.Update(key)
		if s.Active() {
			t.Errorf("%q did not dismiss the overlay", key)
		}
	}
}

// TestRenderClampsScroll: Scroll() is unbounded because the row count depends on
// the terminal width, so Render is what has to clamp — including the "end" key's
// deliberate 1<<20 overshoot.
func TestRenderClampsScroll(t *testing.T) {
	s := &State{}
	s.Open()
	s.Update("end")
	if s.ScrollOffset() != 1<<20 {
		t.Fatalf("end set scroll to %d, want the sentinel overshoot", s.ScrollOffset())
	}
	out := s.Render(testCtx(120, 20))
	if s.ScrollOffset() >= 1<<20 {
		t.Errorf("Render did not clamp the scroll offset: %d", s.ScrollOffset())
	}
	if !strings.Contains(out, "Keybindings") {
		t.Error("rendered overlay has no title")
	}

	// Scrolling far above the top clamps to zero.
	s.Scroll(-1 << 20)
	s.Render(testCtx(120, 20))
	if s.ScrollOffset() != 0 {
		t.Errorf("scroll above the top = %d, want 0", s.ScrollOffset())
	}
}

// TestRenderTallWindowShowsEverything: when the sheet fits, there is nothing to
// scroll and the offset is pinned to zero.
func TestRenderTallWindowShowsEverything(t *testing.T) {
	s := &State{}
	s.Open()
	s.Scroll(5)
	s.Render(testCtx(200, 200))
	if s.ScrollOffset() != 0 {
		t.Errorf("scroll = %d in a window taller than the sheet, want 0", s.ScrollOffset())
	}
}

// TestRenderNarrowWindowStacksColumns: below the two-column threshold the sheet
// stacks, and must still fit the terminal width.
func TestRenderNarrowWindowStacksColumns(t *testing.T) {
	for _, w := range []int{200, 100, 60, 30} {
		s := &State{}
		s.Open()
		out := s.Render(testCtx(w, 40))
		for i, line := range strings.Split(out, "\n") {
			if got := lineWidth(line); got > w {
				t.Errorf("width %d: line %d is %d columns wide", w, i, got)
				break
			}
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
