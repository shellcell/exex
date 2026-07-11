package textoverlay

import (
	"strconv"
	"testing"
)

const pageStep = 8

func rows(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = strconv.Itoa(i)
	}
	return out
}

func TestZeroValueIsClosedAtTheTop(t *testing.T) {
	var s Scroller
	if s.Active() || s.ScrollOffset() != 0 {
		t.Errorf("zero value: active=%v scroll=%d", s.Active(), s.ScrollOffset())
	}
}

func TestOpenResetsScroll(t *testing.T) {
	var s Scroller
	s.Scroll(30)
	s.Open()
	if !s.Active() || s.ScrollOffset() != 0 {
		t.Errorf("Open: active=%v scroll=%d, want true/0", s.Active(), s.ScrollOffset())
	}
}

func TestScrollKeysDoNotClose(t *testing.T) {
	for _, key := range []string{"up", "k", "down", "j", "pgup", "pgdown", "home", "g", "end", "G"} {
		var s Scroller
		s.Open()
		s.Update(key, pageStep)
		if !s.Active() {
			t.Errorf("scroll key %q closed the overlay", key)
		}
	}
}

// TestAnyOtherKeyDismisses is the documented behaviour: these overlays are a
// glance, not a mode.
func TestAnyOtherKeyDismisses(t *testing.T) {
	for _, key := range []string{"esc", "q", "?", "x", "enter", "/"} {
		var s Scroller
		s.Open()
		s.Update(key, pageStep)
		if s.Active() {
			t.Errorf("%q did not dismiss the overlay", key)
		}
	}
}

func TestPageStepIsPerOverlay(t *testing.T) {
	var s Scroller
	s.Open()
	s.Update("pgdown", 10)
	if s.ScrollOffset() != 10 {
		t.Errorf("pgdown with step 10 = %d", s.ScrollOffset())
	}
	s.Update("pgup", 3)
	if s.ScrollOffset() != 7 {
		t.Errorf("pgup with step 3 = %d, want 7", s.ScrollOffset())
	}
}

// TestWindowClampsBothEnds: Scroll and the "end" key are deliberately unbounded,
// because the row count is not known until render. Window is what clamps.
func TestWindowClampsBothEnds(t *testing.T) {
	const height = 20 // BodyRows = 12
	body := BodyRows(height)
	all := rows(30)

	var s Scroller
	s.Open()
	s.Update("end", pageStep)
	if s.ScrollOffset() != endSentinel {
		t.Fatalf("end set scroll to %d, want the sentinel", s.ScrollOffset())
	}
	visible, from, to, scrolled := s.Window(all, height)
	if !scrolled {
		t.Fatal("30 rows in a 12-row body should scroll")
	}
	if s.ScrollOffset() != len(all)-body {
		t.Errorf("end clamped to %d, want %d", s.ScrollOffset(), len(all)-body)
	}
	if len(visible) != body || visible[len(visible)-1] != "29" {
		t.Errorf("end did not show the last row: %v", visible)
	}
	if from != len(all)-body+1 || to != len(all) {
		t.Errorf("range %d–%d, want %d–%d", from, to, len(all)-body+1, len(all))
	}

	s.Scroll(-1 << 20)
	visible, from, to, _ = s.Window(all, height)
	if s.ScrollOffset() != 0 || from != 1 || to != body || visible[0] != "0" {
		t.Errorf("scrolling above the top: scroll=%d range=%d–%d first=%q", s.ScrollOffset(), from, to, visible[0])
	}
}

// TestWindowPinsToTopWhenEverythingFits: with nothing to scroll, a stale offset
// must not hide the first rows.
func TestWindowPinsToTopWhenEverythingFits(t *testing.T) {
	var s Scroller
	s.Open()
	s.Scroll(5)
	all := rows(3)
	visible, from, to, scrolled := s.Window(all, 100)
	if scrolled {
		t.Error("3 rows in a tall window should not scroll")
	}
	if s.ScrollOffset() != 0 || len(visible) != 3 || from != 1 || to != 3 {
		t.Errorf("scroll=%d visible=%d range=%d–%d", s.ScrollOffset(), len(visible), from, to)
	}
}

// TestBodyRowsNeverZero: a one-row terminal must still render something rather
// than slicing to an empty window.
func TestBodyRowsNeverZero(t *testing.T) {
	for _, h := range []int{0, 1, 8, 9} {
		if got := BodyRows(h); got < 1 {
			t.Errorf("BodyRows(%d) = %d, want at least 1", h, got)
		}
	}
	if got := BodyRows(20); got != 12 {
		t.Errorf("BodyRows(20) = %d, want 12", got)
	}
}
