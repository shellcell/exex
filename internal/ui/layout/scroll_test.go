package layout

import "testing"

// fixed makes a constant row-height function.
func fixed(h int) func(int) int { return func(int) int { return h } }

func TestMaxViewportTopUniform(t *testing.T) {
	// 10 rows, height 1, viewport of 3 → the last top that fills the window is 7.
	if got := MaxViewportTop(10, 3, fixed(1)); got != 7 {
		t.Fatalf("MaxViewportTop = %d, want 7", got)
	}
	// Everything fits → top 0.
	if got := MaxViewportTop(2, 5, fixed(1)); got != 0 {
		t.Fatalf("MaxViewportTop(fits) = %d, want 0", got)
	}
	if got := MaxViewportTop(0, 3, fixed(1)); got != 0 {
		t.Fatalf("MaxViewportTop(empty) = %d, want 0", got)
	}
}

func TestVisualTopKeepsCursorVisible(t *testing.T) {
	rh := fixed(1)
	// Cursor above the current top pulls the top up to the cursor.
	if got := VisualTop(2, 5, 20, 4, rh); got > 2 {
		t.Fatalf("VisualTop above window = %d, want <= 2", got)
	}
	// Cursor far below scrolls down but never past MaxViewportTop.
	top := VisualTop(19, 0, 20, 4, rh)
	if max := MaxViewportTop(20, 4, rh); top > max {
		t.Fatalf("VisualTop = %d exceeds MaxViewportTop %d", top, max)
	}
	if top < 19-4+1 {
		t.Fatalf("VisualTop = %d does not keep cursor 19 visible in height 4", top)
	}
}

func TestVisualTopVariableHeights(t *testing.T) {
	// Row 0 is tall (3), the rest are 1. A viewport of 3 can't show row 0 plus the
	// cursor at row 2, so the top must advance off the tall row.
	rh := func(i int) int {
		if i == 0 {
			return 3
		}
		return 1
	}
	if got := VisualTop(2, 0, 5, 3, rh); got == 0 {
		t.Fatalf("VisualTop kept the oversized top row; want it scrolled past, got %d", got)
	}
}

func TestVisualItemAtRow(t *testing.T) {
	// Heights [1,2,1]: visual rows 0→item0, 1→item1, 2→item1, 3→item2.
	rh := func(i int) int {
		if i == 1 {
			return 2
		}
		return 1
	}
	cases := map[int]int{0: 0, 1: 1, 2: 1, 3: 2}
	for row, want := range cases {
		if got, ok := VisualItemAtRow(0, 3, row, rh); !ok || got != want {
			t.Fatalf("VisualItemAtRow(row=%d) = %d ok=%v, want %d", row, got, ok, want)
		}
	}
	if _, ok := VisualItemAtRow(0, 3, -1, rh); ok {
		t.Fatalf("VisualItemAtRow(-1) ok=true, want false")
	}
	if _, ok := VisualItemAtRow(0, 3, 99, rh); ok {
		t.Fatalf("VisualItemAtRow(past end) ok=true, want false")
	}
}

func TestViewportTopClamps(t *testing.T) {
	rh := fixed(1)
	if got := ViewportTop(-5, 10, 3, rh); got != 0 {
		t.Fatalf("ViewportTop(negative) = %d, want 0", got)
	}
	if got, max := ViewportTop(100, 10, 3, rh), MaxViewportTop(10, 3, rh); got != max {
		t.Fatalf("ViewportTop(overshoot) = %d, want %d", got, max)
	}
}
