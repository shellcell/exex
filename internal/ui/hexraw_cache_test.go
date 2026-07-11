package ui

import (
	"strings"
	"testing"
)

// byteRows is the hex/raw body without its banner line — i.e. exactly the rows
// the memo serves.
func byteRows(m *Model) string {
	lines := strings.Split(m.current().body(), "\n")
	if len(lines) > 1 {
		lines = lines[1:]
	}
	return strings.Join(lines, "\n")
}

// TestHexRowsRestyleOnAThemeChange guards the hex/raw row memo. The rows bake in
// the byte palette and the address colour, so a theme change must drop them — a
// golden frame renders once and so can never catch a cache serving pre-change
// rows.
func TestHexRowsRestyleOnAThemeChange(t *testing.T) {
	for _, md := range []mode{modeHex, modeRaw} {
		t.Run(md.String(), func(t *testing.T) {
			m := goldenModel(t)
			enterMode(t, m, md)
			// Only the byte rows. The whole frame won't do — a theme change restyles
			// the tabs and footer — and neither will the whole body, whose first line
			// is a banner rendered fresh every frame. Either would pass with stale
			// rows underneath.
			before := byteRows(m)

			// Any theme with a different palette will do.
			other := "solarized-light"
			if m.cfg.Theme == other {
				other = "nord"
			}
			m.cfg.Theme = other
			m.applyThemeChange()

			if after := byteRows(m); after == before {
				t.Fatalf("%v rows rendered identically after a theme change — the row cache served stale rows", md)
			}
		})
	}
}

// TestHexRowsFollowTheCaret pins that the memo is keyed on where the caret is:
// moving it must redraw the row it entered (and the one it left), not reuse them.
func TestHexRowsFollowTheCaret(t *testing.T) {
	m := goldenModel(t)
	enterMode(t, m, modeHex)
	before := frame(m)

	for range 4 { // move down a row's worth of bytes
		m.handleKey(keyPress("down"))
	}
	if after := frame(m); after == before {
		t.Fatal("the hex frame did not change after moving the caret — rows were served from the cache")
	}
}
