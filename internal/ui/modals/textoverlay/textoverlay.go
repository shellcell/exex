// Package textoverlay is the shared behaviour of exex's scrollable text
// overlays: the keybinding cheat-sheet and the raw container header.
//
// Neither has a list or a selection. They show a block of pre-rendered rows,
// page through it when it is taller than the terminal, and dismiss on any key
// that isn't a scroll key. Only the rows and the footer wording differ, so
// everything else lives here.
package textoverlay

import "github.com/rabarbra/exex/internal/ui/layout"

// chromeRows is how many rows the title, footer, border and padding cost, and so
// how much of the terminal's height the body cannot use.
const chromeRows = 8

// endSentinel is the scroll offset the "end" key sets. Window clamps it to the
// real bottom, which the overlay only knows once its rows are built.
const endSentinel = 1 << 20

// Scroller is the state shared by the scrollable text overlays. The zero value is
// closed and scrolled to the top.
type Scroller struct {
	active bool
	scroll int
}

func (s *Scroller) Open()        { s.active, s.scroll = true, 0 }
func (s *Scroller) Close()       { s.active = false }
func (s *Scroller) Active() bool { return s.active }

// Scroll moves the view by delta rows. The offset is clamped by Window, because
// the row count is not known until the overlay renders.
func (s *Scroller) Scroll(delta int) { s.scroll += delta }

// ScrollOffset is the current top row, valid after the last Window call.
func (s *Scroller) ScrollOffset() int { return s.scroll }

// Update handles one keypress: scroll keys page through the rows; any other key
// dismisses the overlay. pageStep is how far PgUp/PgDn move, which differs per
// overlay because their rows differ in density.
func (s *Scroller) Update(key string, pageStep int) {
	switch key {
	case "up", "k":
		s.scroll--
	case "down", "j":
		s.scroll++
	case "pgup":
		s.scroll -= pageStep
	case "pgdown":
		s.scroll += pageStep
	case "home", "g":
		s.scroll = 0
	case "end", "G":
		s.scroll = endSentinel // clamped by Window
	default:
		s.Close()
	}
}

// BodyRows is how many rows of content fit in a terminal of this height.
func BodyRows(height int) int { return max(1, height-chromeRows) }

// Window clamps the scroll offset to rows and returns the visible slice, plus the
// 1-based range it covers. scrolled is false when everything fits, in which case
// the offset is pinned to the top and the caller should show no range.
func (s *Scroller) Window(rows []string, height int) (visible []string, from, to int, scrolled bool) {
	maxRows := BodyRows(height)
	if len(rows) <= maxRows {
		s.scroll = 0
		return rows, 1, len(rows), false
	}
	s.scroll = layout.Clamp(s.scroll, 0, len(rows)-maxRows)
	return rows[s.scroll : s.scroll+maxRows], s.scroll + 1, s.scroll + maxRows, true
}
