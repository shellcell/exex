// Package jumpto is the "open caret position in…" overlay: take the address
// under the cursor and offer to reopen it in each of the other views, each row
// previewing exactly where it would land, above a header describing what the
// address *is*.
//
// The overlay knows nothing about views, caret positions, or the binary. The
// shell resolves all of that into a Header and a list of Targets, each carrying
// an opaque ID it hands back through Host.OpenCaretIn. That keeps the two
// concepts the shell owns — what a view is, and where the caret is — out of here.
package jumpto

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/shellcell/exex/internal/ui/layout"
	"github.com/shellcell/exex/internal/ui/modal"
)

// Target is one row: a destination the caret can be reopened in, a preview of
// where it would land there, and whether that landing is possible.
type Target struct {
	// ID identifies the destination to the shell. The overlay only passes it back.
	ID int
	// Digit is the view-switch shortcut badge, and doubles as a hotkey.
	Digit   string
	Label   string
	Preview string
	Enabled bool
}

// Header describes the caret position the overlay was opened for. Every field is
// pre-rendered plain text; the shell resolves symbols, sections and pointers.
type Header struct {
	Loc     string // "0x1234", or "file 0x10" for an offset-only caret
	Context string // symbol · section, or ""
	Pointer string // the pointer the slot holds, or ""
}

// Host is what the overlay needs from the shell beyond the modal base.
type Host interface {
	modal.Host
	// OpenCaretIn performs the jump for the target with this ID, using the caret
	// the overlay was opened for.
	OpenCaretIn(id int)
}

// State is the jump overlay. The zero value is closed.
type State struct {
	active  bool
	sel     int
	header  Header
	targets []Target
	listRow int
}

// Open shows the overlay and lands the selection on the first reachable target.
// It reports whether any target is reachable; when none is, the caller should
// leave the overlay closed and say so rather than showing a dead menu.
func (s *State) Open(header Header, targets []Target) (anyEnabled bool) {
	s.header, s.targets, s.sel = header, targets, 0
	for i, t := range targets {
		if t.Enabled {
			if !anyEnabled {
				s.sel = i
			}
			anyEnabled = true
		}
	}
	s.active = anyEnabled
	return anyEnabled
}

func (s *State) Active() bool { return s.active }
func (s *State) Close()       { s.active = false }
func (s *State) ListRow() int { return s.listRow }

// Targets returns the rows the overlay is showing.
func (s *State) Targets() []Target { return s.targets }

// Sel returns the selected row index.
func (s *State) Sel() int { return s.sel }

// List exposes the target rows to the shell's shared mouse handling. The wheel
// may rest on a disabled row — Activate reports why rather than navigating —
// which is the pre-existing behaviour, and gentler than skipping rows under a
// scroll gesture.
func (s *State) List() (sel *int, top, n int, wrap, ok bool) {
	return &s.sel, 0, len(s.targets), false, true
}

func (s *State) ClickRow(listRow int) bool {
	return modal.ClickIndex(&s.sel, 0, len(s.targets), listRow)
}

// Update drives the selection: up/down move, a target's view digit jumps
// straight to it, Enter opens the selection, Esc closes.
func (s *State) Update(host Host, key string) tea.Cmd {
	switch key {
	case "esc":
		s.Close()
	case "up", "k":
		s.moveSel(-1)
	case "down", "j":
		s.moveSel(1)
	case "enter", "space":
		return s.Activate(host)
	default:
		if len(key) == 1 && key[0] >= '0' && key[0] <= '9' {
			for i, t := range s.targets {
				if t.Enabled && t.Digit == key {
					s.sel = i
					return s.Activate(host)
				}
			}
		}
	}
	return nil
}

// moveSel moves the selection by d, skipping disabled rows so the keyboard
// cursor always rests on something actionable.
func (s *State) moveSel(d int) {
	n := len(s.targets)
	if n == 0 {
		return
	}
	for range s.targets {
		s.sel = (s.sel + d + n) % n
		if s.targets[s.sel].Enabled {
			return
		}
	}
}

// Activate performs the selected jump and closes. A disabled row reports its
// reason (carried in Preview) instead of navigating, and leaves the overlay open.
func (s *State) Activate(host Host) tea.Cmd {
	if s.sel < 0 || s.sel >= len(s.targets) {
		return nil
	}
	t := s.targets[s.sel]
	if !t.Enabled {
		host.SetStatus(t.Label+": "+t.Preview, true)
		return nil
	}
	s.Close()
	host.OpenCaretIn(t.ID)
	return nil
}

func (s *State) Render(ctx modal.Context) string {
	var sb strings.Builder
	rowW := ctx.ListWidth()

	// Header: the address (or file offset), then what it is (symbol · section)
	// and, for a data slot, the pointer it holds. Count the lines so the mouse
	// hit-test maps rows correctly.
	sb.WriteString(ctx.Title("Open ") + " " + ctx.AddrStyle.Render(s.header.Loc))
	sb.WriteString("\n")
	headerLines := 1
	if s.header.Context != "" {
		sb.WriteString(" " + ctx.HeadingStyle.Render(layout.TruncateANSI(s.header.Context, max(1, rowW-1))) + "\n")
		headerLines++
	}
	if s.header.Pointer != "" {
		sb.WriteString(" " + ctx.ShadowStyle.Render(layout.TruncateANSI(s.header.Pointer, max(1, rowW-1))) + "\n")
		headerLines++
	}
	sb.WriteString("\n")
	headerLines++
	s.listRow = headerLines

	const labelW = 9
	prevW := max(4, rowW-3-2-labelW-3)
	faint := lipgloss.NewStyle().Faint(true)
	for i, t := range s.targets {
		glyph, gStyle := "▸", ctx.AccentStyle
		if !t.Enabled {
			glyph, gStyle = "·", ctx.ShadowStyle
		}
		digit := ctx.KeyStyle.Render(t.Digit)
		label := layout.PadVisual(t.Label, labelW)
		preview := ctx.ShadowStyle.Render(layout.TruncateMiddle(t.Preview, prevW))
		line := fmt.Sprintf(" %s %s  %s  %s", gStyle.Render(glyph), digit, label, preview)
		line = layout.PadRight(line, rowW)
		switch {
		case i == s.sel:
			line = ctx.SelStyle.Render(ansi.Strip(line))
		case !t.Enabled:
			line = faint.Render(ansi.Strip(line))
		}
		sb.WriteString(line + "\n")
	}
	sb.WriteString("\n")
	sb.WriteString(ctx.Hint("↑/↓ select · ↵ or digit open · Esc cancel"))
	return ctx.Frame(sb.String())
}
