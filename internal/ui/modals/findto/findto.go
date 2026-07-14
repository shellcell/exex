// Package findto is the "Find from here" seed picker (the `f` key): it lists the
// things at the caret — its address, the pointer it holds, the symbol or section
// covering it, a string, a library path — and on selection launches the global
// value search for that seed.
//
// It is the search counterpart of the jump overlay, which opens the *same*
// position in another view; this searches for the *value* under the caret
// wherever it appears.
//
// Reading the caret is the shell's job (it needs the views and the binary), so
// the shell builds the seeds and this package presents them.
package findto

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/shellcell/exex/internal/ui/layout"
	"github.com/shellcell/exex/internal/ui/modal"
	"github.com/shellcell/exex/internal/ui/scope"
)

// Seed is one candidate search: a label, the query value, the scope it searches,
// a human preview, and — for a located seed (symbol/string/section) — the address
// it resolves to, so the global search can look for references to it.
type Seed struct {
	Label   string
	Value   string
	Scope   scope.Scope
	Preview string
	Addr    uint64
	HasAddr bool
}

// Host is what the picker needs from the shell beyond the modal base.
type Host interface {
	modal.Host
	// StartSearch launches the global value search for a seed.
	StartSearch(seed Seed) tea.Cmd
	CopyToClipboard(text, label string)
}

// State is the seed picker. The zero value is closed.
type State struct {
	active  bool
	sel     int
	seeds   []Seed
	listRow int
}

// Open shows the picker for the seeds found at the caret. It reports whether
// there was anything to show; with no seeds the caller should say so rather than
// opening an empty picker.
func (s *State) Open(seeds []Seed) bool {
	if len(seeds) == 0 {
		return false
	}
	s.seeds, s.sel, s.active = seeds, 0, true
	return true
}

func (s *State) Active() bool { return s.active }
func (s *State) Close()       { s.active = false }
func (s *State) ListRow() int { return s.listRow }

// Seeds returns the candidates the picker is showing.
func (s *State) Seeds() []Seed { return s.seeds }

// Sel returns the selected row index.
func (s *State) Sel() int { return s.sel }

// SetSel selects a seed directly (used by tests and the mouse hit-test).
func (s *State) SetSel(i int) {
	if i >= 0 && i < len(s.seeds) {
		s.sel = i
	}
}

func (s *State) List() (sel *int, top, n int, wrap, ok bool) {
	return &s.sel, 0, len(s.seeds), false, true
}

func (s *State) ClickRow(listRow int) bool {
	return modal.ClickIndex(&s.sel, 0, len(s.seeds), listRow)
}

// Update drives the picker: up/down move, Enter (or a digit) runs the search for
// the seed, c copies the seed's value, Esc closes.
func (s *State) Update(host Host, key string) tea.Cmd {
	switch key {
	case "esc":
		s.Close()
	case "up", "k":
		if s.sel > 0 {
			s.sel--
		}
	case "down", "j":
		if s.sel < len(s.seeds)-1 {
			s.sel++
		}
	case "enter", "space":
		return s.Activate(host)
	case "c":
		// Copy the highlighted seed's value — the symbol name, the address, the
		// string, etc. — so the caret's value can be grabbed without searching.
		if s.sel >= 0 && s.sel < len(s.seeds) {
			seed := s.seeds[s.sel]
			host.CopyToClipboard(seed.Value, strings.ToLower(seed.Label))
		}
		s.Close()
	default:
		if len(key) == 1 && key[0] >= '1' && key[0] <= '9' {
			if i := int(key[0] - '1'); i < len(s.seeds) {
				s.sel = i
				return s.Activate(host)
			}
		}
	}
	return nil
}

// Activate launches the global value search for the selected candidate.
func (s *State) Activate(host Host) tea.Cmd {
	if s.sel < 0 || s.sel >= len(s.seeds) {
		return nil
	}
	return host.StartSearch(s.seeds[s.sel])
}

// seedStyle colours a seed's value by its kind — the address hue for
// addresses/pointers, the symbol hue for symbols, and a readable default for the
// rest — so the value reads as content, not chrome.
func seedStyle(ctx modal.Context, seed Seed) lipgloss.Style {
	switch seed.Scope {
	case scope.Addr:
		return ctx.AddrStyle
	case scope.Symbols:
		return ctx.HeadingStyle
	case scope.Strings:
		return ctx.InfoStyle
	case scope.Sections:
		return ctx.WarnStyle
	default:
		return ctx.RowStyle
	}
}

func (s *State) Render(ctx modal.Context) string {
	var sb strings.Builder
	rowW := ctx.ListWidth()
	sb.WriteString(ctx.Title("Find"))
	sb.WriteByte('\n')
	sb.WriteByte('\n')
	sb.WriteString(" " + ctx.Hint("search the whole binary for the value under the caret") + "\n")
	sb.WriteByte('\n')
	s.listRow = 4 // title + blank + subtitle + blank

	const labelW = 9
	prevW := max(4, rowW-4-2-labelW-3)
	for i, seed := range s.seeds {
		digit := ctx.KeyStyle.Render(fmt.Sprintf("%d", i+1))
		label := ctx.ShadowStyle.Render(layout.PadVisual(seed.Label, labelW))
		where := ctx.ShadowStyle.Render("in " + seed.Scope.String())
		// The value is the point of the row — colour it by kind, never dim.
		preview := seedStyle(ctx, seed).Render(layout.TruncateMiddle(seed.Preview, prevW))
		line := fmt.Sprintf(" %s %s  %s   %s", digit, label, preview, where)
		line = layout.PadRight(line, rowW)
		if i == s.sel {
			line = ctx.SelStyle.Render(ansi.Strip(line))
		}
		sb.WriteString(line + "\n")
	}
	sb.WriteByte('\n')
	sb.WriteString(" " + ctx.Hint("↑/↓ select · ↵ or digit search · c copy value · Esc cancel"))
	return ctx.Frame(sb.String())
}
