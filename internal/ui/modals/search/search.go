// Package search is the in-view search prompt (the `/` key): a query box above
// a strip of clickable toggles for the match mode, case sensitivity, direction
// and origin.
//
// The prompt owns the query text and those four options. Running the search —
// which means different things in the hex, disassembly and source views — is the
// shell's, reached through Host.
package search

import (
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/rabarbra/exex/internal/bytesearch"
	"github.com/rabarbra/exex/internal/ui/layout"
	"github.com/rabarbra/exex/internal/ui/modal"
)

// Options is how the prompt is configured to match: the four toggles.
type Options struct {
	Mode          bytesearch.Mode
	CaseSensitive bool
	Forward       bool
	FromCursor    bool
}

// Host is what the prompt needs from the shell beyond the modal base.
type Host interface {
	modal.Host
	// SearchHint describes what the active view searches ("bytes", "instruction
	// text", …), shown under the title.
	SearchHint() string
	// SubmitSearch runs the query in the active view.
	SubmitSearch(query string, o Options) tea.Cmd
	// SearchCaseChanged tells the shell that case sensitivity flipped, so caches
	// whose hits were computed under the old setting must be dropped.
	SearchCaseChanged()
}

// Switch is one clickable toggle: a dim name and the current value, rendered as
// a pill ("name ⟦value⟧").
type Switch struct {
	Name  string
	Value string
}

// Label is the plain "name ⟦value⟧" text. Its width drives both the render and
// the mouse hit-test, so the two cannot drift.
func (s Switch) Label() string { return s.Name + " ⟦" + s.Value + "⟧" }

const (
	// SwitchSep separates the switch segments. Exported so the shell's mouse
	// geometry test can rebuild the strip layout instead of hard-coding it.
	SwitchSep = "   "
	// SwitchLine is the 0-based content row the switch strip occupies inside the
	// overlay (title, hint, blank, input, blank, switches).
	SwitchLine = 5
	// switchIndent is the strip's leading column, matched by Render and ClickAt.
	switchIndent = 1
)

// State is the prompt overlay. Call Init once before use.
type State struct {
	active bool
	input  textinput.Model
	opts   Options
}

// Init installs the prompt widget and the default options: forward, from the
// cursor, case-insensitive, auto mode. They are not the zero values, so a State
// must be initialised rather than merely declared.
func (s *State) Init(in textinput.Model) {
	s.input = in
	s.opts = Options{Mode: bytesearch.ModeAuto, Forward: true, FromCursor: true}
}

func (s *State) ensureInput() {
	if s.input.Prompt == "" {
		s.input = textinput.New()
		s.input.Prompt = "/ "
	}
}

// Open clears the query and focuses the prompt. Repeat search (n/N) still uses
// the last query, but each new prompt starts empty so stale input is not
// accidentally reused.
func (s *State) Open() {
	s.ensureInput()
	s.active = true
	s.input.SetValue("")
	s.input.Focus()
}

func (s *State) Close() {
	s.active = false
	s.input.Blur()
}

func (s *State) Active() bool { return s.active }

// HandleInput delivers a non-key message (a paste) to the query box.
func (s *State) HandleInput(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	s.input, cmd = s.input.Update(msg)
	return cmd
}

// Value returns the typed query.
func (s *State) Value() string { return s.input.Value() }

// SetOptions overrides the toggles (tests, and restoring a saved configuration).
func (s *State) SetOptions(o Options) { s.opts = o }

// Options returns the current match configuration, which the shell also consults
// when repeating a search with n/N.
func (s *State) Options() Options { return s.opts }

// Mode, CaseSensitive, Forward and FromCursor are the individual toggles.
func (s *State) Mode() bytesearch.Mode { return s.opts.Mode }
func (s *State) CaseSensitive() bool   { return s.opts.CaseSensitive }
func (s *State) Forward() bool         { return s.opts.Forward }
func (s *State) FromCursor() bool      { return s.opts.FromCursor }

// Switches returns the mode / case / direction / origin toggles. Render and the
// mouse hit-test both build from this, so they cannot drift.
func (s *State) Switches() []Switch {
	dir := "→ forward"
	if !s.opts.Forward {
		dir = "← backward"
	}
	origin := "cursor"
	if !s.opts.FromCursor {
		if s.opts.Forward {
			origin = "start"
		} else {
			origin = "end"
		}
	}
	caseTag := "insensitive"
	if s.opts.CaseSensitive {
		caseTag = "sensitive"
	}
	return []Switch{
		{"mode", s.opts.Mode.String()},
		{"case", caseTag},
		{"dir", dir},
		{"origin", origin},
	}
}

// toggle flips switch i. Only the case toggle has a side effect on the shell.
func (s *State) toggle(host Host, i int) {
	switch i {
	case 0:
		s.opts.Mode = bytesearch.NextMode(s.opts.Mode)
	case 1:
		s.opts.CaseSensitive = !s.opts.CaseSensitive
		host.SearchCaseChanged()
	case 2:
		s.opts.Forward = !s.opts.Forward
	case 3:
		s.opts.FromCursor = !s.opts.FromCursor
	}
}

// ClickAt toggles the switch under a content column on the switch strip,
// reporting whether one was hit. cx is the 0-based column within the overlay's
// content area; the caller has already checked the row.
func (s *State) ClickAt(host Host, cx int) bool {
	if cx < 0 {
		return false
	}
	pos := switchIndent
	sepW := lipgloss.Width(SwitchSep)
	for i, sw := range s.Switches() {
		w := lipgloss.Width(sw.Label())
		if cx >= pos && cx < pos+w {
			s.toggle(host, i)
			return true
		}
		pos += w + sepW
	}
	return false
}

// Update handles one keypress. Anything that isn't a control types into the
// query box.
func (s *State) Update(host Host, msg tea.KeyMsg, key string) tea.Cmd {
	switch key {
	case "esc":
		s.Close()
		return nil
	case "ctrl+t":
		s.toggle(host, 0)
		return nil
	case "ctrl+i":
		s.toggle(host, 1)
		return nil
	case "ctrl+r":
		s.toggle(host, 2)
		return nil
	case "ctrl+o":
		s.toggle(host, 3)
		return nil
	case "enter":
		query := strings.TrimSpace(s.input.Value())
		s.Close()
		return host.SubmitSearch(query, s.opts)
	}
	var cmd tea.Cmd
	s.input, cmd = s.input.Update(msg)
	return cmd
}

func (s *State) Render(ctx modal.Context, host Host) string {
	s.ensureInput()
	rowW := ctx.ListWidth()
	// Switch strip (content row SwitchLine) — clickable; geometry shared with
	// ClickAt via Switches(). Each switch is a dim name plus the current value in
	// an accent pill. Indented one column to line up with the other elements (and
	// the goto/find overlays).
	var segs []string
	for _, sw := range s.Switches() {
		segs = append(segs, ctx.ShadowStyle.Render(sw.Name)+" "+ctx.SwitchStyle.Render("⟦"+sw.Value+"⟧"))
	}
	switches := strings.Join(segs, SwitchSep)
	help := ctx.Hint("^T mode · ^I case · ^R dir · ^O origin · ↵ find · n/N next/prev · esc cancel")

	var sb strings.Builder
	sb.WriteString(ctx.Title("Search"))
	sb.WriteByte('\n')
	sb.WriteString(" " + ctx.Hint(host.SearchHint()) + "\n")
	sb.WriteByte('\n')
	sb.WriteString(" " + s.input.View() + "\n")
	sb.WriteByte('\n')
	sb.WriteString(" " + switches + "\n") // content row SwitchLine
	sb.WriteByte('\n')
	sb.WriteString(" " + help)
	return ctx.Frame(layout.PadRight(sb.String(), rowW))
}
