// Package findquery is the free-text global-search prompt (the `l` key): type a
// symbol name, a string, or a hex address, and it runs the same content scan the
// caret-seeded Find does.
//
// The prompt owns the text and the case-sensitivity toggle. Interpreting the
// text (a 0x… literal is an address; anything else is content) and running the
// scan are the shell's, reached through Host.
package findquery

import (
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"

	"github.com/shellcell/exex/internal/ui/layout"
	"github.com/shellcell/exex/internal/ui/modal"
)

// Host is what the prompt needs from the shell beyond the modal base.
type Host interface {
	modal.Host
	// StartTextSearch runs the global search for a typed query. The shell decides
	// what the text means and reports when there is nothing searchable in it.
	StartTextSearch(text string, caseSensitive bool) tea.Cmd
}

// State is the prompt overlay. Call SetInput once before use.
type State struct {
	active        bool
	input         textinput.Model
	caseSensitive bool // toggled with ^i; off by default
}

// SetInput installs the prompt widget. The shell owns its styling, so it builds
// it and hands it over.
func (s *State) SetInput(in textinput.Model) { s.input = in }

func (s *State) ensureInput() {
	if s.input.Prompt == "" {
		s.input = textinput.New()
		s.input.Prompt = "search "
	}
}

// Open clears the prompt and focuses it. The case-sensitivity toggle is sticky
// across opens, like a search option rather than a per-query field.
func (s *State) Open() {
	s.ensureInput()
	s.input.SetValue("")
	s.active = true
	s.input.Focus()
}

func (s *State) Close() {
	s.active = false
	s.input.Blur()
}

func (s *State) Active() bool { return s.active }

// Value returns the typed text.
func (s *State) Value() string { return s.input.Value() }

// CaseSensitive reports whether matching honours case.
func (s *State) CaseSensitive() bool { return s.caseSensitive }

// Update handles one keypress. Anything that isn't a control types into the
// prompt.
func (s *State) Update(host Host, msg tea.KeyMsg, key string) tea.Cmd {
	switch key {
	case "esc":
		s.Close()
		return nil
	case "ctrl+i":
		s.caseSensitive = !s.caseSensitive
		return nil
	case "enter":
		text := strings.TrimSpace(s.input.Value())
		caseSensitive := s.caseSensitive
		s.Close()
		return host.StartTextSearch(text, caseSensitive)
	}
	var cmd tea.Cmd
	s.input, cmd = s.input.Update(msg)
	return cmd
}

func (s *State) Render(ctx modal.Context) string {
	s.ensureInput()
	rowW := ctx.ListWidth()
	var sb strings.Builder
	sb.WriteString(ctx.Title("Search the binary"))
	sb.WriteByte('\n')
	sb.WriteByte('\n')
	sb.WriteString(" " + s.input.View())
	sb.WriteByte('\n')
	sb.WriteByte('\n')
	caseTag := ctx.Hint("case-insensitive")
	if s.caseSensitive {
		caseTag = ctx.WarnStyle.Render("case-sensitive")
	}
	sb.WriteString(" " + caseTag + ctx.Hint("  (^i)") + "\n")
	sb.WriteByte('\n')
	sb.WriteString(" " + ctx.Hint("↵ search disasm · data · strings · relocs   ·   Esc cancel"))
	return ctx.Frame(layout.PadRight(sb.String(), rowW))
}
