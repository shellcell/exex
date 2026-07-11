// Package palette is the "Jump to" command palette (the `g` key): type a query,
// pick a scope, and jump to a symbol, section, string, library or address.
//
// (The package is named for what the overlay is rather than for its key, because
// `goto` is a Go keyword.)
//
// The overlay owns the prompt, the scope selector, the result list and its
// geometry. Searching the binary and routing a chosen result to a view are the
// shell's, reached through Host: the ranked symbol search touches the symbol
// table and the demangled-name index, and "jump to this" means different things
// per kind and per active view.
package palette

import (
	"fmt"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/ui/layout"
	"github.com/rabarbra/exex/internal/ui/modal"
	"github.com/rabarbra/exex/internal/ui/scope"
)

// Kind tags a result so it can be coloured and routed to the right view.
type Kind uint8

const (
	KindAddr Kind = iota
	KindSymbol
	KindSection
	KindString
	KindLib
)

// ViewLabel names the view a result of this kind opens in, shown as a badge so a
// mixed (All-scope) result list reads as "found in <view>".
func (k Kind) ViewLabel() string {
	switch k {
	case KindSymbol:
		return "Symbols"
	case KindSection:
		return "Sections"
	case KindString:
		return "Strings"
	case KindLib:
		return "Libs"
	default:
		return "Address"
	}
}

// Target is one selectable palette entry.
type Target struct {
	Kind    Kind
	Label   string
	Addr    uint64
	Off     uint64 // file offset (sections / strings with no virtual address)
	Sym     binfile.Symbol
	HasAddr bool
}

// Host is what the palette needs from the shell beyond the modal base.
type Host interface {
	modal.Host
	// Search returns the entries matching query in the given scope. phys asks for
	// a typed address to be read as a physical (load) address.
	Search(query string, sc scope.Scope, phys bool) []Target
	// Activate routes the chosen result to a view. When hasSel is false there were
	// no results, and typed is the raw prompt text to fall back on.
	Activate(t Target, hasSel bool, typed string)
	// HasPhysAddrs reports whether the binary distinguishes load from virtual
	// addresses, which is the only case where the ^p toggle means anything.
	HasPhysAddrs() bool
}

// State is the palette overlay. Call SetInput once before use.
type State struct {
	active   bool
	input    textinput.Model
	scope    scope.Scope
	addrPhys bool

	results []Target
	sel     int
	top     int
	listRow int
}

// SetInput installs the prompt widget. The shell owns its styling, so it builds
// it and hands it over.
func (s *State) SetInput(in textinput.Model) { s.input = in }

// visibleRows is the constant number of result rows, so the overlay's height
// doesn't bounce up and down as the user types.
func visibleRows(height int) int { return layout.Clamp(height-12, 4, 40) }

// Open focuses the prompt and runs the initial (empty) search.
func (s *State) Open(host Host) {
	s.active = true
	s.input.Focus()
	s.recompute(host)
}

// Close dismisses the palette and resets its transient state, so the next open
// starts from a clean prompt in the All scope.
func (s *State) Close() {
	s.active = false
	s.input.Blur()
	s.input.SetValue("")
	s.results = s.results[:0]
	s.sel, s.top = 0, 0
	s.scope = scope.All
	s.addrPhys = false
}

func (s *State) Active() bool { return s.active }
func (s *State) ListRow() int { return s.listRow }

// Results returns the entries currently listed.
func (s *State) Results() []Target { return s.results }

// Sel returns the selected row index.
func (s *State) Sel() int { return s.sel }

// Scope returns the corpus the palette is searching.
func (s *State) Scope() scope.Scope { return s.scope }

// Value returns the prompt's text.
func (s *State) Value() string { return s.input.Value() }

// SetQuery types q into the prompt and re-runs the search.
func (s *State) SetQuery(host Host, q string) {
	s.input.SetValue(q)
	s.recompute(host)
}

// Selected returns the highlighted result, or ok=false when there are none.
func (s *State) Selected() (Target, bool) {
	if s.sel < 0 || s.sel >= len(s.results) {
		return Target{}, false
	}
	return s.results[s.sel], true
}

func (s *State) List() (sel *int, top, n int, wrap, ok bool) {
	return &s.sel, s.top, len(s.results), false, true
}

func (s *State) ClickRow(listRow int) bool {
	return modal.ClickIndex(&s.sel, s.top, len(s.results), listRow)
}

// recompute rebuilds the result list from the prompt and scope, resetting the
// selection to the top.
func (s *State) recompute(host Host) {
	s.results = host.Search(strings.TrimSpace(s.input.Value()), s.scope, s.addrPhys)
	s.sel, s.top = 0, 0
}

// Activate jumps to the selection and closes.
func (s *State) Activate(host Host) {
	t, ok := s.Selected()
	host.Activate(t, ok, strings.TrimSpace(s.input.Value()))
	s.Close()
}

// Update handles one keypress. Anything that isn't a palette control is typed
// into the prompt, which re-runs the search.
func (s *State) Update(host Host, msg tea.KeyMsg, key string) tea.Cmd {
	switch key {
	case "esc":
		s.Close()
		return nil
	case "up":
		if s.sel > 0 {
			s.sel--
		}
		return nil
	case "down":
		if s.sel < len(s.results)-1 {
			s.sel++
		}
		return nil
	case "enter":
		s.Activate(host)
		return nil
	case "tab":
		s.scope = scope.Next(s.scope)
		s.recompute(host)
		return nil
	case "shift+tab":
		s.scope = scope.Prev(s.scope)
		s.recompute(host)
		return nil
	case "ctrl+p":
		// Toggle physical-address interpretation (only meaningful when LMA differs).
		if host.HasPhysAddrs() {
			s.addrPhys = !s.addrPhys
			s.recompute(host)
		}
		return nil
	}
	var cmd tea.Cmd
	s.input, cmd = s.input.Update(msg)
	s.recompute(host)
	return cmd
}

// HandleInput delivers a non-key message (a paste) to the prompt, re-running the
// search only when the text actually changed.
func (s *State) HandleInput(host Host, msg tea.Msg) tea.Cmd {
	before := s.input.Value()
	var cmd tea.Cmd
	s.input, cmd = s.input.Update(msg)
	if s.input.Value() != before {
		s.recompute(host)
	}
	return cmd
}

// tagStyle colours the kind badge with a distinct hue per kind. In the All scope
// only addr/sym/sec appear, and those three (blue/green/yellow) are clearly
// distinct; str/lib show only in their own scopes.
func tagStyle(ctx modal.Context, k Kind) lipgloss.Style {
	switch k {
	case KindSymbol:
		return ctx.InfoStyle // green
	case KindSection:
		return ctx.WarnStyle // yellow
	case KindString:
		return ctx.ErrorStyle // red
	case KindLib:
		return ctx.ShadowStyle // dim
	default:
		return ctx.AccentStyle // addr — blue
	}
}

// labelStyle colours a result by kind (symbols by their own kind/bind colour,
// like the Symbols view; other kinds by category).
func labelStyle(ctx modal.Context, t Target) lipgloss.Style {
	switch t.Kind {
	case KindSymbol:
		return ctx.SymbolStyle(t.Sym.Kind, t.Sym.Bind)
	case KindSection:
		return ctx.InfoStyle
	case KindString:
		return ctx.RowStyle
	case KindLib:
		return ctx.HeadingStyle
	default:
		return ctx.AccentStyle // address
	}
}

// emptyHint names what the current scope searches.
func (s *State) emptyHint() string {
	switch s.scope {
	case scope.Addr:
		return "a hex/decimal address"
	case scope.Strings:
		return "a printable string"
	case scope.Libs:
		return "a linked library"
	case scope.Sections:
		return "a section name"
	case scope.Symbols:
		return "a symbol name"
	default:
		return "a symbol, section or address"
	}
}

// scopeBar renders the scope selector with the active scope highlighted, plus the
// physical-address toggle when the binary has distinct LMAs.
func (s *State) scopeBar(ctx modal.Context, host Host) string {
	var b strings.Builder
	for sc := scope.Scope(0); sc < scope.Count; sc++ {
		if sc > 0 {
			b.WriteString(ctx.ShadowStyle.Render(" "))
		}
		if sc == s.scope {
			b.WriteString(ctx.SelStyle.Render(" " + sc.String() + " "))
		} else {
			b.WriteString(ctx.ShadowStyle.Render(" " + sc.String() + " "))
		}
	}
	if (s.scope == scope.All || s.scope == scope.Addr) && host.HasPhysAddrs() {
		tag := "virtual"
		if s.addrPhys {
			tag = ctx.WarnStyle.Render("physical")
		}
		b.WriteString(ctx.Hint("   addr: ") + tag + ctx.Hint(" (^p)"))
	}
	return b.String()
}

func (s *State) Render(ctx modal.Context, host Host) string {
	var sb strings.Builder
	rowW := ctx.ListWidth()
	visible := visibleRows(ctx.Height)

	// Header: title, a blank line for breathing room, the scope tabs, and the input
	// — each indented one column to line up with the result rows below.
	sb.WriteString(ctx.Title("Jump to"))
	sb.WriteByte('\n')
	sb.WriteByte('\n')
	sb.WriteString(" " + layout.FitANSIWidth(s.scopeBar(ctx, host), rowW-1))
	sb.WriteByte('\n')
	sb.WriteString(" " + s.input.View())
	sb.WriteByte('\n')
	sb.WriteByte('\n')
	s.listRow = 5 // title + blank + scope bar + input + blank → list at row 5

	// Body: exactly `visible` lines, always — result rows padded out with blanks (or
	// a centred empty hint), so the modal keeps a constant height.
	blank := layout.PadRight("", rowW)
	if len(s.results) == 0 {
		for i := range visible {
			if i == visible/2 {
				hint := ctx.Hint("type to search — " + s.emptyHint())
				sb.WriteString(modal.CenterLine(hint, rowW) + "\n")
			} else {
				sb.WriteString(blank + "\n")
			}
		}
	} else {
		addrW := ctx.AddrHexWidth()
		s.top = layout.VisualTop(s.sel, s.top, len(s.results), visible, func(int) int { return 1 })
		const badgeW = 9
		labelW := max(4, rowW-badgeW-3-addrW-3)
		for row := range visible {
			i := s.top + row
			if i >= len(s.results) {
				sb.WriteString(blank + "\n")
				continue
			}
			t := s.results[i]
			loc := strings.Repeat(" ", 2+addrW)
			if t.HasAddr || t.Kind == KindAddr {
				loc = ctx.AddrStyle.Render(fmt.Sprintf("0x%0*x", addrW, t.Addr))
			}
			badge := tagStyle(ctx, t.Kind).Render(layout.PadVisual(t.Kind.ViewLabel(), badgeW))
			label := labelStyle(ctx, t).Render(layout.TruncateMiddle(t.Label, labelW))
			line := layout.PadRight(fmt.Sprintf(" %s  %s  %s", badge, loc, label), rowW)
			if i == s.sel {
				line = ctx.SelStyle.Render(ansi.Strip(line))
			}
			sb.WriteString(line + "\n")
		}
	}

	count := ""
	if n := len(s.results); n > 0 {
		count = fmt.Sprintf("  (%d/%d)", s.sel+1, n)
	}
	sb.WriteByte('\n')
	sb.WriteString(" " + ctx.Hint("↑/↓ select · ↵ jump · ⇥ scope · Esc cancel"+count))
	return ctx.Frame(sb.String())
}
