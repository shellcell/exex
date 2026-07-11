// Package xref is the cross-references results overlay: every instruction that
// references the address under the disasm cursor, sortable, filterable, and
// followable with Enter.
//
// Finding the references is analysis (explorer.DisasmService.ScanMatching) and
// running it off the UI goroutine is the shell's, since only the shell owns the
// event loop. This package owns what the results look like and how they respond
// to input.
package xref

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/rabarbra/exex/internal/disasm"
	"github.com/rabarbra/exex/internal/ui/layout"
	"github.com/rabarbra/exex/internal/ui/modal"
)

// Hit is one referencing instruction.
type Hit struct {
	Addr uint64 // address of the instruction making the reference
	Text string // its (trimmed) assembly text
	Sym  string // display name of the symbol it lives in, or ""
}

// SortKey selects how the overlay orders references.
type SortKey uint8

const (
	SortAddr SortKey = iota // referencing address
	SortLoc                 // containing symbol
	SortKind                // instruction kind (groups calls / jumps / loads)
	SortKeyCount
)

func (k SortKey) String() string {
	switch k {
	case SortLoc:
		return "location"
	case SortKind:
		return "kind"
	default:
		return "address"
	}
}

// State is the results overlay. Call SetInput once before use.
type State struct {
	active bool
	label  string // display name of the target (symbol or 0x…)

	results []Hit
	shown   []int // indices into results after sort + filter
	sel     int
	top     int

	sort      SortKey
	sortDesc  bool
	filter    textinput.Model
	filtering bool
	total     int // results before the text filter

	listRow int
}

// SetInput installs the filter widget. The shell owns its styling, so it builds
// it and hands it over.
func (s *State) SetInput(in textinput.Model) { s.filter = in }

// ensureInput guarantees the filter is constructed before it is focused or
// rendered, so a State built without SetInput (a bare test model) can't panic.
func (s *State) ensureInput() {
	if s.filter.Prompt == "" {
		s.filter = textinput.New()
		s.filter.Prompt = "/ "
	}
}

// Open shows the overlay for a finished scan, resetting the filter.
func (s *State) Open(label string, hits []Hit) {
	s.label = label
	s.results = hits
	s.sel, s.top = 0, 0
	s.ensureInput()
	s.filter.SetValue("")
	s.filter.Blur()
	s.filtering = false
	s.rebuild()
	s.active = true
}

func (s *State) Active() bool { return s.active }
func (s *State) Close()       { s.active = false }
func (s *State) ListRow() int { return s.listRow }

// Sel returns the selected row index.
func (s *State) Sel() int { return s.sel }

// SetLabel updates the target's display name, for when symbol names change form
// (the demangle toggle) while the overlay is open.
func (s *State) SetLabel(label string) { s.label = label }

// RelabelSymbols re-resolves every row's containing-symbol name and re-sorts, for
// when the shell's symbol display form changes (the demangle or abbreviation
// toggles) while the overlay is open. The sort can depend on the name, so the
// rows have to be rebuilt, not just repainted.
func (s *State) RelabelSymbols(displayAt func(addr uint64) string) {
	for i := range s.results {
		s.results[i].Sym = displayAt(s.results[i].Addr)
	}
	s.rebuild()
}

// Filtering reports whether the filter box has the keyboard.
func (s *State) Filtering() bool { return s.filtering }

func (s *State) List() (sel *int, top, n int, wrap, ok bool) {
	return &s.sel, s.top, len(s.shown), false, true
}

func (s *State) ClickRow(listRow int) bool {
	return modal.ClickIndex(&s.sel, s.top, len(s.shown), listRow)
}

// rebuild recomputes shown (indices into results) for the active sort and filter.
func (s *State) rebuild() {
	rows := s.shown[:0]
	for i := range s.results {
		rows = append(rows, i)
	}
	desc := s.sortDesc
	sort.SliceStable(rows, func(a, b int) bool {
		x, y := s.results[rows[a]], s.results[rows[b]]
		if desc {
			x, y = y, x
		}
		return less(x, y, s.sort)
	})
	s.total = len(rows)
	if needle := strings.ToLower(strings.TrimSpace(s.filter.Value())); needle != "" {
		kept := rows[:0]
		for _, idx := range rows {
			if matches(s.results[idx], needle) {
				kept = append(kept, idx)
			}
		}
		rows = kept
	}
	s.shown = rows
	if s.sel >= len(rows) {
		s.sel = max(0, len(rows)-1)
	}
}

func less(a, b Hit, key SortKey) bool {
	switch key {
	case SortLoc:
		if a.Sym != b.Sym {
			return a.Sym < b.Sym
		}
		return a.Addr < b.Addr
	case SortKind:
		if ka, kb := kindOf(a.Text), kindOf(b.Text); ka != kb {
			return ka < kb
		}
		return a.Addr < b.Addr
	default:
		return a.Addr < b.Addr
	}
}

func matches(h Hit, needle string) bool {
	return layout.ContainsFold(h.Sym, needle) || layout.ContainsFold(h.Text, needle) ||
		layout.ContainsFold("0x"+strconv.FormatUint(h.Addr, 16), needle)
}

// kindOf buckets a referencing instruction so the overlay can colour and sort it:
// 0 call, 1 jump/branch, 2 address-load, 3 other.
func kindOf(text string) int {
	op := disasm.Mnemonic(text)
	switch {
	case strings.HasPrefix(op, "call") || strings.HasPrefix(op, "bl"):
		return 0
	case op == "jmp" || op == "b" || (len(op) > 0 && op[0] == 'j') || strings.HasPrefix(op, "b."):
		return 1
	case disasm.IsAddrLoad(op):
		return 2
	}
	return 3
}

func kindStyle(ctx modal.Context, text string) lipgloss.Style {
	switch kindOf(text) {
	case 0:
		return ctx.InfoStyle // call → green
	case 1:
		return ctx.WarnStyle // jump/branch → yellow
	case 2:
		return ctx.AccentStyle // address load → blue
	default:
		return ctx.ShadowStyle // other → dim
	}
}

// Update drives the results list. While the filter box is focused, typing edits
// it; otherwise s/r sort, / filters, Enter jumps and Esc closes.
func (s *State) Update(host modal.Host, msg tea.KeyMsg, key string) tea.Cmd {
	s.ensureInput()
	rows := s.shown
	if s.filtering {
		switch key {
		case "esc":
			s.filter.SetValue("")
			s.filter.Blur()
			s.filtering = false
			s.sel, s.top = 0, 0
			s.rebuild()
		case "up":
			if s.sel > 0 {
				s.sel--
			}
		case "down":
			if s.sel < len(rows)-1 {
				s.sel++
			}
		case "enter":
			return s.Activate(host)
		default:
			if key == "tab" {
				s.filter.Blur()
				s.filtering = false
				return nil
			}
			var cmd tea.Cmd
			s.filter, cmd = s.filter.Update(msg)
			s.sel, s.top = 0, 0
			s.rebuild()
			return cmd
		}
		return nil
	}
	switch key {
	case "esc":
		s.Close()
	case "/":
		s.filtering = true
		return s.filter.Focus()
	case "s":
		s.sort = (s.sort + 1) % SortKeyCount
		s.sel, s.top = 0, 0
		s.rebuild()
		host.SetStatus("sort: "+s.sort.String(), false)
	case "r":
		s.sortDesc = !s.sortDesc
		s.sel, s.top = 0, 0
		s.rebuild()
	case "up", "k":
		if s.sel > 0 {
			s.sel--
		}
	case "down", "j":
		if s.sel < len(rows)-1 {
			s.sel++
		}
	case "enter":
		return s.Activate(host)
	}
	return nil
}

// Activate follows the selected reference to its instruction in the disasm view.
func (s *State) Activate(host modal.Host) tea.Cmd {
	if s.sel < 0 || s.sel >= len(s.shown) {
		return nil
	}
	addr := s.results[s.shown[s.sel]].Addr
	s.Close()
	host.LoadDisasmAt(addr)
	return nil
}

func (s *State) Render(ctx modal.Context) string {
	s.ensureInput()
	var sb strings.Builder
	addrW := ctx.AddrHexWidth()
	rowW := ctx.ListWidth()
	rows := s.shown
	visible := layout.Clamp(ctx.Height-10, 3, 40) // 2 extra header lines (filter + legend)

	// Column budget: " 0x<addr>  <sym>  <text>". The instruction text in an xref
	// is short (call/lea/branch), so cap it and give the rest to the symbol.
	avail := rowW - len(" ") - (2 + addrW) - len("  ") - len("  ")
	textW := layout.Clamp(avail/3, 12, 40)
	symW := max(8, avail-textW)

	// Title + target name (a possibly long demangled symbol), then a filter box and
	// a colour/sort legend before the rows.
	sb.WriteString(ctx.Title("Cross-references"))
	sb.WriteString("\n")
	targetRows := layout.RenderLineRowsIndented(ctx.HeadingStyle.Render(s.label), rowW, true, 0)
	for _, r := range targetRows {
		sb.WriteString(r)
		sb.WriteString("\n")
	}
	countStr := fmt.Sprintf("  %d", len(rows))
	if s.total != len(rows) {
		countStr = fmt.Sprintf("  %d of %d", len(rows), s.total)
	}
	s.filter.SetWidth(layout.Clamp(rowW-len(countStr)-4, 12, 60))
	sb.WriteString(layout.FitANSIWidth(s.filter.View()+ctx.Hint(countStr), rowW))
	sb.WriteString("\n")
	dir := "↑"
	if s.sortDesc {
		dir = "↓"
	}
	legend := ctx.InfoStyle.Render("call") + ctx.Hint(" · ") +
		ctx.WarnStyle.Render("jump") + ctx.Hint(" · ") +
		ctx.AccentStyle.Render("load") + ctx.Hint("    sort: "+s.sort.String()+dir)
	sb.WriteString(layout.FitANSIWidth(legend, rowW))
	sb.WriteString("\n\n")
	s.listRow = 1 + len(targetRows) + 2 + 1 // title + target line(s) + filter + legend + blank
	s.top = layout.VisualTop(s.sel, s.top, len(rows), visible, func(int) int { return 1 })
	end := min(s.top+visible, len(rows))
	for i := s.top; i < end; i++ {
		h := s.results[rows[i]]
		loc := h.Sym
		if loc == "" {
			loc = "—"
		}
		line := fmt.Sprintf(" 0x%0*x  %s  %s",
			addrW, h.Addr,
			layout.PadVisual(layout.TruncateMiddle(loc, symW), symW),
			kindStyle(ctx, h.Text).Render(layout.TruncateMiddle(h.Text, textW)))
		line = layout.PadRight(line, rowW)
		if i == s.sel {
			line = ctx.SelStyle.Render(ansi.Strip(line))
		}
		sb.WriteString(line)
		sb.WriteString("\n")
	}

	sb.WriteString("\n")
	footer := fmt.Sprintf("↑/↓ select · ↵ jump · s/r sort · / filter · Esc close   (%d/%d)",
		min(s.sel+1, len(rows)), len(rows))
	if s.filtering {
		footer = fmt.Sprintf("type to filter · ↵ jump · Tab done · Esc clear   (%d/%d)",
			min(s.sel+1, len(rows)), len(rows))
	}
	sb.WriteString(ctx.Hint(layout.FitANSIWidth(footer, rowW)))
	return ctx.Frame(sb.String())
}
