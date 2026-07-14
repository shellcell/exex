// Package findresults is the global value search's results overlay: every place
// a value occurs across the binary — disasm operands, data words, string
// contents, relocation targets — in one list, tagged by the view it belongs to
// and filterable by that view.
//
// Results stream in: each source scans concurrently and reports when it
// finishes. The overlay therefore owns the streaming *display* state (which
// sources are still running, how many hits arrived), so it can say "searching"
// rather than "no occurrences" while a facet's own scan is still going. Running
// the scans and cancelling them stay in the shell, which owns the event loop.
package findresults

import (
	"fmt"
	"sort"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/shellcell/exex/internal/ui/layout"
	"github.com/shellcell/exex/internal/ui/modal"
)

// Facet selects which source's hits are shown; FacetAll shows every source.
type Facet uint8

const (
	FacetAll Facet = iota
	FacetDisasm
	FacetData
	FacetStrings
	FacetRelocs
	FacetCount
)

func (f Facet) String() string {
	switch f {
	case FacetDisasm:
		return "disasm"
	case FacetData:
		return "data"
	case FacetStrings:
		return "strings"
	case FacetRelocs:
		return "relocs"
	default:
		return "all"
	}
}

// Hit is one occurrence: which source it came from, its address and/or file
// offset, a context string, and the symbol covering it.
type Hit struct {
	Facet   Facet
	Addr    uint64
	Off     uint64
	HasAddr bool
	Text    string
	Sym     string
}

// Host is what the overlay needs from the shell beyond the modal base.
type Host interface {
	modal.Host
	// OpenHit navigates to a hit in the view its facet belongs to.
	OpenHit(h Hit)
	// CancelSearch abandons any source scans still in flight.
	CancelSearch()
}

// State is the results overlay. Call SetInput once before use.
type State struct {
	active bool
	label  string // the value being searched for, for the title

	hits  []Hit
	shown []int // indices into hits after facet + text filter
	sel   int
	top   int
	total int // hits in the active facet before the text filter

	facet     Facet
	filter    textinput.Model
	filtering bool

	// Streaming state: which sources are still scanning, so an empty list can say
	// "searching …" for the active facet rather than "no occurrences found".
	running      bool
	pending      int // source scans still running (0 = done)
	facetPending [FacetCount]bool

	listRow int
}

// SetInput installs the filter widget. The shell owns its styling, so it builds
// it and hands it over.
func (s *State) SetInput(in textinput.Model) { s.filter = in }

func (s *State) ensureInput() {
	if s.filter.Prompt == "" {
		s.filter = textinput.New()
		s.filter.Prompt = "/ "
	}
}

// Open shows the overlay for a search that is about to start, with `sources`
// scans in flight. Hits arrive later through AddHits.
func (s *State) Open(label string, sources int) {
	s.label = label
	s.hits = nil
	s.shown = nil
	s.sel, s.top = 0, 0
	s.facet = FacetAll
	s.total = 0
	s.ensureInput()
	s.filter.SetValue("")
	s.filter.Blur()
	s.filtering = false
	s.active = true
	s.running = true
	s.pending = sources
	s.facetPending = [FacetCount]bool{}
	for f := FacetDisasm; f < FacetCount; f++ {
		s.facetPending[f] = sources > 0
	}
}

// AddHits records one source's finished scan, reporting whether that was the
// last one outstanding.
func (s *State) AddHits(facet Facet, hits []Hit) (finished bool) {
	s.hits = append(s.hits, hits...)
	if int(facet) < len(s.facetPending) {
		s.facetPending[facet] = false
	}
	s.pending--
	if s.pending <= 0 {
		s.running = false
		finished = true
	}
	s.rebuild()
	return finished
}

// StopScan marks the search abandoned, so the overlay stops claiming it is still
// searching.
func (s *State) StopScan() { s.running = false }

func (s *State) Active() bool  { return s.active }
func (s *State) Close()        { s.active = false }
func (s *State) Running() bool { return s.running }
func (s *State) ListRow() int  { return s.listRow }
func (s *State) Sel() int      { return s.sel }

// Hits returns every hit collected so far, across all facets.
func (s *State) Hits() []Hit { return s.hits }

// Shown returns how many rows the active facet + filter leave visible.
func (s *State) Shown() int { return len(s.shown) }

// Pending returns how many source scans are still outstanding.
func (s *State) Pending() int { return s.pending }

// Facet returns the active view facet.
func (s *State) Facet() Facet { return s.facet }

// SetFacet switches the view facet and rebuilds the visible rows.
func (s *State) SetFacet(f Facet) {
	s.facet = f
	s.sel, s.top = 0, 0
	s.rebuild()
}

// Label is the value being searched for.
func (s *State) Label() string { return s.label }

// Filtering reports whether the filter box has the keyboard.
func (s *State) Filtering() bool { return s.filtering }

func (s *State) List() (sel *int, top, n int, wrap, ok bool) {
	return &s.sel, s.top, len(s.shown), false, true
}

func (s *State) ClickRow(listRow int) bool {
	return modal.ClickIndex(&s.sel, s.top, len(s.shown), listRow)
}

// rebuild recomputes the displayed indices for the active facet + text filter.
func (s *State) rebuild() {
	s.shown = s.shown[:0]
	total := 0
	needle := strings.ToLower(strings.TrimSpace(s.filter.Value()))
	for i := range s.hits {
		h := &s.hits[i]
		if s.facet != FacetAll && h.Facet != s.facet {
			continue
		}
		total++
		if needle != "" && !hitMatches(h, needle) {
			continue
		}
		s.shown = append(s.shown, i)
	}
	s.total = total
	// Stable display order — grouped by facet, then address — so streamed-in hits
	// don't reshuffle the list as each source reports.
	sort.SliceStable(s.shown, func(a, b int) bool {
		ha, hb := &s.hits[s.shown[a]], &s.hits[s.shown[b]]
		if ha.Facet != hb.Facet {
			return ha.Facet < hb.Facet
		}
		if ha.Addr != hb.Addr {
			return ha.Addr < hb.Addr
		}
		return ha.Off < hb.Off
	})
	if s.sel >= len(s.shown) {
		s.sel = max(0, len(s.shown)-1)
	}
}

func hitMatches(h *Hit, needle string) bool {
	return layout.ContainsFold(h.Text, needle) || layout.ContainsFold(h.Sym, needle) ||
		layout.ContainsFold(fmt.Sprintf("0x%x", h.Addr), needle)
}

// facetCounts returns the per-facet hit counts for the facet bar.
func (s *State) facetCounts() [FacetCount]int {
	var c [FacetCount]int
	for i := range s.hits {
		c[s.hits[i].Facet]++
	}
	return c
}

// FacetStillScanning reports whether the active facet's source scan is still
// running (so an empty list should say "searching", not "no occurrences").
func (s *State) FacetStillScanning() bool {
	if s.facet == FacetAll {
		return s.running
	}
	return int(s.facet) < len(s.facetPending) && s.facetPending[s.facet]
}

// Update drives the results list: Tab cycles the view facet, / filters, Enter
// jumps, Esc closes (cancelling any running scan).
func (s *State) Update(host Host, msg tea.KeyMsg, key string) tea.Cmd {
	s.ensureInput()
	if s.filtering {
		switch key {
		case "esc":
			s.filter.SetValue("")
			s.filter.Blur()
			s.filtering = false
			s.rebuild()
			return nil
		case "enter":
			return s.Activate(host)
		case "up":
			s.moveSel(-1)
			return nil
		case "down":
			s.moveSel(1)
			return nil
		case "tab":
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

	switch key {
	case "esc":
		s.Close()
		host.CancelSearch()
	case "tab":
		s.facet = (s.facet + 1) % FacetCount
		s.sel, s.top = 0, 0
		s.rebuild()
	case "shift+tab":
		s.facet = (s.facet + FacetCount - 1) % FacetCount
		s.sel, s.top = 0, 0
		s.rebuild()
	case "/":
		s.filtering = true
		return s.filter.Focus()
	case "up", "k":
		s.moveSel(-1)
	case "down", "j":
		s.moveSel(1)
	case "enter", " ":
		return s.Activate(host)
	}
	return nil
}

func (s *State) moveSel(d int) {
	n := len(s.shown)
	if n == 0 {
		return
	}
	s.sel = layout.Clamp(s.sel+d, 0, n-1)
}

// Activate navigates to the selected hit in the view its facet belongs to, and
// cancels any scan still running — the user has found what they wanted.
func (s *State) Activate(host Host) tea.Cmd {
	if s.sel < 0 || s.sel >= len(s.shown) {
		return nil
	}
	h := s.hits[s.shown[s.sel]]
	s.Close()
	host.CancelSearch()
	host.OpenHit(h)
	return nil
}

// facetStyle colours a facet badge/tab by its view.
func facetStyle(ctx modal.Context, f Facet) lipgloss.Style {
	switch f {
	case FacetDisasm:
		return ctx.AccentStyle
	case FacetData:
		return ctx.WarnStyle
	case FacetStrings:
		return ctx.InfoStyle
	case FacetRelocs:
		return ctx.ErrorStyle
	default:
		return ctx.ShadowStyle
	}
}

// runningNote reports how many of the source scans are still in flight, so the
// overlay shows that results are still streaming in.
func (s *State) runningNote() string {
	if s.pending <= 1 {
		return "1 source"
	}
	return fmt.Sprintf("%d sources", s.pending)
}

// visibleRows is the fixed number of result rows, so the overlay's height is
// constant (no vertical bounce as results stream in or the filter narrows).
func visibleRows(height int) int { return layout.Clamp(height-12, 4, 40) }

// facetBar renders the view facets as a segmented control with per-facet counts,
// the active one highlighted.
func (s *State) facetBar(ctx modal.Context) string {
	counts := s.facetCounts()
	var b strings.Builder
	for f := Facet(0); f < FacetCount; f++ {
		if f > 0 {
			b.WriteString(ctx.ShadowStyle.Render(" "))
		}
		label := f.String()
		if f == FacetAll {
			label = fmt.Sprintf("all %d", len(s.hits))
		} else if counts[f] > 0 {
			label = fmt.Sprintf("%s %d", f.String(), counts[f])
		}
		seg := " " + label + " "
		if f == s.facet {
			b.WriteString(ctx.SelStyle.Render(seg))
		} else {
			b.WriteString(ctx.ShadowStyle.Render(seg))
		}
	}
	return b.String()
}

func (s *State) Render(ctx modal.Context) string {
	s.ensureInput()
	var sb strings.Builder
	rowW := ctx.ListWidth()
	visible := visibleRows(ctx.Height)

	sb.WriteString(ctx.Title("Find " + s.label))
	if s.running {
		// Which sources are still scanning (the disasm decode is the slow one).
		sb.WriteString("  " + ctx.WarnStyle.Render("● searching "+s.runningNote()))
	} else {
		sb.WriteString("  " + ctx.InfoStyle.Render(fmt.Sprintf("✓ %d found", len(s.hits))))
	}
	sb.WriteByte('\n')
	sb.WriteByte('\n')
	sb.WriteString(" " + layout.FitANSIWidth(s.facetBar(ctx), rowW-1))
	sb.WriteByte('\n')
	countStr := fmt.Sprintf("  %d", len(s.shown))
	if s.total != len(s.shown) {
		countStr = fmt.Sprintf("  %d of %d", len(s.shown), s.total)
	}
	s.filter.SetWidth(layout.Clamp(rowW-len(countStr)-4, 12, 60))
	sb.WriteString(" " + layout.FitANSIWidth(s.filter.View()+ctx.Hint(countStr), rowW-1))
	sb.WriteByte('\n')
	sb.WriteByte('\n')
	s.listRow = 5 // title + blank + facet bar + filter + blank

	addrW := ctx.AddrHexWidth()
	blank := layout.PadRight("", rowW)
	if len(s.shown) == 0 {
		// "No occurrences" only once the active facet's own scan has finished — while
		// its source is still running (the disasm decode, typically) show "searching".
		msg := "no occurrences found"
		if s.FacetStillScanning() {
			msg = "searching …"
		}
		for i := range visible {
			if i == visible/2 {
				sb.WriteString(modal.CenterLine(ctx.Hint(msg), rowW) + "\n")
			} else {
				sb.WriteString(blank + "\n")
			}
		}
	} else {
		s.top = layout.VisualTop(s.sel, s.top, len(s.shown), visible, func(int) int { return 1 })
		const badgeW = 8
		locW := 2 + addrW
		ctxW := max(6, rowW-1-badgeW-2-locW-2-18)
		for row := range visible {
			r := s.top + row
			if r >= len(s.shown) {
				sb.WriteString(blank + "\n")
				continue
			}
			h := s.hits[s.shown[r]]
			badge := facetStyle(ctx, h.Facet).Render(layout.PadVisual(h.Facet.String(), badgeW))
			loc := layout.PadVisual("", locW)
			switch {
			case h.HasAddr:
				loc = ctx.AddrStyle.Render(fmt.Sprintf("0x%0*x", addrW, h.Addr))
			case h.Off != 0 || h.Facet == FacetData:
				loc = ctx.ShadowStyle.Render(fmt.Sprintf("@0x%0*x", addrW-1, h.Off))
			}
			text := layout.TruncateMiddle(h.Text, ctxW)
			sym := ""
			if h.Sym != "" {
				sym = "  " + ctx.ShadowStyle.Render(layout.TruncateMiddle(h.Sym, 16))
			}
			line := layout.PadRight(fmt.Sprintf(" %s  %s  %s%s", badge, loc, text, sym), rowW)
			if r == s.sel {
				line = ctx.SelStyle.Render(ansi.Strip(line))
			}
			sb.WriteString(line + "\n")
		}
	}

	sb.WriteByte('\n')
	hint := "↑/↓ select · ↵ jump · ⇥ view · / filter · Esc cancel"
	if s.filtering {
		hint = "type to filter · ↵ jump · Tab done · Esc clear"
	}
	sb.WriteString(" " + ctx.Hint(hint))
	return ctx.Frame(sb.String())
}
