// Package cpufeat is the CPU-features overlay: the set of optional instruction
// families (SSE/AVX/NEON/…) a binary requires, the baseline they imply, and how
// often each is used. Enter jumps to a feature's first use.
//
// The scan that produces the set is analysis (internal/dump) and its async
// orchestration is the shell's, since only the shell owns the event loop. This
// package owns what the scan's result looks like and how it responds to input.
package cpufeat

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/shellcell/exex/internal/dump"
	"github.com/shellcell/exex/internal/ui/layout"
	"github.com/shellcell/exex/internal/ui/modal"
)

// visibleRows is how many feature rows fit, leaving room for the modal's title,
// subtitle, footer, border and padding.
func visibleRows(height int) int { return layout.Clamp(height-9, 3, 40) }

// State is the CPU-features overlay. The zero value is closed and empty.
type State struct {
	active  bool
	scanned bool // a scan has completed; set is the cached result

	set   dump.CPUFeatureSet
	feats []string // feature names in display order
	sel   int
	top   int

	listRow int // content row the list starts on; set by Render
}

// Scanned reports whether a completed scan is cached, so the shell can reopen
// the overlay without rescanning.
func (s *State) Scanned() bool { return s.scanned }

// Set returns the cached scan result.
func (s *State) Set() dump.CPUFeatureSet { return s.set }

// Features returns the feature names in display order.
func (s *State) Features() []string { return s.feats }

// Open shows the overlay for a scan result and marks it cached.
func (s *State) Open(set dump.CPUFeatureSet) {
	s.set = set
	s.feats = set.SortedFeatures()
	s.sel, s.top = 0, 0
	s.scanned = true
	s.active = true
}

func (s *State) Active() bool { return s.active }
func (s *State) Close()       { s.active = false }
func (s *State) ListRow() int { return s.listRow }

// List exposes the feature list to the shell's shared mouse handling. Selection
// does not wrap: this is a flat list, not a settings cycle.
func (s *State) List() (sel *int, top, n int, wrap, ok bool) {
	return &s.sel, s.top, len(s.feats), false, true
}

// ClickRow selects the feature on a clicked content row. Rows map 1:1 to
// features, so the shared helper does it.
func (s *State) ClickRow(listRow int) bool {
	return modal.ClickIndex(&s.sel, s.top, len(s.feats), listRow)
}

// Update handles one keypress.
func (s *State) Update(ctx modal.Context, host modal.Host, key string) tea.Cmd {
	switch key {
	case "esc":
		s.Close()
	case "up", "k":
		if s.sel > 0 {
			s.sel--
		}
	case "down", "j":
		if s.sel < len(s.feats)-1 {
			s.sel++
		}
	case "enter":
		return s.Activate(host)
	}
	return nil
}

// Activate jumps to the first use of the selected feature and closes.
func (s *State) Activate(host modal.Host) tea.Cmd {
	if s.sel < 0 || s.sel >= len(s.feats) {
		return nil
	}
	addr, ok := s.set.FirstUse[s.feats[s.sel]]
	if !ok {
		return nil
	}
	s.Close()
	host.LoadDisasmAt(addr)
	return nil
}

func (s *State) Render(ctx modal.Context) string {
	var sb strings.Builder
	rowW := ctx.ListWidth()
	addrW := ctx.AddrHexWidth()
	visible := visibleRows(ctx.Height)

	sb.WriteString(ctx.Title("CPU features"))
	sb.WriteString("\n")
	sub := fmt.Sprintf("%d instructions scanned", s.set.Total)
	if s.set.Baseline != "" {
		sub = ctx.WarnStyle.Render(s.set.Baseline) + ctx.Hint("   ·   "+sub)
	} else {
		sub = ctx.Hint(sub)
	}
	sb.WriteString(layout.FitANSIWidth(sub, rowW))
	sb.WriteString("\n\n")
	s.listRow = 3

	if len(s.feats) == 0 {
		sb.WriteString(" " + ctx.ShadowStyle.Render("only base instructions — no optional CPU features detected") + "\n")
	}
	nameW := 0
	for _, f := range s.feats {
		nameW = max(nameW, len(f))
	}
	nameW = layout.Clamp(nameW, 8, 28)
	s.top = layout.VisualTop(s.sel, s.top, len(s.feats), visible, func(int) int { return 1 })
	end := min(s.top+visible, len(s.feats))
	for i := s.top; i < end; i++ {
		f := s.feats[i]
		line := fmt.Sprintf(" %s  %s ×   %s",
			ctx.InfoStyle.Render(layout.PadVisual(f, nameW)),
			layout.PadVisual(fmt.Sprintf("%d", s.set.Counts[f]), 8),
			ctx.ShadowStyle.Render(fmt.Sprintf("first at 0x%0*x", addrW, s.set.FirstUse[f])))
		line = layout.PadRight(line, rowW)
		if i == s.sel {
			line = ctx.SelStyle.Render(ansi.Strip(line))
		}
		sb.WriteString(line)
		sb.WriteString("\n")
	}
	sb.WriteString("\n")
	sb.WriteString(ctx.Hint(fmt.Sprintf("↑/↓ select · ↵ jump to first use · Esc close   (%d/%d)",
		min(s.sel+1, len(s.feats)), len(s.feats))))
	return ctx.Frame(sb.String())
}
