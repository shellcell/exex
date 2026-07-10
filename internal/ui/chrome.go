package ui

import (
	"image/color"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/rabarbra/exex/internal/ui/layout"
)

// View renders the screen.
func (m *Model) View() tea.View {
	if m.width == 0 || m.height == 0 {
		return tea.NewView("initializing…")
	}
	// Reuse the last frame when the preceding message changed nothing visible
	// (e.g. a coalesced wheel event that only accumulated scroll), so a flood of
	// such events can't make each redraw rebuild the whole screen.
	if !m.viewDirty && m.viewCache != "" {
		return m.screenView(m.viewCache)
	}
	// The panel background fills the whole frame, not just the body: the tab strip
	// and the footer belong to the panel too. renderViewBackground re-applies the
	// fill after every style reset, so a tab's own colours and the status badge
	// still win over it, and it is a no-op when behavior.background is off.
	parts := []string{
		m.theme.renderViewBackground(m.renderTabs(), m.width),
		m.theme.renderViewBackground(m.current().body(), m.width),
		m.theme.renderViewBackground(m.renderFooter(), m.width),
	}
	out := lipgloss.JoinVertical(lipgloss.Left, parts...)
	if modal := m.renderActiveModal(); modal != "" {
		out = m.overlayCenter(out, modal)
	}
	m.viewCache = out
	m.viewDirty = false
	return m.screenView(out)
}

// screenView wraps a rendered body string in the alt-screen / mouse-mode view
// configuration shared by every frame.
func (m *Model) screenView(out string) tea.View {
	v := tea.NewView(out)
	v.AltScreen = true
	v.MouseMode = tea.MouseModeCellMotion
	return v
}

// Shared modal styling, so every popup (help, goto, search, settings, xrefs,
// path picker) looks the same: a filled title bar, dim hint/footer lines, and a
// common list width.
func (t Theme) modalTitle(s string) string { return t.titleStyle.Render(" " + s + " ") }
func (t Theme) modalHint(s string) string  { return t.footerStyle.Padding(0).Render(s) }
func modalListWidth(termW int) int         { return layout.Clamp(termW-8, 40, 120) }

// centeredModalLine horizontally centres a (possibly styled) line within width w,
// padding both sides — for a modal's empty/status message.
func centeredModalLine(s string, w int) string {
	sw := lipgloss.Width(s)
	if sw >= w {
		return layout.FitANSIWidth(s, w)
	}
	left := (w - sw) / 2
	return strings.Repeat(" ", left) + s + strings.Repeat(" ", w-sw-left)
}

// overlayCenter draws a pre-rendered modal centred over bg.
func (m *Model) overlayCenter(bg, modal string) string {
	mw := lipgloss.Width(modal)
	modal = layout.RenderStyle(modal, mw, m.theme.tableRowStyle)
	modal = m.theme.renderViewBackground(modal, mw)
	mh := lipgloss.Height(modal)
	return layout.Overlay(bg, modal, (m.width-mw)/2, (m.height-mh)/2)
}

// tabItems is the ordered tab strip, shared by renderTabs (drawing) and
// tabHitTest (mouse mapping) so the two never drift apart.
var tabItems = []struct {
	label string
	mode  mode
}{
	{"1·Info", modeInfo},
	{"2·Sections", modeSections},
	{"3·Symbols", modeSymbols},
	{"4·Disasm", modeDisasm},
	{"5·Hex", modeHex},
	{"6·Raw", modeRaw},
	{"7·Strings", modeStrings},
	{"8·Libs", modeLibs},
	{"9·Sources", modeSources},
	{"0·Relocs", modeRelocs},
}

func (m *Model) tabSegment(label string, active bool) string {
	if active {
		return m.theme.activeTabStyle.Render(label)
	}
	return m.theme.tabStyle.Render(label)
}

// tabLabel is a tab's drawn label: the full "4·Disasm" normally, or just its
// number ("4") in compact mode — except the active tab, which keeps its full
// label so the current view is always named even on a narrow terminal.
func tabLabel(label string, active, compact bool) string {
	if compact && !active {
		if num, _, ok := strings.Cut(label, "·"); ok {
			return num
		}
	}
	return label
}

// tabsCompact reports whether the full-label tab strip would overflow the
// terminal width, in which case renderTabs/tabHitTest collapse inactive tabs to
// their numbers.
func (m *Model) tabsCompact() bool {
	w := 0
	for _, s := range m.tabLead() {
		w += lipgloss.Width(s)
	}
	for _, t := range tabItems {
		w += lipgloss.Width(m.tabSegment(t.label, m.mode == t.mode))
	}
	return w > m.width
}

// tabLead is the non-clickable prefix of the tab row: the tool name and a chip
// showing the detected container format (so the UI is honest that it isn't
// ELF-only). Shared by renderTabs and tabHitTest so their geometry matches.
func (m *Model) tabLead() []string {
	return []string{
		m.theme.titleStyle.Render(" ExEx "),
		m.theme.tabStyle.Render(string(m.file.Format)),
	}
}

func (m *Model) renderTabs() string {
	compact := m.tabsCompact()
	segs := m.tabLead()
	for _, t := range tabItems {
		active := m.mode == t.mode
		segs = append(segs, m.tabSegment(tabLabel(t.label, active, compact), active))
	}
	row := lipgloss.JoinHorizontal(lipgloss.Left, segs...)
	// When we've descended into another file (a dependency), show the breadcrumb
	// right-aligned in the tab strip so "where am I" is always visible.
	if bc := m.breadcrumb(); bc != "" {
		avail := m.width - lipgloss.Width(row) - 2
		if avail >= 14 {
			crumb := m.theme.footerStyle.Render(truncLeftWidth(bc, avail-9)) + m.theme.helpKeyStyle.Render(" ^O")
			gap := max(1, m.width-lipgloss.Width(row)-lipgloss.Width(crumb))
			return row + strings.Repeat(" ", gap) + crumb
		}
	}
	// Clamp to width: a too-wide tab strip would wrap and push the whole body
	// down a row (and the status line off-screen).
	return layout.PadRight(row, m.width)
}

// truncLeftWidth trims s from the left to fit w columns, keeping the tail (the
// current file) and prefixing "…".
func truncLeftWidth(s string, w int) string {
	if lipgloss.Width(s) <= w {
		return s
	}
	r := []rune(s)
	for len(r) > 0 && lipgloss.Width(string(r))+1 > w {
		r = r[1:]
	}
	return "…" + string(r)
}

// tabHitTest maps an x column on the tab row to the tab the user clicked. It must
// mirror renderTabs' label choice so click geometry matches what's drawn.
func (m *Model) tabHitTest(x int) (mode, bool) {
	compact := m.tabsCompact()
	pos := 0
	for _, s := range m.tabLead() {
		pos += lipgloss.Width(s)
	}
	for _, t := range tabItems {
		active := m.mode == t.mode
		w := lipgloss.Width(m.tabSegment(tabLabel(t.label, active, compact), active))
		if x >= pos && x < pos+w {
			return t.mode, true
		}
		pos += w
	}
	return 0, false
}

// switchMode changes the active view, building the lazy state a view needs
// before it can render. Shared by the keyboard dispatch and tab clicks. It may
// return a Cmd (the background disasm decode).
func (m *Model) switchMode(md mode) tea.Cmd {
	// Disasm is special: it needs the disassembler and sets the mode before its
	// (possibly background) decode. Every other view prepares its lazy state, then
	// the mode flips.
	if md == modeDisasm {
		if m.dis == nil {
			m.setStatus("no disassembler for this architecture", true)
			return nil
		}
		m.setMode(modeDisasm)
		return disasmView{baseView{m}}.ensure()
	}
	cmd := m.viewFor(md).ensure()
	m.setMode(md)
	return cmd
}

// footerHint is one "key action" pair shown in the footer.
type footerHint struct{ key, desc string }

// globalHints are the commands available everywhere; appended to every view's
// footer so they are never missing. The full reference lives behind '?'.
var globalHints = []footerHint{
	{"g", "goto"}, {"␣", "open in…"}, {"f", "find here"}, {"l", "search all"}, {",", "settings"}, {"?", "help"}, {"q", "quit"},
}

// viewHints returns the current view's primary commands (view-specific only;
// globals are appended by renderFooter). Kept curated — the complete list is in
// the '?' overlay.
func (m *Model) viewHints() []footerHint {
	return m.current().hints()
}

func (m *Model) renderFooter() string {
	keyStyle := m.theme.helpKeyStyle            // accent, bold
	descStyle := m.theme.footerStyle.Padding(0) // muted, no padding
	sep := descStyle.Render(" · ")

	hints := m.viewHints()
	if m.mode == modeInfo {
		hints = append(hints, globalHints...)
	}
	parts := make([]string, 0, len(hints))
	for _, h := range hints {
		parts = append(parts, keyStyle.Render(h.key)+" "+descStyle.Render(h.desc))
	}

	if m.status == "" {
		// No message: hints fill the line, shrinking with an ellipsis if too wide.
		return layout.PadRight(" "+fitJoin(parts, sep, m.width-1), m.width)
	}

	// A status message dominates: it keeps its full width on the right as a badge
	// (its semantic colour as the background — red for errors — with a contrasting
	// foreground) and the hints shrink into whatever is left, so the two never
	// overlap.
	st := m.theme.infoStyle
	if m.statusError {
		st = m.theme.errorStyle
	}
	bg := st.GetForeground()
	badge := lipgloss.NewStyle().Bold(true).Background(bg).Foreground(contrastOn(bg))
	msg := badge.Render(" " + m.status + " ")
	if lipgloss.Width(msg) > m.width {
		msg = layout.FitANSIWidth(msg, m.width)
	}
	msgW := lipgloss.Width(msg)
	left := layout.PadRight(" "+fitJoin(parts, sep, m.width-msgW-1), m.width-msgW)
	return left + msg
}

// contrastOn returns near-black or near-white, whichever reads better on bg, by
// its perceived luminance — so the status badge stays legible whatever colour the
// theme gives info/error messages.
func contrastOn(bg color.Color) color.Color {
	r, g, b, _ := bg.RGBA() // 0–65535, premultiplied
	lum := 0.299*float64(r) + 0.587*float64(g) + 0.114*float64(b)
	if lum > 0.55*0xffff {
		return lipgloss.Color("#1c1c1c") // dark text on a light badge
	}
	return lipgloss.Color("#f5f5f5") // light text on a dark badge
}

// fitJoin joins the rendered parts with sep, keeping only whole parts that fit
// within w visible columns and appending " …" when some are dropped. Used by the
// footer so key-hints degrade gracefully on narrow terminals instead of being
// hard-truncated mid-hint.
func fitJoin(parts []string, sep string, w int) string {
	if w <= 0 || len(parts) == 0 {
		return ""
	}
	sepW := lipgloss.Width(sep)
	var b strings.Builder
	used := 0
	for i, p := range parts {
		add := lipgloss.Width(p)
		if i > 0 {
			add += sepW
		}
		if used+add > w {
			if used+2 <= w { // room for " …"
				b.WriteString(" …")
			}
			break
		}
		if i > 0 {
			b.WriteString(sep)
		}
		b.WriteString(p)
		used += add
	}
	return b.String()
}

// bodyHeight is the number of rows available between tabs and footer.
func (m *Model) bodyHeight() int {
	if m.height <= 2 {
		return 1
	}
	return m.height - 2
}
