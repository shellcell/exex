package ui

import (
	"fmt"
	"image/color"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

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
	parts := []string{m.renderTabs()}
	body := m.theme.renderViewBackground(m.current().body(), m.width)
	parts = append(parts, body, m.renderFooter())
	out := lipgloss.JoinVertical(lipgloss.Left, parts...)
	switch {
	case m.headerActive:
		out = m.overlayCenter(out, m.renderHeaderModal())
	case m.helpActive:
		out = m.overlayCenter(out, m.renderHelpModal())
	case m.settingsActive:
		out = m.overlayCenter(out, m.renderSettingsModal())
	case m.gotoActive:
		out = m.overlayCenter(out, m.renderGotoModal())
	case m.searchActive:
		out = m.overlayCenter(out, m.renderSearchModal())
	case m.xrefActive:
		out = m.overlayCenter(out, m.renderXrefModal())
	case m.syscallActive:
		out = m.overlayCenter(out, m.renderSyscallModal())
	case m.cpufeatActive:
		out = m.overlayCenter(out, m.renderCPUFeatModal())
	case m.jumpActive:
		out = m.overlayCenter(out, m.renderJumpModal())
	case m.findActive:
		out = m.overlayCenter(out, m.renderFindModal())
	case m.findResultsActive:
		out = m.overlayCenter(out, m.renderFindResultsModal())
	case m.findQueryActive:
		out = m.overlayCenter(out, m.renderFindQueryModal())
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

// renderHelpModal lists the keybindings, grouped by scope, in two columns. The
// key column is padded by display width (so multibyte arrows align) and the two
// columns are laid out side by side to keep the modal compact.
// helpEntry is one line of a help column: a section header, a key/description
// row, or a blank spacer.
type helpEntry struct {
	head string // section title (uppercased + ruled) when non-empty
	text string // a pre-rendered key+desc row; "" with no head = blank line
}

func (m *Model) renderHelpModal() string {
	const keyW = 16
	row := func(keys, desc string) helpEntry {
		return helpEntry{text: m.theme.helpKeyStyle.Render(layout.PadVisual(keys, keyW)) + " " + m.theme.helpDescStyle.Render(desc)}
	}
	head := func(s string) helpEntry { return helpEntry{head: s} }
	blank := helpEntry{}

	left := []helpEntry{
		head("Global"),
		row("1–9 · 0", "switch view (0 = relocations)"),
		row("g", "jump to anything (symbol/section/string/lib/addr · ⇥ scope)"),
		row(",", "settings (theme, wrap, …)"),
		row("?", "this help"),
		row("w", "toggle long-line wrap"),
		row("d/h/m", "go to addr in disasm / hex / raw"),
		row("␣ / >", "open caret address in another view (menu)"),
		row("f", "find the value under the caret across the binary"),
		row("l", "search the binary for anything you type (disasm/data/strings/relocs)"),
		row("⇧a/⇧s/⇧l", "copy address / name / line"),
		row("t / ⇥", "switch view"),
		row("/  n/N", "search · next/prev"),
		row("^O", "back (return from an opened dependency)"),
		row("⇧F", "CPU features required (SSE/AVX/NEON · baseline)"),
		row("⇧H", "raw file header (ELF e_* / Mach-O load cmds / PE)"),
		row("q / ^C", "quit"),
		row("↵ Enter", "open / jump"),
		blank,
		head("Lists (all views)"),
		row("/", "filter / search"),
		row("↑/↓", "move line"),
		row("s/r", "sort · reverse"),
		row("PgUp/PgDn  [ ]", "page  ("+layout.CtrlKeys("↑", "↓")+")"),
		row("Home/End ^A/^E", "begin/end"),
		row("Esc", "clear filters"),
		blank,
		head("Tree actions"),
		row("t / ⇥", "toggle namespace tree / flat table"),
		row("←/→", "tree: collapse / expand group"),
		row("↵ · +/−", "tree: expand/collapse all below · all"),
		blank,
		head("Info"),
		row("t / ⇥", "fat-Mach-O arch slice · static-lib members list"),
		row("↵ Enter", "open entry point · open selected member"),
		blank,
		head("Sections"),
		row(layout.CtrlKeys("t", "f"), "filter by type / flags"),
		row("t / ⇥", "cycle sections / segments / header"),
		blank,
		head("Symbols"),
		row(layout.CtrlKeys("t", "b", "s"), "filter by type / bind / scope"),
		row("e / .", "collapse (…)/<…> to ... · all / current"),
	}
	right := []helpEntry{
		head("Disassembly"),
		row("↵ Enter", "follow address"),
		row("[ ]", "previous / next symbol"),
		row("←/→", "history back / forward"),
		row("x", "find references (xrefs)"),
		row("y", "list system calls"),
		row("a", "disassemble all sections / exec-only (object files, data)"),
		row("⇧a/⇧s/⇧c", "copy addr / symbol / function asm"),
		row("Tab", "show / hide right pane"),
		row("⇧Tab", "swap source / disasm"),
		row("⇧↑/⇧↓", "scroll right pane"),
		row("", "modals (xrefs / syscalls): / filter · s/r sort"),
		blank,
		head("Hex / Raw"),
		row("[ ]", "prev / next section"),
		row("⇧[ ⇧]", "prev / next nonzero"),
		row("t / ⇥", "trailing column: ascii ↔ numeric"),
		row("⇧t", "cycle interpretation (i8…i64/u…/f32/f64)"),
		row("i", "data inspector"),
		row("⇧a/⇧s/⇧p", "copy address / symbol / pointer"),
		row("↵ Enter", "follow pointer at cursor"),
		blank,
		head("Sources"),
		row("[ ]", "prev / next mapped line"),
		row(layout.CtrlKeys("p"), "filter: all / present / missing"),
		row("t / ⇥", "toggle directory tree / flat list"),
		row("↵ Enter / o", "open in disasm source-first view"),
		blank,
		head("Libraries / Relocations"),
		row("8 / 0", "libraries view / relocations view"),
		row("o", "(libs) open as primary"),
		row(layout.CtrlKeys("p"), "(libs) filter all/on-disk/cache"),
		row("t / ⇥", "(libs) flat ↔ tree"),
		row("↵", "libs: imported symbols · relocs: go to patched addr"),
		row("s/r  "+layout.CtrlKeys("t", "s"), "(relocs) sort/rev · type/section filter"),
		blank,
		head("Strings"),
		row(layout.CtrlKeys("s"), "filter by section"),
		row(layout.CtrlKeys("p"), "filter to paths only"),
		row("t / ⇥", "table ↔ compact (· flow) layout"),
	}

	leftLines := m.helpColumn(left)
	rightLines := m.helpColumn(right)
	lw, rw := lipgloss.Width(leftLines[0]), lipgloss.Width(rightLines[0])

	// Two side-by-side columns when they fit the terminal; otherwise stack into a
	// single column so the modal never overruns a narrow window.
	var bodyRows []string
	if lw+rw+6 <= m.width-6 {
		div := m.theme.srcShadowStyle.Render("│")
		n := max(len(leftLines), len(rightLines))
		for i := range n {
			l, r := layout.PadVisual("", lw), layout.PadVisual("", rw)
			if i < len(leftLines) {
				l = leftLines[i]
			}
			if i < len(rightLines) {
				r = rightLines[i]
			}
			bodyRows = append(bodyRows, l+"  "+div+"  "+r)
		}
	} else {
		bodyRows = append(bodyRows, leftLines...)
		bodyRows = append(bodyRows, layout.PadVisual("", lw))
		bodyRows = append(bodyRows, rightLines...)
	}

	// Vertically window the body when it is taller than the screen, scrolled by
	// m.helpScroll (the title, hint and modal chrome cost ~8 rows).
	hint := "Mouse: wheel scrolls · over right pane scrolls it · click selects · double-click follows"
	total := len(bodyRows)
	maxRows := max(1, m.height-8)
	if total > maxRows {
		m.helpScroll = layout.Clamp(m.helpScroll, 0, total-maxRows)
		bodyRows = bodyRows[m.helpScroll : m.helpScroll+maxRows]
		hint = fmt.Sprintf("↑/↓ scroll · %d–%d of %d · Esc/any key closes",
			m.helpScroll+1, m.helpScroll+maxRows, total)
	} else {
		m.helpScroll = 0
	}

	// Never let a row push the modal past the terminal (very narrow windows).
	rowCap := max(1, m.width-6)

	var b strings.Builder
	b.WriteString(m.theme.modalTitle("Keybindings"))
	b.WriteString("\n\n")
	for _, r := range bodyRows {
		b.WriteString(layout.FitANSIWidth(r, rowCap))
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(m.theme.modalHint(hint))
	return m.theme.modalStyle.Render(b.String())
}

// helpPageStep is how many rows PgUp/PgDn move the help overlay.
const helpPageStep = 8

// helpColumn renders a help column: rows padded to a common width, section
// headers shown uppercase with a dim rule to the column edge (matching the Info
// view), blanks as empty lines.
func (m *Model) helpColumn(entries []helpEntry) []string {
	w := 0
	for _, e := range entries {
		if e.head == "" {
			if rw := ansi.StringWidth(e.text); rw > w {
				w = rw
			}
		}
	}
	out := make([]string, len(entries))
	for i, e := range entries {
		switch {
		case e.head != "":
			label := strings.ToUpper(e.head) + " "
			line := m.theme.helpHeadStyle.Render(label)
			if fill := w - lipgloss.Width(label); fill > 0 {
				line += m.theme.srcShadowStyle.Render(strings.Repeat("─", fill))
			}
			out[i] = layout.PadVisual(line, w)
		default:
			out[i] = layout.PadVisual(e.text, w)
		}
	}
	return out
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

// gotoVisibleRows is the fixed number of result rows the goto modal reserves, so
// its total height never changes with the result count — otherwise the centred
// overlay would bounce up and down as the user types.
func (m *Model) gotoVisibleRows() int {
	return layout.Clamp(m.height-12, 4, 40)
}

func (m *Model) renderGotoModal() string {
	var sb strings.Builder
	rowW := modalListWidth(m.width)
	visible := m.gotoVisibleRows()

	// Header: title, a blank line for breathing room, the scope tabs, and the input
	// — each indented one column to line up with the result rows below.
	sb.WriteString(m.theme.modalTitle("Jump to"))
	sb.WriteByte('\n')
	sb.WriteByte('\n')
	sb.WriteString(" " + layout.FitANSIWidth(m.gotoScopeBar(), rowW-1))
	sb.WriteByte('\n')
	sb.WriteString(" " + m.gotoInput.View())
	sb.WriteByte('\n')
	sb.WriteByte('\n')
	m.modalListRow = 5 // title + blank + scope bar + input + blank → list at row 5

	// Body: exactly `visible` lines, always — result rows padded out with blanks (or
	// a centred empty hint), so the modal keeps a constant height.
	blank := layout.PadRight("", rowW)
	if len(m.gotoResults) == 0 {
		for i := 0; i < visible; i++ {
			if i == visible/2 {
				hint := m.theme.modalHint("type to search — " + m.gotoEmptyHint())
				sb.WriteString(centeredModalLine(hint, rowW) + "\n")
			} else {
				sb.WriteString(blank + "\n")
			}
		}
	} else {
		addrW := m.file.AddrHexWidth()
		gotoTop := layout.VisualTop(m.gotoSel, m.gotoTop, len(m.gotoResults), visible, func(int) int { return 1 })
		m.gotoTop = gotoTop
		const badgeW = 9
		labelW := max(4, rowW-badgeW-3-addrW-3)
		for row := 0; row < visible; row++ {
			i := gotoTop + row
			if i >= len(m.gotoResults) {
				sb.WriteString(blank + "\n")
				continue
			}
			t := m.gotoResults[i]
			loc := strings.Repeat(" ", 2+addrW)
			if t.hasAddr || t.kind == gkAddr {
				loc = m.theme.addrStyle.Render(fmt.Sprintf("0x%0*x", addrW, t.addr))
			}
			badge := m.gotoTagStyle(t.kind).Render(layout.PadVisual(t.kind.viewLabel(), badgeW))
			label := m.gotoKindStyle(t).Render(layout.TruncateMiddle(t.label, labelW))
			line := layout.PadRight(fmt.Sprintf(" %s  %s  %s", badge, loc, label), rowW)
			if i == m.gotoSel {
				line = m.theme.tableSelStyle.Render(ansi.Strip(line))
			}
			sb.WriteString(line + "\n")
		}
	}

	count := ""
	if n := len(m.gotoResults); n > 0 {
		count = fmt.Sprintf("  (%d/%d)", m.gotoSel+1, n)
	}
	sb.WriteByte('\n')
	sb.WriteString(" " + m.theme.modalHint("↑/↓ select · ↵ jump · ⇥ scope · Esc cancel"+count))
	return m.theme.modalStyle.Render(sb.String())
}

// gotoScopeBar renders the scope selector with the active scope highlighted, plus
// the physical-address toggle when the binary has distinct LMAs.
func (m *Model) gotoScopeBar() string {
	var b strings.Builder
	for s := gotoScope(0); s < gsScopeCount; s++ {
		if s > 0 {
			b.WriteString(m.theme.srcShadowStyle.Render(" "))
		}
		if s == m.gotoScope {
			b.WriteString(m.theme.tableSelStyle.Render(" " + s.String() + " "))
		} else {
			b.WriteString(m.theme.srcShadowStyle.Render(" " + s.String() + " "))
		}
	}
	if (m.gotoScope == gsAll || m.gotoScope == gsAddr) && m.file.HasPhysAddrs() {
		tag := "virtual"
		if m.gotoAddrPhys {
			tag = m.theme.warnStyle.Render("physical")
		}
		b.WriteString(m.theme.modalHint("   addr: ") + tag + m.theme.modalHint(" (^p)"))
	}
	return b.String()
}

// gotoTagStyle colours the kind badge with a distinct hue per kind. In the All
// scope only addr/sym/sec appear, and those three (blue/green/yellow) are clearly
// distinct; str/lib show only in their own scopes.
func (m *Model) gotoTagStyle(k gotoKind) lipgloss.Style {
	switch k {
	case gkSymbol:
		return m.theme.infoStyle // green
	case gkSection:
		return m.theme.warnStyle // yellow
	case gkString:
		return m.theme.errorStyle // red
	case gkLib:
		return m.theme.srcShadowStyle // dim
	default:
		return m.theme.headerKey // addr — blue
	}
}

// gotoKindStyle colours a result by kind (symbols by their own kind/bind colour,
// like the Symbols view; other kinds by category).
func (m *Model) gotoKindStyle(t gotoTarget) lipgloss.Style {
	switch t.kind {
	case gkSymbol:
		return m.theme.styleForSymbol(t.sym.Kind, t.sym.Bind)
	case gkSection:
		return m.theme.infoStyle
	case gkString:
		return m.theme.tableRowStyle
	case gkLib:
		return m.theme.symbolNameStyle
	default:
		return m.theme.headerKey // address
	}
}

// gotoEmptyHint names what the current scope searches.
func (m *Model) gotoEmptyHint() string {
	switch m.gotoScope {
	case gsAddr:
		return "a hex/decimal address"
	case gsStrings:
		return "a printable string"
	case gsLibs:
		return "a linked library"
	case gsSections:
		return "a section name"
	case gsSymbols:
		return "a symbol name"
	default:
		return "a symbol, section or address"
	}
}

func (m *Model) renderSearchModal() string {
	rowW := modalListWidth(m.width)
	// Switch strip (content row searchSwitchLine) — clickable; geometry shared with
	// handleSearchPopupClick via searchSwitches(). Each switch is a dim name plus
	// the current value in an accent pill. Indented one column to line up with the
	// other elements (and the goto/find modals).
	var segs []string
	for _, sw := range m.searchSwitches() {
		segs = append(segs, m.theme.srcShadowStyle.Render(sw.name)+" "+m.theme.switchStyle.Render("⟦"+sw.value+"⟧"))
	}
	switches := strings.Join(segs, searchSwitchSep)
	help := m.theme.modalHint("^T mode · ^I case · ^R dir · ^O origin · ↵ find · n/N next/prev · esc cancel")

	var sb strings.Builder
	sb.WriteString(m.theme.modalTitle("Search"))
	sb.WriteByte('\n')
	sb.WriteString(" " + m.theme.modalHint(m.current().searchHint()) + "\n")
	sb.WriteByte('\n')
	sb.WriteString(" " + m.searchInput.View() + "\n")
	sb.WriteByte('\n')
	sb.WriteString(" " + switches + "\n") // content row searchSwitchLine
	sb.WriteByte('\n')
	sb.WriteString(" " + help)
	return m.theme.modalStyle.Render(layout.PadRight(sb.String(), rowW))
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
