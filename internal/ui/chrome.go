package ui

import (
	"fmt"
	"image/color"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
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
	body := ""
	switch m.mode {
	case modeInfo:
		body = m.renderInfo()
	case modeSections:
		body = m.renderSections()
	case modeSymbols:
		body = m.renderSymbols()
	case modeDisasm:
		body = m.renderDisasm()
	case modeHex:
		body = m.renderHex()
	case modeRaw:
		body = m.renderRaw()
	case modeStrings:
		body = m.renderStrings()
	case modeSources:
		body = m.renderSources()
	case modeLibs:
		body = m.renderLibs()
	case modeRelocs:
		body = m.renderRelocs()
	}
	body = m.theme.renderViewBackground(body, m.width)
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
		return helpEntry{text: m.theme.helpKeyStyle.Render(padVisual(keys, keyW)) + " " + m.theme.helpDescStyle.Render(desc)}
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
		row("PgUp/PgDn  [ ]", "page  ("+altKeys("↑", "↓")+")"),
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
		row(altKeys("t", "f"), "filter by type / flags"),
		row("t / ⇥", "cycle sections / segments / header"),
		blank,
		head("Symbols"),
		row(altKeys("t", "b", "s"), "filter by type / bind / scope"),
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
		row(altKeys("a"), "filter: all / present / missing"),
		row("t / ⇥", "toggle directory tree / flat list"),
		row("↵ Enter / o", "open in disasm source-first view"),
		blank,
		head("Libraries / Relocations"),
		row("8 / 0", "libraries view / relocations view"),
		row("o", "(libs) open as primary"),
		row(altKeys("a"), "(libs) filter all/on-disk/cache"),
		row("t / ⇥", "(libs) flat ↔ tree"),
		row("↵", "libs: imported symbols · relocs: go to patched addr"),
		row("s/r  "+altKeys("t", "s"), "(relocs) sort/rev · type/section filter"),
		blank,
		head("Strings"),
		row(altKeys("s"), "filter by section"),
		row(altKeys("p"), "filter to paths only"),
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
			l, r := padVisual("", lw), padVisual("", rw)
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
		bodyRows = append(bodyRows, padVisual("", lw))
		bodyRows = append(bodyRows, rightLines...)
	}

	// Vertically window the body when it is taller than the screen, scrolled by
	// m.helpScroll (the title, hint and modal chrome cost ~8 rows).
	hint := "Mouse: wheel scrolls · over right pane scrolls it · click selects · double-click follows"
	total := len(bodyRows)
	maxRows := max(1, m.height-8)
	if total > maxRows {
		m.helpScroll = clamp(m.helpScroll, 0, total-maxRows)
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
		b.WriteString(fitANSIWidth(r, rowCap))
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
			out[i] = padVisual(line, w)
		default:
			out[i] = padVisual(e.text, w)
		}
	}
	return out
}

// Shared modal styling, so every popup (help, goto, search, settings, xrefs,
// path picker) looks the same: a filled title bar, dim hint/footer lines, and a
// common list width.
func (t Theme) modalTitle(s string) string { return t.titleStyle.Render(" " + s + " ") }
func (t Theme) modalHint(s string) string  { return t.footerStyle.Padding(0).Render(s) }
func modalListWidth(termW int) int         { return clamp(termW-8, 40, 120) }

// overlayCenter draws a pre-rendered modal centred over bg.
func (m *Model) overlayCenter(bg, modal string) string {
	mw := lipgloss.Width(modal)
	modal = renderStyle(modal, mw, m.theme.tableRowStyle)
	modal = m.theme.renderViewBackground(modal, mw)
	mh := lipgloss.Height(modal)
	return overlay(bg, modal, (m.width-mw)/2, (m.height-mh)/2)
}

func (m *Model) renderGotoModal() string {
	var sb strings.Builder
	rowW := modalListWidth(m.width)
	sb.WriteString(m.theme.modalTitle("Jump to"))
	sb.WriteString("\n")
	sb.WriteString(fitANSIWidth(m.gotoScopeBar(), rowW))
	sb.WriteString("\n")
	sb.WriteString(m.gotoInput.View())
	sb.WriteString("\n")
	m.modalListRow = 4 // title + scope bar + input + blank → list at row 4
	if len(m.gotoResults) == 0 {
		sb.WriteString("\n")
		sb.WriteString(m.theme.modalHint("type to search · ⇥ scope · " + m.gotoEmptyHint()))
		sb.WriteString("\n")
	} else {
		sb.WriteString("\n")
		addrW := m.file.AddrHexWidth()
		visible := clamp(m.height-11, 3, 40)
		gotoTop := visualTop(m.gotoSel, m.gotoTop, len(m.gotoResults), visible, func(int) int { return 1 })
		m.gotoTop = gotoTop
		end := min(gotoTop+visible, len(m.gotoResults))
		labelW := rowW - addrW - 9
		for i := gotoTop; i < end; i++ {
			t := m.gotoResults[i]
			loc := strings.Repeat(" ", 2+addrW)
			if t.hasAddr || t.kind == gkAddr {
				loc = m.theme.addrStyle.Render(fmt.Sprintf("0x%0*x", addrW, t.addr))
			} else if t.kind == gkLib {
				loc = padVisual("", 2+addrW)
			}
			// Colour the kind tag and label by kind so mixed results (the All scope)
			// are distinguishable at a glance.
			label := m.gotoKindStyle(t).Render(truncateMiddle(t.label, labelW))
			line := fmt.Sprintf(" %s  %s %s",
				m.gotoTagStyle(t.kind).Render(t.kind.tag()), loc, label)
			line = padRight(line, rowW)
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
	sb.WriteString("\n")
	sb.WriteString(m.theme.modalHint("↑/↓ select · ↵ jump · ⇥ scope · Esc cancel" + count))
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
		b.WriteString(m.theme.modalHint("   addr: ") + tag + m.theme.modalHint(" (⌥p)"))
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
	hint := "Search this view"
	switch m.mode {
	case modeDisasm:
		hint = "Search instruction text / symbol"
	case modeHex, modeRaw:
		hint = "Search hex bytes (de ad be ef), \"text\", or 0x…"
	case modeSources:
		if m.srcSearchAll {
			hint = "Search across all source files"
		} else {
			hint = "Search in this source file"
		}
	}
	// Switch strip (content row searchSwitchLine) — clickable; geometry shared
	// with handleSearchPopupClick via searchSwitches(). Each switch is a dim name
	// plus the current value in an accent pill.
	var segs []string
	for _, sw := range m.searchSwitches() {
		segs = append(segs, m.theme.srcShadowStyle.Render(sw.name)+" "+m.theme.switchStyle.Render("⟦"+sw.value+"⟧"))
	}
	switches := strings.Join(segs, searchSwitchSep)
	help := m.theme.modalHint("^T mode · ^R dir · ^O origin · ↵ find · n/N next/prev · esc cancel")

	body := m.theme.modalTitle("Search") + "\n" + m.theme.modalHint(hint) +
		"\n\n" + m.searchInput.View() + "\n\n" + switches + "\n\n" + help
	return m.theme.modalStyle.Render(body)
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
	return padRight(row, m.width)
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
	switch md {
	case modeDisasm:
		if m.dis == nil {
			m.setStatus("no disassembler for this architecture", true)
			return nil
		}
		m.setMode(modeDisasm)
		if !m.disasmBuilt {
			// Decode the initial window in the background; later jumps decode a
			// fresh bounded span synchronously so targeted navigation lands
			// immediately.
			if !m.disasmDecoding {
				m.disasmDecoding = true
				m.disasmPendingAddr = m.disasmInitAddr
				return m.decodeDisasmCmd(m.disasmInitAddr)
			}
			return nil
		}
		// Already decoded: land on the entry the first time in.
		if !m.disasmPositioned && m.disasmInitAddr != 0 {
			m.loadDisasmAt(m.disasmInitAddr)
		}
		return nil
	case modeHex:
		m.ensureHex()
	case modeRaw:
		m.ensureRaw()
	case modeStrings:
		m.ensureStrings()
	case modeSources:
		m.ensureSources()
	case modeRelocs:
		m.buildRelocFacets()
		m.recomputeRelocs()
	}
	m.setMode(md)
	return nil
}

// footerHint is one "key action" pair shown in the footer.
type footerHint struct{ key, desc string }

// globalHints are the commands available everywhere; appended to every view's
// footer so they are never missing. The full reference lives behind '?'.
var globalHints = []footerHint{
	{"g", "goto"}, {",", "settings"}, {"?", "help"}, {"q", "quit"},
}

// viewHints returns the current view's primary commands (view-specific only;
// globals are appended by renderFooter). Kept curated — the complete list is in
// the '?' overlay.
func (m *Model) viewHints() []footerHint {
	switch m.mode {
	case modeInfo:
		if m.isArchive() && m.infoMembers {
			return []footerHint{{"↑/↓", "select"}, {"↵/t", "open member"}, {"esc", "back"}}
		}
		hints := []footerHint{{"↵", "disasm entry"}}
		switch {
		case m.isArchive():
			hints = append(hints, footerHint{"t", "members"})
		case len(m.file.FatArches) > 1:
			hints = append(hints, footerHint{"t", "switch arch"})
		}
		return hints
	case modeSections:
		return []footerHint{{"↵", "open"}, {"d/h/m", "go to"}, {"s/r", "sort/rev"}, {"t", "sec/seg"}, {"/", "filter"}, {altKeys("t", "f"), "type/flags"}, {"⇧H", "header"}}
	case modeSymbols:
		if m.symbolTreeActive() {
			return []footerHint{{"←/→", "fold/unfold"}, {"↵", "all below"}, {"+/−", "all"}, {"t", "flat"}}
		}
		return []footerHint{{"↵", "jump"}, {"d/h/m", "go to"}, {"s/r", "sort/rev"}, {"t", "tree"}, {"/", "filter"}, {altKeys("t", "s", "b"), "type/scope/bind"}, {"⇧a/⇧s", "copy"}}
	case modeDisasm:
		dwarf := m.file.HasDWARF()
		switch {
		case m.searchRunning:
			return []footerHint{{"esc", "cancel"}, {"[ ]", "sym"}, {"←/→", "history"}, {"/", "search"}}
		case m.sourceFirst && m.srcFile != "":
			// Source navigation leads: no disasm history, and [ ] steps mapped lines.
			return []footerHint{{"↵", "to disasm"}, {"[ ]", "mapped"}, {"esc", "back"}, {"⇧tab", "swap"}, {"/", "search"}, {"⇧s", "copy"}}
		case m.showSource && dwarf:
			// Disasm-first with the source pane open.
			return []footerHint{{"↵", "follow"}, {"[ ]", "sym"}, {"←/→", "history"}, {"x", "xrefs"}, {"y", "syscalls"}, {"h/m", "hex/raw"}, {"a", m.disasmAllHint()}, {"tab", "pane"}, {"⇧tab", "swap"}, {"/", "search"}, {"⇧a/⇧s/⇧c", "copy"}}
		default:
			// Disasm-first, no pane. Offer tab to open the pane only when there is
			// debug info to show.
			hints := []footerHint{{"↵", "follow"}, {"[ ]", "sym"}, {"←/→", "history"}, {"x", "xrefs"}, {"y", "syscalls"}, {"h/m", "hex/raw"}, {"a", m.disasmAllHint()}, {"/", "search"}, {"⇧a/⇧s/⇧c", "copy"}}
			if dwarf {
				hints = append(hints, footerHint{"tab", "pane"})
			}
			return hints
		}
	case modeHex:
		return []footerHint{{"↵", "follow ptr"}, {"d/m", "disasm/raw"}, {"[ ]", "section"}, {"t/⇧t", "ascii·interp"}, {"i", "inspect"}, {"/", "search"}, {"⇧a/⇧s/⇧p", "copy"}}
	case modeRaw:
		return []footerHint{{"↵", "follow ptr"}, {"d", "disasm"}, {"[ ]", "section"}, {"t/⇧t", "ascii·interp"}, {"i", "inspect"}, {"/", "search"}, {"⇧a/⇧s/⇧p", "copy"}}
	case modeStrings:
		return []footerHint{{"↵", "jump"}, {"d/h/m", "go to"}, {"s/r", "sort/rev"}, {"t", "table/flow"}, {"/", "filter"}, {altKeys("s"), "section"}, {altKeys("p"), "paths"}, {"⇧a/⇧s", "copy"}}
	case modeSources:
		if m.sourcesTree {
			return []footerHint{{"←/→", "fold/unfold"}, {"↵", "open/all below"}, {altKeys("a"), "present"}, {"t", "flat"}}
		}
		return []footerHint{{"↵", "open"}, {"s/r", "sort/rev"}, {"t", "tree"}, {"/", "filter"}, {altKeys("a"), "present"}, {"⇧s", "copy"}}
	case modeLibs:
		return []footerHint{{"↵", "imports"}, {"o", "open"}, {"r", "rev"}, {"t", "tree"}, {"/", "filter"}, {altKeys("a"), "avail"}, {"⇧s", "copy"}}
	case modeRelocs:
		return []footerHint{{"↵", "go to patched addr"}, {"s/r", "sort/rev"}, {altKeys("t", "s"), "type/section"}, {"/", "filter"}}
	}
	return nil
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
		return padRight(" "+fitJoin(parts, sep, m.width-1), m.width)
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
		msg = fitANSIWidth(msg, m.width)
	}
	msgW := lipgloss.Width(msg)
	left := padRight(" "+fitJoin(parts, sep, m.width-msgW-1), m.width-msgW)
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
