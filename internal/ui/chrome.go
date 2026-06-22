package ui

import (
	"fmt"
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
	}
	body = m.theme.renderViewBackground(body, m.width)
	parts = append(parts, body, m.renderFooter())
	out := lipgloss.JoinVertical(lipgloss.Left, parts...)
	switch {
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
		row("1–9", "switch view"),
		row("g", "go to address / symbol"),
		row(",", "settings (theme, wrap, …)"),
		row("?", "this help  ·  q / ^C quit"),
		blank,
		head("Lists (all views)"),
		row("↑/↓  j/k", "move line"),
		row("PgUp/PgDn  [ ]", "page  (⌘↑/⌘↓ on macOS)"),
		row("Home/End", "begin/end  (^A / ^E)"),
		row("/", "filter / search"),
		row("Enter", "open / jump"),
		row("d / h / m", "go to addr in disasm / hex / raw"),
		row("⇧a / ⇧s", "copy address / name"),
		row("⇧l", "copy the whole current row"),
		row("Esc", "clear filters"),
		row("w", "toggle long-line wrap"),
		blank,
		head("Info"),
		row("Enter", "open entry point"),
		row("t / ⇥", "switch fat-Mach-O arch slice"),
		blank,
		head("Sections"),
		row("Enter", "open in Hex"),
		row("d / h / m", "go to addr in disasm / hex / raw"),
		row("s / r", "sort (index/name/addr/size) · reverse"),
		row("⌥t / ⌥f", "filter by type / flags"),
		row("t / ⇥", "toggle sections / segments"),
		blank,
		head("Symbols"),
		row("↵ / d / h / m", "open · go to disasm / hex / raw"),
		row("⌥t / ⌥b", "filter by type / bind"),
		row("⌥s", "scope: all/internal/imported"),
		row("s / r", "sort field · reverse (asc/desc)"),
		row("t / ⇥", "toggle namespace tree / flat table"),
		row("←/→", "tree: collapse / expand group (← on a leaf folds its branch)"),
		row("↵ · +/−", "tree: expand/collapse all below · all"),
		row("e / .", "collapse (…)/<…> to ... · all / current row"),
		row("Esc", "clear filters (type/scope/bind/lib/text)"),
	}
	right := []helpEntry{
		head("Disassembly"),
		row("↑/↓", "scroll"),
		row("←/→", "history back / forward"),
		row("[ / ]", "previous / next symbol"),
		row("Enter / dbl-clk", "follow address"),
		row("x", "find references (xrefs)"),
		row("h / m", "go to addr in hex / raw"),
		row("⇧a / ⇧s / ⇧c", "copy addr / symbol / function asm"),
		row("e", "collapse (…)/<…> in symbol names"),
		row("/  n/N", "search · next/prev"),
		row("Tab", "show / hide right pane"),
		row("⇧Tab", "swap source / disasm"),
		row("⇧↑/⇧↓", "scroll right pane"),
		blank,
		head("Hex / Raw"),
		row("↑/↓/←/→  h/l", "move byte cursor"),
		row("d  ·  m", "go to addr in disasm  ·  raw (hex only)"),
		row("[ / ]", "prev / next section"),
		row("⇧[ / ⇧]", "prev / next nonzero"),
		row("t / ⇥", "toggle ascii / pointer column"),
		row("i", "data inspector"),
		row("Enter", "follow pointer at cursor"),
		row("⇧a / ⇧s / ⇧p", "copy address / symbol / pointer"),
		row("w", "wrap long rows"),
		row("e", "collapse (…)/<…> in symbol names"),
		row("/  n/N", "search bytes/\"text\"/0x…"),
		blank,
		head("Sources"),
		row("Enter / o", "open in disasm source-first view"),
		row("[ / ]", "prev / next mapped line"),
		row("/  ^F", "find in file · grep all"),
		row("⌥a", "filter: all / present / missing"),
		row("s / r", "sort (project/name) · reverse"),
		row("t / ⇥", "toggle directory tree / flat list"),
		row("⇧s  ·  g", "copy path · goto symbol"),
		blank,
		head("Libraries"),
		row("Enter", "imported symbols"),
		row("o  ·  ⇧s", "open as primary · copy"),
		row("/  ·  ⌥a", "search · filter all/on-disk/in dyld cache"),
		row("r", "reverse the (name) sort"),
		blank,
		head("Strings"),
		row("d / h / m", "go to addr in disasm / hex / raw"),
		row("⌥s", "filter by section"),
		row("s / r", "sort (offset/address/string) · reverse"),
		row("⇧a / ⇧s", "copy address / string"),
	}

	leftLines := m.helpColumn(left)
	rightLines := m.helpColumn(right)
	n := max(len(leftLines), len(rightLines))
	lw, rw := lipgloss.Width(leftLines[0]), lipgloss.Width(rightLines[0])
	div := m.theme.srcShadowStyle.Render("│")

	var b strings.Builder
	b.WriteString(m.theme.modalTitle("Keybindings"))
	b.WriteString("\n\n")
	for i := range n {
		l, r := padVisual("", lw), padVisual("", rw)
		if i < len(leftLines) {
			l = leftLines[i]
		}
		if i < len(rightLines) {
			r = rightLines[i]
		}
		b.WriteString(l)
		b.WriteString("  ")
		b.WriteString(div)
		b.WriteString("  ")
		b.WriteString(r)
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(m.theme.modalHint("Mouse: wheel scrolls · over right pane scrolls it · click selects · double-click follows"))
	return m.theme.modalStyle.Render(b.String())
}

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
	sb.WriteString(m.theme.modalTitle("Go to"))
	sb.WriteString("\n\n")
	sb.WriteString(m.gotoInput.View())
	sb.WriteString("\n")
	if len(m.gotoResults) == 0 {
		sb.WriteString("\n")
		sb.WriteString(m.theme.modalHint("type an address or symbol name"))
		sb.WriteString("\n")
	} else {
		sb.WriteString("\n")
		addrW := m.file.AddrHexWidth()
		// Scroll the window so the selection stays visible.
		gotoTop := visualTop(m.gotoSel, m.gotoTop, len(m.gotoResults), gotoVisible, func(int) int { return 1 })
		end := gotoTop + gotoVisible
		if end > len(m.gotoResults) {
			end = len(m.gotoResults)
		}
		rowW := modalListWidth(m.width)
		labelW := rowW - addrW - 6
		for i := gotoTop; i < end; i++ {
			t := m.gotoResults[i]
			line := fmt.Sprintf(" 0x%0*x  %s", addrW, t.addr, truncateMiddle(t.label, labelW))
			line = padRight(line, rowW)
			if i == m.gotoSel {
				line = m.theme.tableSelStyle.Render(line)
			}
			sb.WriteString(line + "\n")
		}
	}
	count := ""
	if n := len(m.gotoResults); n > 0 {
		count = fmt.Sprintf("  (%d/%d)", m.gotoSel+1, n)
	}
	sb.WriteString("\n")
	sb.WriteString(m.theme.modalHint("↑/↓ select · Enter jump · Esc cancel" + count))
	return m.theme.modalStyle.Render(sb.String())
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
}

func (m *Model) tabSegment(label string, active bool) string {
	if active {
		return m.theme.activeTabStyle.Render(label)
	}
	return m.theme.tabStyle.Render(label)
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
	segs := m.tabLead()
	for _, t := range tabItems {
		segs = append(segs, m.tabSegment(t.label, m.mode == t.mode))
	}
	row := lipgloss.JoinHorizontal(lipgloss.Left, segs...)
	// Clamp to width: a too-wide tab strip would wrap and push the whole body
	// down a row (and the status line off-screen).
	return padRight(row, m.width)
}

// tabHitTest maps an x column on the tab row to the tab the user clicked.
func (m *Model) tabHitTest(x int) (mode, bool) {
	pos := 0
	for _, s := range m.tabLead() {
		pos += lipgloss.Width(s)
	}
	for _, t := range tabItems {
		w := lipgloss.Width(m.tabSegment(t.label, m.mode == t.mode))
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
		hints := []footerHint{{"↵", "disasm entry"}}
		if len(m.file.FatArches) > 1 {
			hints = append(hints, footerHint{"t", "switch arch"})
		}
		return hints
	case modeSections:
		return []footerHint{{"↵", "open"}, {"d/h/m", "go to"}, {"s/r", "sort/rev"}, {"⌥t/⌥f", "type/flags"}, {"t", "sec/seg"}, {"/", "filter"}}
	case modeSymbols:
		if m.symbolTreeActive() {
			return []footerHint{{"←/→", "fold/unfold"}, {"↵", "all below"}, {"+/−", "all"}, {"/", "filter"}, {"t", "flat"}}
		}
		return []footerHint{{"↵", "jump"}, {"d/h/m", "go to"}, {"/", "filter"}, {"⌥t/⌥s/⌥b", "type/scope/bind"}, {"s/r", "sort/rev"}, {"t", "tree"}, {"⇧a/⇧s", "copy"}}
	case modeDisasm:
		dwarf := m.file.HasDWARF()
		switch {
		case m.searchRunning:
			return []footerHint{{"esc", "cancel"}, {"[ ]", "sym"}, {"←/→", "history"}, {"/", "search"}}
		case m.sourceFirst && m.srcFile != "":
			// Source navigation leads: no disasm history, and [ ] steps mapped lines.
			return []footerHint{{"↵", "to disasm"}, {"[ ]", "mapped"}, {"esc", "back"}, {"⇧tab", "swap"}, {"/", "search"}, {"^f", "grep"}, {"⇧s", "copy"}}
		case m.showSource && dwarf:
			// Disasm-first with the source pane open.
			return []footerHint{{"↵", "follow"}, {"[ ]", "sym"}, {"←/→", "history"}, {"x", "xrefs"}, {"h/m", "hex/raw"}, {"⇧a/⇧s", "copy"}, {"⇧c", "copy fn"}, {"tab", "pane"}, {"⇧tab", "swap"}, {"/", "search"}}
		default:
			// Disasm-first, no pane. Offer tab to open the pane only when there is
			// debug info to show.
			hints := []footerHint{{"↵", "follow"}, {"[ ]", "sym"}, {"←/→", "history"}, {"x", "xrefs"}, {"h/m", "hex/raw"}, {"⇧a/⇧s", "copy"}, {"⇧c", "copy fn"}, {"/", "search"}}
			if dwarf {
				hints = append(hints, footerHint{"tab", "pane"})
			}
			return hints
		}
	case modeHex:
		return []footerHint{{"↵", "follow ptr"}, {"d/m", "disasm/raw"}, {"[ ]", "section"}, {"t", "ptrs"}, {"i", "inspect"}, {"/", "search"}, {"⇧a/⇧s/⇧p", "copy"}}
	case modeRaw:
		return []footerHint{{"↵", "follow ptr"}, {"d", "disasm"}, {"[ ]", "section"}, {"t", "ptrs"}, {"i", "inspect"}, {"/", "search"}, {"⇧a/⇧s/⇧p", "copy"}}
	case modeStrings:
		return []footerHint{{"↵", "jump"}, {"d/h/m", "go to"}, {"/", "filter"}, {"⌥s", "section"}, {"s/r", "sort/rev"}, {"⇧a/⇧s", "copy"}}
	case modeSources:
		if m.sourcesTree {
			return []footerHint{{"←/→", "fold/unfold"}, {"↵", "open/all below"}, {"/", "filter"}, {"⌥a", "present"}, {"t", "flat"}}
		}
		return []footerHint{{"↵", "open"}, {"/", "filter"}, {"⌥a", "present"}, {"s/r", "sort/rev"}, {"^f", "grep"}, {"t", "tree"}, {"⇧s", "copy"}}
	case modeLibs:
		return []footerHint{{"↵", "imports"}, {"o", "open"}, {"/", "filter"}, {"⌥a", "avail"}, {"r", "rev"}, {"⇧s", "copy"}}
	}
	return nil
}

func (m *Model) renderFooter() string {
	keyStyle := m.theme.helpKeyStyle            // accent, bold
	descStyle := m.theme.footerStyle.Padding(0) // muted, no padding
	sep := descStyle.Render(" · ")

	hints := append(m.viewHints(), globalHints...)
	parts := make([]string, 0, len(hints))
	for _, h := range hints {
		parts = append(parts, keyStyle.Render(h.key)+" "+descStyle.Render(h.desc))
	}
	left := " " + strings.Join(parts, sep)

	if m.status == "" {
		return padRight(left, m.width)
	}
	st := m.theme.infoStyle
	if m.statusError {
		st = m.theme.errorStyle
	}
	// Right-align the status in whatever space the hints leave.
	avail := max(1, m.width-lipgloss.Width(left))
	right := lipgloss.PlaceHorizontal(avail, lipgloss.Right, st.Render(m.status))
	return padRight(left+right, m.width)
}

// bodyHeight is the number of rows available between tabs and footer.
func (m *Model) bodyHeight() int {
	if m.height <= 2 {
		return 1
	}
	return m.height - 2
}
