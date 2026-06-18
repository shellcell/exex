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
	parts = append(parts, body, m.renderFooter())
	out := lipgloss.JoinVertical(lipgloss.Left, parts...)
	switch {
	case m.helpActive:
		out = m.overlayCenter(out, m.renderHelpModal())
	case m.gotoActive:
		out = m.overlayCenter(out, m.renderGotoModal())
	case m.searchActive:
		out = m.overlayCenter(out, m.renderSearchModal())
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
func (m *Model) renderHelpModal() string {
	const keyW = 16
	row := func(keys, desc string) string {
		return m.theme.helpKeyStyle.Render(padVisual(keys, keyW)) + " " + m.theme.helpDescStyle.Render(desc)
	}
	head := func(s string) string { return m.theme.helpHeadStyle.Render(s) }

	left := []string{
		head("Global"),
		row("1–9", "switch view"),
		row("g", "go to address / symbol"),
		row("?", "this help  ·  q / ^C quit"),
		"",
		head("Lists (all views)"),
		row("↑/↓  j/k", "move line"),
		row("PgUp/PgDn", "page  (⌘↑/⌘↓ on macOS)"),
		row("Home/End", "begin/end  (^A / ^E)"),
		row("/", "filter / search"),
		row("Enter", "open / jump"),
		row("a / s", "copy address / name"),
		row("w", "toggle long-line wrap"),
		"",
		head("Sections"),
		row("Enter", "open in Hex"),
		row("d", "disassemble (if exec)"),
		"",
		head("Symbols"),
		row("t", "cycle type filter"),
		row("Esc", "clear library filter"),
	}
	right := []string{
		head("Disassembly"),
		row("↑/↓", "scroll"),
		row("←/→", "history back / forward"),
		row("[ / ]", "previous / next symbol"),
		row("Enter / dbl-clk", "follow address"),
		row("/  n/N", "search · next/prev"),
		row("Tab", "show / hide right pane"),
		row("⇧Tab", "swap source / disasm"),
		row("⇧↑/⇧↓", "scroll right pane"),
		"",
		head("Hex / Raw"),
		row("↑/↓/←/→", "move byte cursor"),
		row("d", "disassemble (if exec)"),
		row("[ / ]", "prev / next section"),
		row("⇧[ / ⇧]", "prev / next nonzero"),
		row("/  n/N", "search bytes/\"text\"/0x…"),
		"",
		head("Sources"),
		row("Enter", "open · jump to disasm"),
		row("[ / ]", "prev / next mapped line"),
		row("/  ^F", "find in file · grep all"),
		row("c  ·  g", "copy path · goto symbol"),
		"",
		head("Libraries"),
		row("Enter", "imported symbols"),
		row("o  ·  c", "open as primary · copy"),
	}

	col := func(rows []string) string {
		w := 0
		for _, r := range rows {
			if rw := ansi.StringWidth(r); rw > w {
				w = rw
			}
		}
		for i, r := range rows {
			rows[i] = padVisual(r, w)
		}
		return strings.Join(rows, "\n")
	}
	cols := lipgloss.JoinHorizontal(lipgloss.Top, col(left), "    ", col(right))
	body := m.theme.titleStyle.Render(" Keybindings ") + "\n\n" + cols +
		"\n\n" + m.theme.footerStyle.Render("Mouse: wheel scrolls · over right pane scrolls it · click selects · double-click follows")
	return m.theme.modalStyle.Render(body)
}

// overlayCenter draws a pre-rendered modal centred over bg.
func (m *Model) overlayCenter(bg, modal string) string {
	mw := lipgloss.Width(modal)
	mh := lipgloss.Height(modal)
	return overlay(bg, modal, (m.width-mw)/2, (m.height-mh)/2)
}

func (m *Model) renderGotoModal() string {
	var sb strings.Builder
	sb.WriteString("Go to address or symbol\n\n")
	sb.WriteString(m.gotoInput.View())
	sb.WriteString("\n")
	if len(m.gotoResults) == 0 {
		sb.WriteString("\n" + m.theme.footerStyle.Render("type an address or symbol name") + "\n")
	} else {
		sb.WriteString("\n")
		addrW := m.file.AddrHexWidth()
		// Scroll the window so the selection stays visible.
		gotoTop := visualTop(m.gotoSel, m.gotoTop, len(m.gotoResults), gotoVisible, func(int) int { return 1 })
		end := gotoTop + gotoVisible
		if end > len(m.gotoResults) {
			end = len(m.gotoResults)
		}
		rowW := min(max(72, m.width-14), 120)
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
	sb.WriteString("\n" + m.theme.footerStyle.Render("↑/↓ select · Enter jump · Esc cancel"+count))
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
	// with handleSearchPopupClick via searchSwitches().
	var segs []string
	for _, sw := range m.searchSwitches() {
		segs = append(segs, m.theme.switchStyle.Render(sw.label))
	}
	switches := strings.Join(segs, searchSwitchSep)
	body := hint + "\n\n" + m.searchInput.View() + "\n\n" + switches + "\n" +
		m.theme.footerStyle.Render("click a switch · Ctrl+M mode · Ctrl+R direction · Ctrl+O origin · Enter find · Esc cancel")
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
	{"6·Libs", modeLibs},
	{"7·Raw", modeRaw},
	{"8·Strings", modeStrings},
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
		m.theme.titleStyle.Render(" exex "),
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

func (m *Model) renderFooter() string {
	// Footers stay short; the full cheat-sheet lives behind '?'.
	var help string
	switch m.mode {
	case modeInfo:
		help = "Enter disasm entry · g goto · ? help · q quit"
	case modeStrings:
		help = "Enter jump · / search · g goto · ? help · q quit"
	case modeSections:
		help = "Enter open · / filter · g goto · ? help · q quit"
	case modeSymbols:
		help = "Enter jump · / filter · g goto · ? help · q quit"
	case modeDisasm:
		help = "Enter follow · [ ] sym · ←/→ history · / search · g goto · ? help · q quit"
		if (m.showSource || m.sourceFirst) && m.file.HasDWARF() {
			help = "Tab toggle right pane · ⇧Tab swap panes · ⇧↑/⇧↓ scroll pane · [ ] sym · ←/→ history · / search · ? help · q quit"
		}
		if m.searchRunning {
			help = "Esc cancel search · [ ] sym · ←/→ history · / search · g goto · ? help · q quit"
		}
	case modeHex:
		help = "[ ] section · ⇧[ / ⇧] non-zero · / search · a/s copy · g goto · ? help · q quit"
	case modeRaw:
		help = "[ ] section · ⇧[ / ⇧] non-zero · / search · a/s copy · g goto · ? help · q quit"
	case modeSources:
		help = "Enter open in disasm · / filter · ^F grep all · c copy · g goto · ? help · q quit"
	case modeLibs:
		help = "↑/↓ move · ? help · q quit"
	}
	left := m.theme.footerStyle.Render(help)
	if m.status == "" {
		return padRight(left, m.width)
	}
	st := m.theme.infoStyle
	if m.statusError {
		st = m.theme.errorStyle
	}
	// Right-align the status in whatever space the help leaves.
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
