// Package ui implements the Bubble Tea TUI for elf-explorer.
package ui

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/psimonen/elf-explorer/internal/binfile"
	"github.com/psimonen/elf-explorer/internal/config"
	"github.com/psimonen/elf-explorer/internal/disasm"
)

type mode int

const (
	modeInfo mode = iota
	modeSections
	modeSymbols
	modeDisasm
	modeHex
	modeLibs
	modeRaw
	modeStrings
)

func (m mode) String() string {
	switch m {
	case modeInfo:
		return "Info"
	case modeSections:
		return "Sections"
	case modeSymbols:
		return "Symbols"
	case modeDisasm:
		return "Disasm"
	case modeHex:
		return "Hex"
	case modeLibs:
		return "Libs"
	case modeRaw:
		return "Raw"
	case modeStrings:
		return "Strings"
	}
	return "?"
}

// Model is the root Bubble Tea model.
type Model struct {
	file *binfile.File
	dis  disasm.Disassembler

	mode mode

	width, height int

	// Header view.
	headerVP viewport.Model

	// Sections view.
	sections    []binfile.Section
	sectionsCur int
	sectionsTop int

	// Symbols view.
	symbolsFilter   textinput.Model
	symbolsFiltered []int // indices into file.Symbols (sorted by name)
	symbolsCur      int
	symbolsTop      int

	// Disasm view. disasmInst holds the decode of *every* executable section,
	// in virtual-address order, built once on first use (disasmBuilt). The
	// decode is deferred until the view is first opened; disasmInitAddr is where
	// the cursor lands on that first open (the entry point), and
	// disasmPositioned guards that one-time landing.
	disasmInst       []disasm.Inst
	disasmBuilt      bool
	disasmInitAddr   uint64
	disasmPositioned bool
	disasmCur        int
	disasmTop        int
	showSource       bool
	srcVP            viewport.Model
	srcHL            map[string][]string // filename → per-line syntax-highlighted source

	// Navigation history for the disasm view: the last `historyCap` jump
	// targets, with `historyPos` indicating where in that ring we are. Left
	// arrow steps back, right arrow steps forward.
	history    []uint64
	historyPos int

	// Hex view (virtual-address): a continuous dump of every mapped section,
	// addressed by virtual address via hexImg.
	hexImg *binfile.Image
	hexCur int // byte position into hexImg.Data
	hexTop int // first row's byte position (multiple of bytesPerHexRow)

	// Raw view: the entire file dumped by file offset.
	rawData []byte
	rawCur  int
	rawTop  int

	// Libs view.
	libsCur int
	libsTop int

	// Strings view.
	stringsList []binfile.StringEntry
	stringsCur  int
	stringsTop  int

	// Mouse double-click tracking (for follow-on-double-click in disasm).
	lastClickY  int
	lastClickAt time.Time

	// Go-to-address modal.
	gotoInput  textinput.Model
	gotoActive bool

	// Transient status message displayed in the footer.
	status      string
	statusError bool

	// User-configurable keymap for the top-level dispatch.
	keys keyMap
}

func New(f *binfile.File) (*Model, error) {
	d, err := disasm.For(f.Arch())
	if err != nil {
		// Don't fail — the user can still browse header/sections/symbols.
		d = nil
	}

	// Load user config and overlay it before constructing styles/keymap.
	// A missing config file is fine (zero Config); a malformed one surfaces.
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	ApplyColors(cfg.Colors)
	keys := defaultKeyMap()
	keys.applyConfig(cfg.Keys)

	filter := textinput.New()
	filter.Placeholder = "type to filter…"
	filter.Prompt = "/ "
	filter.CharLimit = 256

	gotoInput := textinput.New()
	gotoInput.Placeholder = "0x401000 or symbol name"
	gotoInput.Prompt = "→ "
	gotoInput.CharLimit = 256

	m := &Model{
		file:          f,
		dis:           d,
		mode:          modeInfo,
		sections:      f.Sections,
		symbolsFilter: filter,
		gotoInput:     gotoInput,
		showSource:    true,
		keys:          keys,
	}
	m.headerVP = viewport.New(0, 0)
	m.srcVP = viewport.New(0, 0)
	m.recomputeSymbols()

	// The disassembly is decoded lazily on first open (it can be large); record
	// where the cursor should land then — the entry point.
	m.disasmInitAddr = f.Entry()
	return m, nil
}

func (m *Model) Init() tea.Cmd { return nil }

// recomputeSymbols rebuilds symbolsFiltered from the current filter text.
func (m *Model) recomputeSymbols() {
	needle := strings.ToLower(m.symbolsFilter.Value())
	m.symbolsFiltered = m.symbolsFiltered[:0]
	for i, s := range m.file.Symbols {
		if needle == "" ||
			strings.Contains(strings.ToLower(s.Name), needle) ||
			(s.Demangled != "" && strings.Contains(strings.ToLower(s.Demangled), needle)) {
			m.symbolsFiltered = append(m.symbolsFiltered, i)
		}
	}
	if m.symbolsCur >= len(m.symbolsFiltered) {
		m.symbolsCur = max(0, len(m.symbolsFiltered)-1)
	}
}

func (m *Model) setStatus(s string, isError bool) {
	m.status = s
	m.statusError = isError
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		bodyH := m.bodyHeight()
		m.headerVP.Width = m.width
		m.headerVP.Height = bodyH
		m.srcVP.Width = m.width / 2
		m.srcVP.Height = bodyH
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)

	case tea.MouseMsg:
		return m.handleMouse(msg)
	}
	return m, nil
}

func (m *Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	// Modal owns input while active.
	if m.gotoActive {
		switch key {
		case "esc":
			m.gotoActive = false
			m.gotoInput.Blur()
			m.gotoInput.SetValue("")
			return m, nil
		case "enter":
			val := strings.TrimSpace(m.gotoInput.Value())
			m.gotoActive = false
			m.gotoInput.Blur()
			m.gotoInput.SetValue("")
			m.handleGoto(val)
			return m, nil
		}
		var cmd tea.Cmd
		m.gotoInput, cmd = m.gotoInput.Update(msg)
		return m, cmd
	}

	// Filter input in symbols view captures typing keys.
	if m.mode == modeSymbols && m.symbolsFilter.Focused() {
		switch key {
		case "esc":
			m.symbolsFilter.Blur()
			return m, nil
		case "enter":
			m.symbolsFilter.Blur()
			return m, nil
		case "up", "down", "pgup", "pgdown", "home", "end":
			// Let navigation keys fall through.
		default:
			var cmd tea.Cmd
			m.symbolsFilter, cmd = m.symbolsFilter.Update(msg)
			m.recomputeSymbols()
			return m, cmd
		}
	}

	switch m.keys[key] {
	case actionQuit:
		return m, tea.Quit
	case actionViewInfo:
		m.switchMode(modeInfo)
		return m, nil
	case actionViewSections:
		m.switchMode(modeSections)
		return m, nil
	case actionViewSymbols:
		m.switchMode(modeSymbols)
		return m, nil
	case actionViewDisasm:
		m.switchMode(modeDisasm)
		return m, nil
	case actionViewHex:
		m.switchMode(modeHex)
		return m, nil
	case actionViewLibs:
		m.switchMode(modeLibs)
		return m, nil
	case actionViewRaw:
		m.switchMode(modeRaw)
		return m, nil
	case actionViewStrings:
		m.switchMode(modeStrings)
		return m, nil
	case actionGoto:
		m.gotoActive = true
		m.gotoInput.Focus()
		return m, nil
	case actionToggleSource:
		if m.mode == modeDisasm {
			m.showSource = !m.showSource
		}
		return m, nil
	}

	switch m.mode {
	case modeSections:
		return m.updateSections(key)
	case modeSymbols:
		return m.updateSymbols(key)
	case modeDisasm:
		return m.updateDisasm(key)
	case modeHex:
		return m.updateHex(key)
	case modeRaw:
		return m.updateRaw(key)
	case modeStrings:
		return m.updateStrings(key)
	case modeLibs:
		return m.updateLibs(key)
	case modeInfo:
		switch key {
		case "home":
			m.headerVP.GotoTop()
			return m, nil
		case "end", "G":
			m.headerVP.GotoBottom()
			return m, nil
		}
		var cmd tea.Cmd
		m.headerVP, cmd = m.headerVP.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m *Model) updateSections(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "up", "k":
		if m.sectionsCur > 0 {
			m.sectionsCur--
		}
	case "down", "j":
		if m.sectionsCur < len(m.sections)-1 {
			m.sectionsCur++
		}
	case "pgup":
		m.sectionsCur = max(0, m.sectionsCur-m.bodyHeight())
	case "pgdown":
		m.sectionsCur = min(len(m.sections)-1, m.sectionsCur+m.bodyHeight())
	case "home", "g g":
		m.sectionsCur = 0
	case "end", "G":
		m.sectionsCur = len(m.sections) - 1
	case "enter":
		sec := m.sections[m.sectionsCur]
		switch {
		case binfile.IsExecSection(&sec) && m.dis != nil:
			m.loadDisasmAt(sec.Addr)
		case sec.Alloc && sec.Addr != 0:
			m.openHexAt(sec.Addr)
		default:
			// No virtual address (debug, symbol tables, …): show its bytes in
			// the raw file view at the section's file offset.
			m.openRawAt(sec.Offset)
		}
	case "a":
		sec := m.sections[m.sectionsCur]
		m.copyToClipboard(fmt.Sprintf("0x%0*x", m.file.AddrHexWidth(), sec.Addr), "address")
	case "s":
		sec := m.sections[m.sectionsCur]
		m.copyToClipboard(sec.Name, "section name")
	}
	return m, nil
}

func (m *Model) updateSymbols(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "/":
		m.symbolsFilter.Focus()
		return m, nil
	case "up", "k":
		if m.symbolsCur > 0 {
			m.symbolsCur--
		}
	case "down", "j":
		if m.symbolsCur < len(m.symbolsFiltered)-1 {
			m.symbolsCur++
		}
	case "pgup":
		m.symbolsCur = max(0, m.symbolsCur-m.bodyHeight())
	case "pgdown":
		m.symbolsCur = min(len(m.symbolsFiltered)-1, m.symbolsCur+m.bodyHeight())
	case "home":
		m.symbolsCur = 0
	case "end", "G":
		m.symbolsCur = len(m.symbolsFiltered) - 1
	case "enter":
		if len(m.symbolsFiltered) == 0 {
			return m, nil
		}
		sym := m.file.Symbols[m.symbolsFiltered[m.symbolsCur]]
		if sym.Addr == 0 {
			m.setStatus(fmt.Sprintf("symbol %s has no address", sym.Name), true)
			return m, nil
		}
		m.openSymbol(sym)
	case "a":
		if len(m.symbolsFiltered) == 0 {
			return m, nil
		}
		sym := m.file.Symbols[m.symbolsFiltered[m.symbolsCur]]
		m.copyToClipboard(fmt.Sprintf("0x%0*x", m.file.AddrHexWidth(), sym.Addr), "address")
	case "s":
		if len(m.symbolsFiltered) == 0 {
			return m, nil
		}
		sym := m.file.Symbols[m.symbolsFiltered[m.symbolsCur]]
		m.copyToClipboard(sym.Name, "symbol")
	}
	return m, nil
}

// openSymbol opens a symbol in the most appropriate view. The hex and disasm
// views span the whole binary now, so this only chooses which view to land in
// and seeks the cursor onto the symbol's address:
//   - FUNC                  → disasm
//   - OBJECT/TLS/COMMON     → hex (virtual-address) view, cursor on the symbol
//   - SECTION               → exec ⇒ disasm; else hex/raw at the section
//   - NOTYPE                → exec section ⇒ disasm; else hex; else raw
func (m *Model) openSymbol(sym binfile.Symbol) {
	switch sym.Kind {
	case binfile.SymFunc:
		m.loadDisasmAt(sym.Addr)
	case binfile.SymObject, binfile.SymTLS, binfile.SymCommon:
		m.openHexAt(sym.Addr)
	default:
		if sec := m.file.SectionAt(sym.Addr); sec != nil && binfile.IsExecSection(sec) {
			m.loadDisasmAt(sym.Addr)
		} else {
			m.openHexAt(sym.Addr)
		}
	}
}

// copyToClipboard puts text on the system clipboard and reports success or
// failure to the user via the status footer.
func (m *Model) copyToClipboard(text, what string) {
	if err := clipboard.WriteAll(text); err != nil {
		m.setStatus(fmt.Sprintf("clipboard: %v", err), true)
		return
	}
	m.setStatus(fmt.Sprintf("copied %s: %s", what, text), false)
}

func (m *Model) handleGoto(val string) {
	if val == "" {
		return
	}
	// A numeric address routes to whichever view can show it.
	if parsed, err := parseAddr(val); err == nil {
		m.gotoAddr(parsed)
		return
	}
	// Else treat as symbol name (exact, then substring).
	idx := sort.Search(len(m.file.Symbols), func(i int) bool { return m.file.Symbols[i].Name >= val })
	if idx < len(m.file.Symbols) && m.file.Symbols[idx].Name == val && m.file.Symbols[idx].Addr != 0 {
		m.openSymbol(m.file.Symbols[idx])
		return
	}
	needle := strings.ToLower(val)
	for _, s := range m.file.Symbols {
		if s.Addr == 0 {
			continue
		}
		if strings.Contains(strings.ToLower(s.Name), needle) ||
			(s.Demangled != "" && strings.Contains(strings.ToLower(s.Demangled), needle)) {
			m.openSymbol(s)
			return
		}
	}
	m.setStatus(fmt.Sprintf("not found: %s", val), true)
}

// gotoAddr jumps to a virtual address: disasm if it lands in executable code,
// otherwise the hex view if it lands in any mapped section.
func (m *Model) gotoAddr(addr uint64) {
	if _, ok := m.file.ExecImage().PosForAddr(addr); ok && m.dis != nil {
		m.loadDisasmAt(addr)
		return
	}
	if _, ok := m.file.VAImage().PosForAddr(addr); ok {
		m.openHexAt(addr)
		return
	}
	m.setStatus(fmt.Sprintf("0x%x is not in any mapped section", addr), true)
}

func parseAddr(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return strconv.ParseUint(s[2:], 16, 64)
	}
	// Heuristic: any [a-f] means hex.
	for _, r := range s {
		if r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' {
			return strconv.ParseUint(s, 16, 64)
		}
	}
	return strconv.ParseUint(s, 10, 64)
}

// View renders the screen.
func (m *Model) View() string {
	if m.width == 0 || m.height == 0 {
		return "initializing…"
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
	case modeLibs:
		body = m.renderLibs()
	}
	parts = append(parts, body, m.renderFooter())
	out := lipgloss.JoinVertical(lipgloss.Left, parts...)
	if m.gotoActive {
		modal := modalStyle.Render("Go to address or symbol\n\n" + m.gotoInput.View() + "\n\nEnter to jump  Esc to cancel")
		mw := lipgloss.Width(modal)
		mh := lipgloss.Height(modal)
		out = overlay(out, modal, (m.width-mw)/2, (m.height-mh)/2)
	}
	return out
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
}

func (m *Model) tabSegment(label string, active bool) string {
	if active {
		return activeTabStyle.Render(label)
	}
	return tabStyle.Render(label)
}

func (m *Model) renderTabs() string {
	segs := []string{titleStyle.Render(" elf-explorer ")}
	for _, t := range tabItems {
		segs = append(segs, m.tabSegment(t.label, m.mode == t.mode))
	}
	row := lipgloss.JoinHorizontal(lipgloss.Left, segs...)
	pad := m.width - lipgloss.Width(row)
	if pad > 0 {
		row += strings.Repeat(" ", pad)
	}
	return row
}

// tabHitTest maps an x column on the tab row to the tab the user clicked.
func (m *Model) tabHitTest(x int) (mode, bool) {
	pos := lipgloss.Width(titleStyle.Render(" elf-explorer "))
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
// before it can render. Shared by the keyboard dispatch and tab clicks.
func (m *Model) switchMode(md mode) {
	switch md {
	case modeDisasm:
		if !m.ensureDisasm() {
			m.setStatus("no disassembler for this architecture", true)
			return
		}
		// First time in: land on the entry point. loadDisasmAt sets the mode.
		if !m.disasmPositioned && m.disasmInitAddr != 0 {
			m.loadDisasmAt(m.disasmInitAddr)
			return
		}
	case modeHex:
		m.ensureHex()
	case modeRaw:
		m.ensureRaw()
	case modeStrings:
		m.ensureStrings()
	}
	m.mode = md
}

func (m *Model) renderFooter() string {
	var help string
	switch m.mode {
	case modeInfo:
		help = "1-8 switch view · ↑/↓ scroll · Home/End begin/end · g goto · q quit"
	case modeStrings:
		help = "↑/↓ move · Home/End begin/end · Enter jump (if mapped) · a copy addr/off · s copy string · q quit"
	case modeSections:
		help = "↑/↓ move · Home/End begin/end · Enter view (disasm/hex/raw) · g goto · q quit"
	case modeSymbols:
		help = "↑/↓ move · Home/End begin/end · / filter · Enter jump · g goto · q quit"
	case modeDisasm:
		help = "↑/↓ scroll · [ ] prev/next sym · ←/→ history · Home/End begin/end · Enter follow · a/s copy · Tab src · g goto · q quit"
	case modeHex:
		help = "↑/↓/←/→ move · [ ] prev/next non-zero · Home/End begin/end · a copy addr · s copy sym · g goto · q quit"
	case modeRaw:
		help = "↑/↓/←/→ move · [ ] prev/next non-zero · Home/End begin/end · a copy offset · s copy sec · g goto · q quit"
	case modeLibs:
		help = "↑/↓ move · Home/End begin/end · q quit"
	}
	left := footerStyle.Render(help)
	right := ""
	if m.status != "" {
		st := infoStyle
		if m.statusError {
			st = errorStyle
		}
		right = st.Render(m.status)
	}
	gap := m.width - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 1 {
		gap = 1
	}
	return left + strings.Repeat(" ", gap) + right
}

// bodyHeight is the number of rows available between tabs and footer.
func (m *Model) bodyHeight() int {
	if m.height <= 2 {
		return 1
	}
	return m.height - 2
}

func (m *Model) renderInfo() string {
	var b strings.Builder
	kv := func(k, v string) {
		b.WriteString(headerKey.Render(padKey(k, 14)))
		b.WriteString(" ")
		b.WriteString(v)
		b.WriteString("\n")
	}

	// Core ELF header.
	for _, l := range m.file.HeaderInfo() {
		if idx := strings.IndexByte(l, ':'); idx >= 0 {
			b.WriteString(headerKey.Render(l[:idx+1]))
			b.WriteString(l[idx+1:])
		} else {
			b.WriteString(l)
		}
		b.WriteString("\n")
	}

	if m.dis != nil {
		kv("Disassembler:", m.dis.Name())
	}

	if info := m.file.Info; info != nil {
		b.WriteString("\n")
		if info.Interp != "" {
			kv("Interpreter:", info.Interp)
		}
		if info.SoName != "" {
			kv("SONAME:", info.SoName)
		}
		if len(info.RPath) > 0 {
			kv("RPATH:", strings.Join(info.RPath, ":"))
		}
		if len(info.RunPath) > 0 {
			kv("RUNPATH:", strings.Join(info.RunPath, ":"))
		}
		if info.BuildID != "" {
			kv("Build ID:", info.BuildID)
		}
		kv("Stripped:", fmt.Sprintf("%v", info.Stripped))
		kv("Static-linked:", fmt.Sprintf("%v", info.StaticLinked))
		if info.Libc.Kind != "" {
			val := info.Libc.Kind
			if info.Libc.Version != "" {
				val += " " + info.Libc.Version
			}
			if info.Libc.Source != "" {
				val += "  " + footerStyle.Render("("+info.Libc.Source+")")
			}
			kv("Libc:", val)
		}
		if len(info.DynamicLibs) > 0 {
			kv("Needed libs:", fmt.Sprintf("%d (press 6 to view)", len(info.DynamicLibs)))
		}
	}

	return padBody(b.String(), m.width, m.bodyHeight())
}

// padKey right-pads a key label to a fixed column, ignoring the trailing colon
// for alignment purposes.
func padKey(s string, w int) string {
	if len(s) >= w {
		return s
	}
	return s + strings.Repeat(" ", w-len(s))
}

func (m *Model) renderSections() string {
	bodyH := m.bodyHeight()
	// columns: idx, name, type, addr, size, flags
	addrW := m.file.AddrHexWidth() // hex digits in an address
	addrCol := 2 + addrW           // "0x" + digits
	hdr := fmt.Sprintf(" %3s  %-22s %-14s %-*s %-12s  %s",
		"#", "Name", "Type", addrCol, "Addr", "Size", "Flags")
	if len(hdr) > m.width {
		hdr = hdr[:m.width]
	}
	header := tableHeaderStyle.Render(padRight(hdr, m.width))

	visible := bodyH - 1
	if visible < 1 {
		visible = 1
	}
	if m.sectionsCur < m.sectionsTop {
		m.sectionsTop = m.sectionsCur
	} else if m.sectionsCur >= m.sectionsTop+visible {
		m.sectionsTop = m.sectionsCur - visible + 1
	}
	end := m.sectionsTop + visible
	if end > len(m.sections) {
		end = len(m.sections)
	}

	var b strings.Builder
	b.WriteString(header)
	b.WriteString("\n")
	for i := m.sectionsTop; i < end; i++ {
		s := m.sections[i]
		line := fmt.Sprintf(" %3d  %-22s %-14s 0x%0*x %-12d  %s",
			i, truncate(s.Name, 22), truncate(s.TypeName, 14), addrW, s.Addr, s.Size, s.Flags)
		line = padRight(line, m.width)
		if i == m.sectionsCur {
			b.WriteString(tableSelStyle.Render(line))
		} else {
			b.WriteString(styleForSection(&s).Render(line))
		}
		b.WriteString("\n")
	}
	return padBody(b.String(), m.width, bodyH)
}

func (m *Model) renderSymbols() string {
	bodyH := m.bodyHeight()
	if bodyH < 3 {
		bodyH = 3
	}

	filterRow := m.symbolsFilter.View()
	if !m.symbolsFilter.Focused() {
		filterRow = footerStyle.Render(fmt.Sprintf("/ %s   (%d / %d)", m.symbolsFilter.Value(), len(m.symbolsFiltered), len(m.file.Symbols)))
	}

	addrW := m.file.AddrHexWidth()
	addrCol := 2 + addrW
	hdr := fmt.Sprintf(" %-*s %-6s %-5s %-8s  %s", addrCol, "Address", "Size", "Bind", "Type", "Name")
	header := tableHeaderStyle.Render(padRight(hdr, m.width))

	visible := bodyH - 2 // filter row + header
	if visible < 1 {
		visible = 1
	}
	if m.symbolsCur < m.symbolsTop {
		m.symbolsTop = m.symbolsCur
	} else if m.symbolsCur >= m.symbolsTop+visible {
		m.symbolsTop = m.symbolsCur - visible + 1
	}
	end := m.symbolsTop + visible
	if end > len(m.symbolsFiltered) {
		end = len(m.symbolsFiltered)
	}

	var rows strings.Builder
	rows.WriteString(filterRow)
	rows.WriteString("\n")
	rows.WriteString(header)
	rows.WriteString("\n")
	for i := m.symbolsTop; i < end; i++ {
		s := m.file.Symbols[m.symbolsFiltered[i]]
		line := fmt.Sprintf(" 0x%0*x %-6d %-5s %-8s  %s",
			addrW, s.Addr, s.Size, bindString(s.Bind), kindString(s.Kind), s.Display())
		line = padRight(line, m.width)
		if i == m.symbolsCur {
			rows.WriteString(tableSelStyle.Render(line))
		} else {
			rows.WriteString(styleForSymbol(s.Kind, s.Bind).Render(line))
		}
		rows.WriteString("\n")
	}
	return padBody(rows.String(), m.width, bodyH)
}

// ---- helpers ----

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// bytesHex renders up to maxN bytes as space-separated, per-byte-coloured hex.
// The output is padded with plain spaces to a fixed visible width so columns
// line up regardless of how many bytes the instruction occupied. Uses the
// precomputed byteHex table to avoid re-rendering ANSI codes on every byte.
func bytesHex(b []byte, maxN int) string {
	if len(b) > maxN {
		b = b[:maxN]
	}
	var sb strings.Builder
	for i, x := range b {
		if i > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(byteHex[x])
	}
	visible := len(b)*3 - 1
	if len(b) == 0 {
		visible = 0
	}
	want := maxN*3 - 1
	if visible < want {
		sb.WriteString(strings.Repeat(" ", want-visible))
	}
	return sb.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

func padRight(s string, w int) string {
	plain := stripANSI(s)
	if lipgloss.Width(plain) >= w {
		return s
	}
	return s + strings.Repeat(" ", w-lipgloss.Width(plain))
}

func padBody(s string, w, h int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > h {
		lines = lines[:h]
	}
	for len(lines) < h {
		lines = append(lines, strings.Repeat(" ", w))
	}
	return strings.Join(lines, "\n")
}

// overlay places fg over bg at column x, row y. Both are pre-rendered strings.
func overlay(bg, fg string, x, y int) string {
	if x < 0 {
		x = 0
	}
	if y < 0 {
		y = 0
	}
	bgLines := strings.Split(bg, "\n")
	fgLines := strings.Split(fg, "\n")
	for i, fl := range fgLines {
		row := y + i
		if row >= len(bgLines) {
			break
		}
		bgLine := bgLines[row]
		// Convert to runes for width-safe slicing — assume printable.
		plain := stripANSI(bgLine)
		if x >= lipgloss.Width(plain) {
			bgLines[row] = bgLine + strings.Repeat(" ", x-lipgloss.Width(plain)) + fl
			continue
		}
		// Best-effort overlay: just replace the whole row when fg width fits.
		fw := lipgloss.Width(stripANSI(fl))
		prefix := plain
		if x < len(prefix) {
			prefix = prefix[:x]
		}
		suffix := ""
		if x+fw < lipgloss.Width(plain) {
			suffix = plain[x+fw:]
		}
		bgLines[row] = prefix + fl + suffix
	}
	return strings.Join(bgLines, "\n")
}

// stripANSI removes ANSI escape sequences for width math. Cheap and good enough
// for our render strings, which only carry simple SGR codes from lipgloss.
func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && (s[j] < 0x40 || s[j] > 0x7e) {
				j++
			}
			if j < len(s) {
				j++
			}
			i = j - 1
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// fitANSIWidth keeps a styled string intact when it fits within w visible
// columns, and falls back to a plain truncation when it doesn't — so a single
// over-long source line can't break the side-by-side layout while normal-width
// lines retain their syntax colours.
func fitANSIWidth(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if lipgloss.Width(stripANSI(s)) <= w {
		return s
	}
	return truncateANSI(s, w)
}

// truncateANSI naively truncates while keeping the trailing SGR reset.
func truncateANSI(s string, w int) string {
	plain := stripANSI(s)
	if lipgloss.Width(plain) <= w {
		return s
	}
	// Walk and drop characters from the end of the plain content. Cheap fallback.
	return plain[:w]
}
