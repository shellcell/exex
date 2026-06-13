// Package ui implements the Bubble Tea TUI for elf-explorer.
package ui

import (
	"debug/elf"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/psimonen/elf-explorer/internal/binfile"
	"github.com/psimonen/elf-explorer/internal/disasm"
)

type mode int

const (
	modeHeader mode = iota
	modeSections
	modeSymbols
	modeDisasm
)

func (m mode) String() string {
	switch m {
	case modeHeader:
		return "Header"
	case modeSections:
		return "Sections"
	case modeSymbols:
		return "Symbols"
	case modeDisasm:
		return "Disasm"
	}
	return "?"
}

// disasmWindow caps the number of bytes we decode at once. Big enough to fill
// a screen comfortably, small enough to keep redraws snappy.
const disasmWindow = 4096

// Model is the root Bubble Tea model.
type Model struct {
	file *binfile.File
	dis  disasm.Disassembler

	mode mode

	width, height int

	// Header view.
	headerVP viewport.Model

	// Sections view.
	sections    []*elf.Section
	sectionsCur int
	sectionsTop int

	// Symbols view.
	symbolsFilter   textinput.Model
	symbolsFiltered []int // indices into file.Symbols (sorted by name)
	symbolsCur      int
	symbolsTop      int

	// Disasm view.
	disasmAddr uint64
	disasmInst []disasm.Inst
	disasmCur  int
	disasmTop  int
	showSource bool
	srcVP      viewport.Model

	// Go-to-address modal.
	gotoInput  textinput.Model
	gotoActive bool

	// Transient status message displayed in the footer.
	status      string
	statusError bool
}

func New(f *binfile.File) (*Model, error) {
	d, err := disasm.For(f.Machine())
	if err != nil {
		// Don't fail — the user can still browse header/sections/symbols.
		d = nil
	}

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
		mode:          modeHeader,
		sections:      f.Sections,
		symbolsFilter: filter,
		gotoInput:     gotoInput,
		showSource:    true,
	}
	m.headerVP = viewport.New(0, 0)
	m.srcVP = viewport.New(0, 0)
	m.recomputeSymbols()

	// Land the disasm cursor on the entry point by default if it's mapped.
	if d != nil && f.Entry() != 0 {
		m.loadDisasmAt(f.Entry())
	}
	return m, nil
}

func (m *Model) Init() tea.Cmd { return nil }

// recomputeSymbols rebuilds symbolsFiltered from the current filter text.
func (m *Model) recomputeSymbols() {
	needle := strings.ToLower(m.symbolsFilter.Value())
	m.symbolsFiltered = m.symbolsFiltered[:0]
	for i, s := range m.file.Symbols {
		if needle == "" || strings.Contains(strings.ToLower(s.Name), needle) {
			m.symbolsFiltered = append(m.symbolsFiltered, i)
		}
	}
	if m.symbolsCur >= len(m.symbolsFiltered) {
		m.symbolsCur = max(0, len(m.symbolsFiltered)-1)
	}
}

// loadDisasmAt fills disasmInst by decoding a window starting at addr.
func (m *Model) loadDisasmAt(addr uint64) {
	if m.dis == nil {
		m.setStatus("no disassembler for this architecture", true)
		return
	}
	buf, err := m.file.ReadAt(addr, disasmWindow)
	if err != nil {
		m.setStatus(err.Error(), true)
		return
	}
	m.disasmAddr = addr
	m.disasmInst = disasm.Range(m.dis, buf, addr, 0)
	m.disasmCur = 0
	m.disasmTop = 0
	m.mode = modeDisasm
	m.status = ""
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

	switch key {
	case "ctrl+c", "q":
		return m, tea.Quit
	case "1":
		m.mode = modeHeader
		return m, nil
	case "2":
		m.mode = modeSections
		return m, nil
	case "3":
		m.mode = modeSymbols
		return m, nil
	case "4":
		if m.dis == nil {
			m.setStatus("no disassembler for this architecture", true)
			return m, nil
		}
		m.mode = modeDisasm
		return m, nil
	case "g":
		m.gotoActive = true
		m.gotoInput.Focus()
		return m, nil
	case "tab":
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
	case modeHeader:
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
		if sec.Flags&elf.SHF_EXECINSTR != 0 && m.dis != nil {
			m.loadDisasmAt(sec.Addr)
		} else {
			m.setStatus(fmt.Sprintf("section %s is not executable", sec.Name), true)
		}
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
		m.loadDisasmAt(sym.Addr)
	}
	return m, nil
}

func (m *Model) updateDisasm(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "up", "k":
		if m.disasmCur > 0 {
			m.disasmCur--
		}
	case "down", "j":
		if m.disasmCur < len(m.disasmInst)-1 {
			m.disasmCur++
		}
		// Auto-load next window when near the end.
		if m.disasmCur >= len(m.disasmInst)-1 && len(m.disasmInst) > 0 {
			last := m.disasmInst[len(m.disasmInst)-1]
			next := last.Addr + uint64(len(last.Bytes))
			if _, err := m.file.ReadAt(next, 1); err == nil {
				saved := m.disasmCur
				m.loadDisasmAt(next)
				m.mode = modeDisasm // loadDisasmAt sets mode; explicit for clarity
				m.disasmCur = saved
				_ = saved
			}
		}
	case "pgup":
		m.disasmCur = max(0, m.disasmCur-m.bodyHeight())
	case "pgdown":
		m.disasmCur = min(len(m.disasmInst)-1, m.disasmCur+m.bodyHeight())
	case "home":
		m.disasmCur = 0
	case "end", "G":
		m.disasmCur = len(m.disasmInst) - 1
	}
	return m, nil
}

func (m *Model) handleGoto(val string) {
	if val == "" {
		return
	}
	// Hex address first.
	parsed, err := parseAddr(val)
	if err == nil {
		if m.dis == nil {
			m.setStatus("no disassembler for this architecture", true)
			return
		}
		m.loadDisasmAt(parsed)
		return
	}
	// Else treat as symbol name (exact, then substring).
	idx := sort.Search(len(m.file.Symbols), func(i int) bool { return m.file.Symbols[i].Name >= val })
	if idx < len(m.file.Symbols) && m.file.Symbols[idx].Name == val {
		s := m.file.Symbols[idx]
		if s.Addr != 0 && m.dis != nil {
			m.loadDisasmAt(s.Addr)
			return
		}
	}
	needle := strings.ToLower(val)
	for _, s := range m.file.Symbols {
		if s.Addr != 0 && strings.Contains(strings.ToLower(s.Name), needle) {
			if m.dis != nil {
				m.loadDisasmAt(s.Addr)
				return
			}
		}
	}
	m.setStatus(fmt.Sprintf("not found: %s", val), true)
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
	case modeHeader:
		body = m.renderHeader()
	case modeSections:
		body = m.renderSections()
	case modeSymbols:
		body = m.renderSymbols()
	case modeDisasm:
		body = m.renderDisasm()
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

func (m *Model) renderTabs() string {
	render := func(label string, active bool) string {
		if active {
			return activeTabStyle.Render(label)
		}
		return tabStyle.Render(label)
	}
	tabs := []string{
		titleStyle.Render(" elf-explorer "),
		render("1·Header", m.mode == modeHeader),
		render("2·Sections", m.mode == modeSections),
		render("3·Symbols", m.mode == modeSymbols),
		render("4·Disasm", m.mode == modeDisasm),
	}
	row := lipgloss.JoinHorizontal(lipgloss.Left, tabs...)
	pad := m.width - lipgloss.Width(row)
	if pad > 0 {
		row += strings.Repeat(" ", pad)
	}
	return row
}

func (m *Model) renderFooter() string {
	var help string
	switch m.mode {
	case modeHeader:
		help = "1/2/3/4 switch · g goto · q quit"
	case modeSections:
		help = "↑/↓ move · Enter disasm · g goto · q quit"
	case modeSymbols:
		help = "↑/↓ move · / filter · Enter jump · g goto · q quit"
	case modeDisasm:
		help = "↑/↓ move · Tab source pane · g goto · q quit"
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

func (m *Model) renderHeader() string {
	lines := m.file.HeaderInfo()
	var b strings.Builder
	for _, l := range lines {
		idx := strings.IndexByte(l, ':')
		if idx < 0 {
			b.WriteString(l)
		} else {
			b.WriteString(headerKey.Render(l[:idx+1]))
			b.WriteString(l[idx+1:])
		}
		b.WriteString("\n")
	}
	if m.dis != nil {
		b.WriteString("\n")
		b.WriteString(headerKey.Render("Disassembler:"))
		b.WriteString(" " + m.dis.Name())
		b.WriteString("\n")
	}
	return padBody(b.String(), m.width, m.bodyHeight())
}

func (m *Model) renderSections() string {
	bodyH := m.bodyHeight()
	// columns: idx, name, type, addr, size, flags
	addrW := m.file.AddrHexWidth()        // hex digits in an address
	addrCol := 2 + addrW                  // "0x" + digits
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
			i, truncate(s.Name, 22), trimSecType(s.Type.String()), addrW, s.Addr, s.Size, sectionFlags(s.Flags))
		line = padRight(line, m.width)
		if i == m.sectionsCur {
			b.WriteString(tableSelStyle.Render(line))
		} else {
			b.WriteString(tableRowStyle.Render(line))
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
			addrW, s.Addr, s.Size, trimBind(s.Bind), trimType(s.Type), s.Name)
		line = padRight(line, m.width)
		if i == m.symbolsCur {
			rows.WriteString(tableSelStyle.Render(line))
		} else {
			rows.WriteString(symbolNameStyle.Render(line))
		}
		rows.WriteString("\n")
	}
	return padBody(rows.String(), m.width, bodyH)
}

func (m *Model) renderDisasm() string {
	bodyH := m.bodyHeight()
	if len(m.disasmInst) == 0 {
		msg := "no disassembly loaded — press g to go to an address, or pick a symbol from view 3"
		return padBody(msg+"\n", m.width, bodyH)
	}
	leftW := m.width
	rightW := 0
	if m.showSource {
		leftW = m.width / 2
		rightW = m.width - leftW
	}

	left := m.renderDisasmPane(leftW, bodyH)
	if rightW == 0 {
		return left
	}
	right := m.renderSourcePane(rightW, bodyH)
	return lipgloss.JoinHorizontal(lipgloss.Top, left, right)
}

func (m *Model) renderDisasmPane(w, h int) string {
	if m.disasmCur < m.disasmTop {
		m.disasmTop = m.disasmCur
	} else if m.disasmCur >= m.disasmTop+h {
		m.disasmTop = m.disasmCur - h + 1
	}
	end := m.disasmTop + h
	if end > len(m.disasmInst) {
		end = len(m.disasmInst)
	}

	var b strings.Builder
	for i := m.disasmTop; i < end; i++ {
		inst := m.disasmInst[i]
		line := fmt.Sprintf(" %s  %s  %s",
			addrStyle.Render(fmt.Sprintf("0x%0*x", m.file.AddrHexWidth(), inst.Addr)),
			bytesHex(inst.Bytes, 8),
			mnemonicStyle.Render(inst.Text),
		)
		// Symbol prefix if instruction starts at a known symbol address.
		if sym, ok := m.file.SymbolAt(inst.Addr); ok && sym.Addr == inst.Addr {
			tag := symbolNameStyle.Render("<" + sym.Name + ">:")
			b.WriteString(padRight(" "+tag, w))
			b.WriteString("\n")
			h--
			if h <= 0 {
				break
			}
		}
		plain := stripANSI(line)
		if lipgloss.Width(plain) < w {
			line += strings.Repeat(" ", w-lipgloss.Width(plain))
		} else if lipgloss.Width(plain) > w {
			// hard truncate to keep right pane aligned
			line = truncateANSI(line, w)
		}
		if i == m.disasmCur {
			line = tableSelStyle.Render(stripANSI(line))
			if lipgloss.Width(line) < w {
				line += strings.Repeat(" ", w-lipgloss.Width(line))
			}
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return padBody(b.String(), w, m.bodyHeight())
}

func (m *Model) renderSourcePane(w, h int) string {
	border := lipgloss.NewStyle().BorderStyle(lipgloss.NormalBorder()).BorderLeft(true).BorderForeground(lipgloss.Color("240"))
	inner := w - 1
	if inner < 8 {
		inner = w
	}

	if len(m.disasmInst) == 0 {
		return border.Render(padBody("", inner, h))
	}
	addr := m.disasmInst[m.disasmCur].Addr
	file, line := m.file.LookupAddr(addr)
	if file == "" {
		body := "no source mapping for 0x" + fmt.Sprintf("%x", addr)
		return border.Render(padBody(body+"\n", inner, h))
	}
	src := m.file.SourceLines(file)
	if src == nil {
		body := fmt.Sprintf("%s:%d (source file not found)\n", file, line)
		return border.Render(padBody(body, inner, h))
	}

	var b strings.Builder
	b.WriteString(infoStyle.Render(fmt.Sprintf("%s:%d", file, line)))
	b.WriteString("\n")
	half := (h - 1) / 2
	from := line - half
	if from < 1 {
		from = 1
	}
	to := from + h - 2
	if to > len(src) {
		to = len(src)
		from = to - (h - 2)
		if from < 1 {
			from = 1
		}
	}
	for i := from; i <= to; i++ {
		var content string
		if i-1 >= 0 && i-1 < len(src) {
			content = src[i-1]
		}
		prefix := srcLineNoStyle.Render(fmt.Sprintf("%5d  ", i))
		ln := prefix + content
		if i == line {
			ln = srcCurLineStyle.Render(padRight(stripANSI(ln), inner))
		}
		b.WriteString(ln)
		b.WriteString("\n")
	}
	return border.Render(padBody(b.String(), inner, h))
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
// line up regardless of how many bytes the instruction occupied.
func bytesHex(b []byte, maxN int) string {
	if len(b) > maxN {
		b = b[:maxN]
	}
	var sb strings.Builder
	for i, x := range b {
		if i > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(byteFG[x].Render(fmt.Sprintf("%02x", x)))
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

func sectionFlags(f elf.SectionFlag) string {
	var b strings.Builder
	if f&elf.SHF_ALLOC != 0 {
		b.WriteByte('A')
	}
	if f&elf.SHF_WRITE != 0 {
		b.WriteByte('W')
	}
	if f&elf.SHF_EXECINSTR != 0 {
		b.WriteByte('X')
	}
	if f&elf.SHF_MERGE != 0 {
		b.WriteByte('M')
	}
	if f&elf.SHF_STRINGS != 0 {
		b.WriteByte('S')
	}
	if f&elf.SHF_TLS != 0 {
		b.WriteByte('T')
	}
	if b.Len() == 0 {
		return "-"
	}
	return b.String()
}

func trimSecType(s string) string { return strings.TrimPrefix(s, "SHT_") }
func trimBind(b elf.SymBind) string {
	return strings.TrimPrefix(b.String(), "STB_")
}
func trimType(t elf.SymType) string {
	return strings.TrimPrefix(t.String(), "STT_")
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

// truncateANSI naively truncates while keeping the trailing SGR reset.
func truncateANSI(s string, w int) string {
	plain := stripANSI(s)
	if lipgloss.Width(plain) <= w {
		return s
	}
	// Walk and drop characters from the end of the plain content. Cheap fallback.
	return plain[:w]
}
