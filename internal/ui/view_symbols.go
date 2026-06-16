package ui

// This file owns the symbols view: a filterable table of the merged symbol
// table (matching on both raw and demangled names), plus openSymbol, which
// routes a chosen symbol to the most useful view.

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"

	"github.com/rabarbra/exex/internal/binfile"
)

// recomputeSymbols rebuilds symbolsFiltered from the current filter text.
func (m *Model) recomputeSymbols() {
	m.clearSymbolCaches()
	needle := strings.ToLower(m.symbolsFilter.Value())
	m.symbolsFiltered = m.symbolsFiltered[:0]
	for i, s := range m.file.Symbols {
		if m.symbolsKindOn && s.Kind != m.symbolsKind {
			continue
		}
		if m.symbolsLib != "" && s.Library != m.symbolsLib {
			continue
		}
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

func (m *Model) updateSymbols(key string) (tea.Model, tea.Cmd) {
	if navKey(&m.symbolsCur, len(m.symbolsFiltered), m.bodyHeight(), key) {
		return m, nil
	}
	switch key {
	case "/":
		m.symbolsFilter.Focus()
		return m, nil
	case "esc":
		if m.symbolsLib != "" {
			m.symbolsLib = ""
			m.symbolsCur, m.symbolsTop = 0, 0
			m.recomputeSymbols()
			m.setStatus("library filter cleared", false)
		}
		return m, nil
	case "t":
		m.cycleSymbolKindFilter()
		m.recomputeSymbols()
		return m, nil
	case "w":
		m.toggleWrap()
		return m, nil
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

func (m *Model) cycleSymbolKindFilter() {
	order := []binfile.SymKind{binfile.SymFunc, binfile.SymObject, binfile.SymSection, binfile.SymFile, binfile.SymTLS, binfile.SymCommon, binfile.SymOther}
	if !m.symbolsKindOn {
		m.symbolsKindOn = true
		m.symbolsKind = order[0]
		m.setStatus("symbol type filter: "+kindString(m.symbolsKind), false)
		return
	}
	for i, k := range order {
		if k == m.symbolsKind {
			if i == len(order)-1 {
				m.symbolsKindOn = false
				m.setStatus("symbol type filter: all", false)
				return
			}
			m.symbolsKind = order[i+1]
			m.setStatus("symbol type filter: "+kindString(m.symbolsKind), false)
			return
		}
	}
	m.symbolsKindOn = false
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

func (m *Model) renderSymbols() string {
	bodyH := m.bodyHeight()
	if bodyH < 3 {
		bodyH = 3
	}

	filterRow := m.symbolsFilter.View()
	if !m.symbolsFilter.Focused() {
		kind := "all"
		if m.symbolsKindOn {
			kind = kindString(m.symbolsKind)
		}
		libPart := ""
		if m.symbolsLib != "" {
			libPart = "   lib:" + m.symbolsLib + " (Esc clears)"
		}
		filterRow = m.theme.footerStyle.Render(fmt.Sprintf("/ %s   type:%s%s   (%d / %d)", m.symbolsFilter.Value(), kind, libPart, len(m.symbolsFiltered), len(m.file.Symbols)))
	}

	addrW := m.file.AddrHexWidth()
	addrCol := 2 + addrW
	hdr := fmt.Sprintf(" %-*s %-6s %-5s %-8s  %s", addrCol, "Address", "Size", "Bind", "Type", "Name")
	header := m.tableHeader(hdr)

	visible := bodyH - 2 // filter row + header
	if visible < 1 {
		visible = 1
	}
	rowHeight := func(i int) int {
		return m.symbolRowHeight(i)
	}
	top := m.visualTopForView(m.symbolsCur, m.symbolsTop, len(m.symbolsFiltered), visible, rowHeight)
	m.symbolsTop = top
	m.renderedSymbolsTop = top

	rows := []string{filterRow, header}
	for i := top; i < len(m.symbolsFiltered); i++ {
		for _, row := range m.symbolRows(i, addrW) {
			if len(rows) >= bodyH {
				break
			}
			if i == m.symbolsCur {
				row = m.theme.tableSelStyle.Render(stripANSI(row))
			}
			rows = append(rows, row)
		}
		if len(rows) >= bodyH {
			break
		}
	}
	return padBodyRows(rows, m.width, bodyH)
}

func (m *Model) symbolRowHeight(i int) int {
	if i < 0 || i >= len(m.symbolsFiltered) {
		return 1
	}
	key := symbolRowCacheKey{i, m.width, m.file.AddrHexWidth(), m.wrap}
	if m.symbolHeightCache != nil {
		if h, ok := m.symbolHeightCache[key]; ok {
			return h
		}
	}
	h := len(m.symbolRows(i, m.file.AddrHexWidth()))
	if m.symbolHeightCache == nil {
		m.symbolHeightCache = make(map[symbolRowCacheKey]int)
	}
	m.symbolHeightCache[key] = h
	return h
}

func (m *Model) symbolRows(i, addrW int) []string {
	s := m.file.Symbols[m.symbolsFiltered[i]]

	key := symbolRowCacheKey{i, m.width, addrW, m.wrap}
	if m.symbolRowCache != nil {
		if rows, ok := m.symbolRowCache[key]; ok {
			return rows
		}
	}

	rowStyle := m.theme.styleForSymbol(s.Kind, s.Bind)
	prefixPlain := fmt.Sprintf(" 0x%0*x %-6d %-5s %-8s  ", addrW, s.Addr, s.Size, bindString(s.Bind), kindString(s.Kind))
	prefix := " " + m.theme.addrStyle.Render(fmt.Sprintf("0x%0*x", addrW, s.Addr)) + rowStyle.Render(fmt.Sprintf(" %-6d %-5s %-8s  ", s.Size, bindString(s.Bind), kindString(s.Kind)))
	nameW := m.width - len(prefixPlain)
	if nameW < 1 {
		nameW = 1
	}
	name := s.Display()
	parts := []string{name}
	if m.wrap {
		parts = strings.Split(strings.TrimRight(ansi.Wrap(name, nameW, " \t/.-_:$@<>"), "\n"), "\n")
		if len(parts) == 0 {
			parts = []string{""}
		}
	} else {
		parts = []string{truncateMiddle(name, nameW)}
	}
	rows := make([]string, 0, len(parts))
	for j, part := range parts {
		var line string
		if j == 0 {
			line = prefix + rowStyle.Render(part)
		} else {
			line = strings.Repeat(" ", len(prefixPlain)) + rowStyle.Render(part)
		}
		rows = append(rows, line)
	}

	if m.symbolRowCache == nil {
		m.symbolRowCache = make(map[symbolRowCacheKey][]string)
	}
	m.symbolRowCache[key] = rows
	return rows
}
