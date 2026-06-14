package ui

// This file owns the symbols view: a filterable table of the merged symbol
// table (matching on both raw and demangled names), plus openSymbol, which
// routes a chosen symbol to the most useful view.

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/rabarbra/exex/internal/binfile"
)

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
