package ui

// This file owns the symbols view: a filterable table of the merged symbol
// table (matching on both raw and demangled names), plus openSymbol, which
// routes a chosen symbol to the most useful view.

import (
	"fmt"
	"sort"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/rabarbra/exex/internal/binfile"
)

// symbolSort is the display order of the (filtered) symbol table.
type symbolSort uint8

const (
	sortByName symbolSort = iota // f.Symbols' own order (already name-sorted)
	sortByAddr
	sortBySize
)

// String returns the sort's filter-status label.
func (s symbolSort) String() string {
	switch s {
	case sortByAddr:
		return "address"
	case sortBySize:
		return "size"
	}
	return "name"
}

// symbolScope filters the symbol table by where a symbol comes from.
type symbolScope uint8

const (
	scopeAll      symbolScope = iota // every symbol
	scopeInternal                    // defined in this binary (own functions/data)
	scopeImported                    // bound to a shared library (PLT/GOT/stubs)
)

// String returns the scope's filter-status label.
func (sc symbolScope) String() string {
	switch sc {
	case scopeInternal:
		return "internal"
	case scopeImported:
		return "imported"
	}
	return "all"
}

// includes reports whether s passes the scope filter. Internal means defined
// here (a real address, not bound to a library); imported means bound to a
// shared library (the synthesised PLT/GOT/stub symbols).
func (sc symbolScope) includes(s binfile.Symbol) bool {
	switch sc {
	case scopeInternal:
		return s.Library == "" && s.Addr != 0
	case scopeImported:
		return s.Library != ""
	}
	return true
}

// recomputeSymbols rebuilds symbolsFiltered from the current filter text.
func (m *Model) recomputeSymbols() {
	m.clearSymbolCaches()
	needle := strings.ToLower(m.symbolsFilter.Value())
	lowerName, lowerDem := m.file.LowerNames()
	m.symbolsFiltered = m.symbolsFiltered[:0]
	for i, s := range m.file.Symbols {
		if m.symbolsKindOn && s.Kind != m.symbolsKind {
			continue
		}
		if m.symbolsBindOn && s.Bind != m.symbolsBind {
			continue
		}
		if !m.symbolsScope.includes(s) {
			continue
		}
		if m.symbolsLib != "" && s.Library != m.symbolsLib {
			continue
		}
		if needle == "" ||
			strings.Contains(lowerName[i], needle) ||
			(lowerDem[i] != "" && strings.Contains(lowerDem[i], needle)) {
			m.symbolsFiltered = append(m.symbolsFiltered, i)
		}
	}
	m.applySymbolSort()
	if m.symbolsCur >= len(m.symbolsFiltered) {
		m.symbolsCur = max(0, len(m.symbolsFiltered)-1)
	}
}

// applySymbolSort orders symbolsFiltered by the active sort. Name order is the
// natural order (f.Symbols is name-sorted and indices were appended ascending),
// so only address/size need an explicit sort.
func (m *Model) applySymbolSort() {
	switch m.symbolsSort {
	case sortByAddr:
		sort.SliceStable(m.symbolsFiltered, func(i, j int) bool {
			return m.file.Symbols[m.symbolsFiltered[i]].Addr < m.file.Symbols[m.symbolsFiltered[j]].Addr
		})
	case sortBySize:
		sort.SliceStable(m.symbolsFiltered, func(i, j int) bool {
			return m.file.Symbols[m.symbolsFiltered[i]].Size > m.file.Symbols[m.symbolsFiltered[j]].Size
		})
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
	case "i":
		m.symbolsScope = (m.symbolsScope + 1) % 3
		m.symbolsCur, m.symbolsTop = 0, 0
		m.recomputeSymbols()
		m.setStatus("symbol scope: "+m.symbolsScope.String(), false)
		return m, nil
	case "b":
		m.cycleSymbolBindFilter()
		m.symbolsCur, m.symbolsTop = 0, 0
		m.recomputeSymbols()
		return m, nil
	case "o":
		m.symbolsSort = (m.symbolsSort + 1) % 3
		m.symbolsCur, m.symbolsTop = 0, 0
		m.recomputeSymbols()
		m.setStatus("sort: "+m.symbolsSort.String(), false)
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

// cycleSymbolBindFilter steps the bind filter off → global → weak → local → off
// (global is the usual "exported symbols" lens when combined with scope:internal).
func (m *Model) cycleSymbolBindFilter() {
	order := []binfile.SymBind{binfile.BindGlobal, binfile.BindWeak, binfile.BindLocal}
	if !m.symbolsBindOn {
		m.symbolsBindOn = true
		m.symbolsBind = order[0]
		m.setStatus("symbol bind filter: "+bindString(m.symbolsBind), false)
		return
	}
	for i, b := range order {
		if b == m.symbolsBind {
			if i == len(order)-1 {
				m.symbolsBindOn = false
				m.setStatus("symbol bind filter: all", false)
				return
			}
			m.symbolsBind = order[i+1]
			m.setStatus("symbol bind filter: "+bindString(m.symbolsBind), false)
			return
		}
	}
	m.symbolsBindOn = false
}

// canDisasmAt reports whether addr can actually be disassembled: there is a
// decoder for this architecture and the address lives in executable code. When
// false (an unsupported CPU, or an address outside any mapped exec section),
// callers should fall back to the hex view rather than the disasm view.
func (m *Model) canDisasmAt(addr uint64) bool {
	if m.dis == nil {
		return false
	}
	_, ok := m.file.ExecImage().PosForAddr(addr)
	return ok
}

// openSymbol opens a symbol in the most appropriate view. The hex and disasm
// views span the whole binary now, so this only chooses which view to land in
// and seeks the cursor onto the symbol's address:
//   - FUNC                  → disasm
//   - OBJECT/TLS/COMMON     → hex (virtual-address) view, cursor on the symbol
//   - SECTION               → exec ⇒ disasm; else hex/raw at the section
//   - NOTYPE                → exec section ⇒ disasm; else hex; else raw
//
// Anything that would land in disasm falls back to hex when disassembly isn't
// possible (no decoder for this CPU, or the address isn't in executable code).
func (m *Model) openSymbol(sym binfile.Symbol) {
	wantDisasm := false
	switch sym.Kind {
	case binfile.SymFunc:
		wantDisasm = true
	case binfile.SymObject, binfile.SymTLS, binfile.SymCommon:
		wantDisasm = false
	default:
		if sec := m.file.SectionAt(sym.Addr); sec != nil && binfile.IsExecSection(sec) {
			wantDisasm = true
		}
	}
	if wantDisasm && m.canDisasmAt(sym.Addr) {
		m.loadDisasmAt(sym.Addr)
	} else {
		m.openHexAt(sym.Addr)
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
		facets := []string{"type:" + kind, "scope:" + m.symbolsScope.String()}
		if m.symbolsBindOn {
			facets = append(facets, "bind:"+bindString(m.symbolsBind))
		}
		if m.symbolsSort != sortByName {
			facets = append(facets, "sort:"+m.symbolsSort.String())
		}
		if m.symbolsLib != "" {
			facets = append(facets, "lib:"+m.symbolsLib+" (Esc clears)")
		}
		filterRow = m.theme.footerStyle.Render(fmt.Sprintf("/ %s   %s   (%d / %d)",
			m.symbolsFilter.Value(), strings.Join(facets, "  "), len(m.symbolsFiltered), len(m.file.Symbols)))
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
				row = m.theme.tableSelStyle.Render(ansi.Strip(row))
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
	key := rowCacheKey{i, m.width, m.file.AddrHexWidth(), m.wrap}
	if m.symbolHeightCache != nil {
		if h, ok := m.symbolHeightCache[key]; ok {
			return h
		}
	}
	h := len(m.symbolRows(i, m.file.AddrHexWidth()))
	if m.symbolHeightCache == nil {
		m.symbolHeightCache = make(map[rowCacheKey]int)
	}
	m.symbolHeightCache[key] = h
	return h
}

func (m *Model) symbolRows(i, addrW int) []string {
	s := m.file.Symbols[m.symbolsFiltered[i]]

	key := rowCacheKey{i, m.width, addrW, m.wrap}
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
		m.symbolRowCache = make(map[rowCacheKey][]string)
	}
	m.symbolRowCache[key] = rows
	return rows
}
