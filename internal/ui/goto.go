package ui

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/rabarbra/exex/internal/binfile"
)

// gotoTarget is one selectable entry in the goto modal: either a symbol or a
// bare parsed address.
type gotoTarget struct {
	label string
	addr  uint64
	sym   binfile.Symbol
	isSym bool
}

// gotoMaxResults bounds how many matches we keep (the list scrolls; the visible
// window is sized to the terminal height in renderGotoModal).
const gotoMaxResults = 500

// recomputeGoto rebuilds the modal's result list from the current input. A
// parseable address is always offered first; symbols are matched (raw name and
// demangled name) and ranked exact → prefix → substring.
func (m *Model) recomputeGoto() {
	m.gotoResults = m.gotoResults[:0]
	m.gotoSel = 0
	m.gotoTop = 0
	val := strings.TrimSpace(m.gotoInput.Value())
	if val == "" {
		return
	}
	if a, err := parseAddr(val); err == nil {
		m.gotoResults = append(m.gotoResults, gotoTarget{label: "address", addr: a})
	}

	needle := strings.ToLower(val)
	lowerName, lowerDem := m.file.LowerNames()
	type ranked struct {
		t    gotoTarget
		rank int
	}
	var matches []ranked
	for i := range m.file.Symbols {
		s := m.file.Symbols[i]
		if s.Addr == 0 {
			continue
		}
		name, dem := lowerName[i], lowerDem[i]
		hit := strings.Contains(name, needle) || (dem != "" && strings.Contains(dem, needle))
		if !hit {
			continue
		}
		rank := 2
		switch {
		case name == needle || dem == needle:
			rank = 0
		case strings.HasPrefix(name, needle) || strings.HasPrefix(dem, needle):
			rank = 1
		}
		matches = append(matches, ranked{gotoTarget{label: s.Display(), addr: s.Addr, sym: s, isSym: true}, rank})
	}
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].rank != matches[j].rank {
			return matches[i].rank < matches[j].rank
		}
		return matches[i].t.label < matches[j].t.label
	})
	for _, mt := range matches {
		if len(m.gotoResults) >= gotoMaxResults {
			break
		}
		m.gotoResults = append(m.gotoResults, mt.t)
	}
}

// activateGoto acts on the highlighted result, falling back to a bare address
// parse when there are no results.
func (m *Model) activateGoto() {
	addr, ok := m.gotoSelectionAddr()
	if !ok {
		m.setStatus("nothing to go to", true)
		return
	}
	// In the Sources view, goto navigates by source: resolve the target to its
	// source file:line and open it there.
	if m.mode == modeSources {
		m.openSourceForAddr(addr)
		return
	}
	if m.gotoSel >= 0 && m.gotoSel < len(m.gotoResults) && m.gotoResults[m.gotoSel].isSym {
		m.openSymbol(m.gotoResults[m.gotoSel].sym)
		return
	}
	m.gotoAddr(addr)
}

// gotoSelectionAddr returns the address of the highlighted result, falling back
// to a bare address typed into the prompt.
func (m *Model) gotoSelectionAddr() (uint64, bool) {
	if m.gotoSel >= 0 && m.gotoSel < len(m.gotoResults) {
		t := m.gotoResults[m.gotoSel]
		if t.isSym {
			return t.sym.Addr, true
		}
		return t.addr, true
	}
	if a, err := parseAddr(strings.TrimSpace(m.gotoInput.Value())); err == nil {
		return a, true
	}
	return 0, false
}

// openSourceForAddr opens the Sources view at the source location that addr
// maps to.
func (m *Model) openSourceForAddr(addr uint64) {
	file, line := m.file.LookupAddr(addr)
	if file == "" {
		m.setStatus(fmt.Sprintf("no source mapping for 0x%x", addr), true)
		return
	}
	m.ensureSources()
	m.openSourceFile(file, line)
}

// closeGoto dismisses the goto modal and resets its transient state.
func (m *Model) closeGoto() {
	m.gotoActive = false
	m.gotoInput.Blur()
	m.gotoInput.SetValue("")
	m.gotoResults = m.gotoResults[:0]
	m.gotoSel = 0
	m.gotoTop = 0
}

// gotoTargetString navigates to a startup goto argument: an explicit address
// (0x… or a hex/decimal literal), or a symbol by name (raw or demangled). A
// single match jumps straight to it; several matches open the Symbols view with
// the query pre-applied as a filter so the user can pick. Reports via the status
// line when nothing matches.
func (m *Model) gotoTargetString(s string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return
	}
	// A 0x-prefixed value is unambiguously an address.
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		if a, err := parseAddr(s); err == nil {
			m.gotoAddr(a)
			return
		}
	}
	// Resolve against the symbol table (names beat numbers like "main").
	best, count, exact, exactN := m.resolveSymbolGoto(s)
	switch {
	case exactN == 1:
		// A unique exact name is unambiguous even amid substring matches.
		m.openSymbol(exact)
		return
	case count == 1:
		m.openSymbol(best)
		return
	case count > 1:
		m.openSymbolsFiltered(s)
		return
	}
	// No symbol matched: fall back to a bare address parse.
	if a, err := parseAddr(s); err == nil {
		m.gotoAddr(a)
		return
	}
	m.setStatus(fmt.Sprintf("goto %q: no matching symbol or address", s), true)
}

// resolveSymbolGoto scans the symbol table for needle (raw or demangled name),
// returning the best-ranked match (exact → prefix → substring), the total number
// of matches, and the unique exact match when there is exactly one.
func (m *Model) resolveSymbolGoto(s string) (best binfile.Symbol, count int, exact binfile.Symbol, exactN int) {
	needle := strings.ToLower(s)
	lowerName, lowerDem := m.file.LowerNames()
	bestRank := 99
	for i := range m.file.Symbols {
		sym := m.file.Symbols[i]
		if sym.Addr == 0 {
			continue
		}
		name, dem := lowerName[i], lowerDem[i]
		isExact := name == needle || dem == needle
		if !isExact && !strings.Contains(name, needle) && (dem == "" || !strings.Contains(dem, needle)) {
			continue
		}
		count++
		if isExact {
			exact, exactN = sym, exactN+1
		}
		rank := 2
		switch {
		case isExact:
			rank = 0
		case strings.HasPrefix(name, needle) || (dem != "" && strings.HasPrefix(dem, needle)):
			rank = 1
		}
		if rank < bestRank {
			bestRank, best = rank, sym
		}
	}
	return best, count, exact, exactN
}

// openSymbolsFiltered shows the Symbols view with q applied as the live filter.
func (m *Model) openSymbolsFiltered(q string) {
	m.symbolsFilter.SetValue(q)
	m.recomputeSymbols()
	m.symbolsCur = 0
	m.symbolsTop = 0
	m.viewportDetached = false
	m.setMode(modeSymbols)
	m.setStatus(fmt.Sprintf("%d symbols match %q", len(m.symbolsFiltered), q), false)
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
	m.openRawAt(addr)
	m.setStatus(fmt.Sprintf("0x%x is not mapped; showing raw offset", addr), false)
}

// parseAddr parses decimal addresses unless a 0x prefix or hex digit is present.
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
