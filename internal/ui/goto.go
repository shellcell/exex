package ui

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/rabarbra/exex/internal/binfile"
)

// gotoKind tags a palette result so it can be coloured and routed to the right
// view on Enter.
type gotoKind uint8

const (
	gkAddr gotoKind = iota
	gkSymbol
	gkSection
	gkString
	gkLib
)

func (k gotoKind) tag() string {
	switch k {
	case gkSymbol:
		return "sym"
	case gkSection:
		return "sec"
	case gkString:
		return "str"
	case gkLib:
		return "lib"
	default:
		return "addr"
	}
}

// gotoScope selects what the palette searches.
type gotoScope uint8

const (
	gsAll      gotoScope = iota // symbols + sections + a typed address
	gsSymbols                   // symbols only
	gsSections                  // section names
	gsStrings                   // printable strings (its own scope — the corpus is large)
	gsLibs                      // linked libraries
	gsAddr                      // a raw address (virtual, or physical when toggled)
	gsScopeCount
)

func (s gotoScope) String() string {
	switch s {
	case gsSymbols:
		return "symbols"
	case gsSections:
		return "sections"
	case gsStrings:
		return "strings"
	case gsLibs:
		return "libraries"
	case gsAddr:
		return "address"
	default:
		return "all"
	}
}

// gotoTarget is one selectable palette entry, tagged by kind for colour + routing.
type gotoTarget struct {
	kind    gotoKind
	label   string
	addr    uint64
	off     uint64 // file offset (sections / strings with no virtual address)
	sym     binfile.Symbol
	hasAddr bool
}

func (t gotoTarget) isSym() bool { return t.kind == gkSymbol }

// gotoMaxResults bounds how many matches we keep (the list scrolls; the visible
// window is sized to the terminal height in renderGotoModal).
const gotoMaxResults = 500

// recomputeGoto rebuilds the palette's result list from the current input and
// scope. Each scope searches its corpus; "all" spans symbols + sections and
// offers a parseable address. Strings/libraries are their own scopes (the string
// corpus is large enough that scanning it on every keystroke must be opt-in).
func (m *Model) recomputeGoto() {
	m.gotoResults = m.gotoResults[:0]
	m.gotoSel = 0
	m.gotoTop = 0
	val := strings.TrimSpace(m.gotoInput.Value())
	if val == "" {
		return
	}
	needle := strings.ToLower(val)
	sc := m.gotoScope

	if sc == gsAll || sc == gsAddr {
		m.appendAddrTarget(val)
	}
	if sc == gsAll || sc == gsSymbols {
		m.appendSymbolMatches(needle)
	}
	if sc == gsAll || sc == gsSections {
		m.appendSectionMatches(needle)
	}
	if sc == gsStrings {
		m.appendStringMatches(needle)
	}
	if sc == gsLibs {
		m.appendLibMatches(needle)
	}
}

// appendAddrTarget offers a parseable address, resolving a physical address to
// its virtual one when physical mode is on.
func (m *Model) appendAddrTarget(val string) {
	a, err := parseAddr(val)
	if err != nil {
		return
	}
	label := "address  0x" + strconv.FormatUint(a, 16)
	if m.gotoAddrPhys {
		v, ok := m.file.PhysToVirtual(a)
		if !ok {
			return // physical address not in any section's load range
		}
		label = fmt.Sprintf("physical 0x%x → virtual 0x%x", a, v)
		a = v
	}
	m.gotoResults = append(m.gotoResults, gotoTarget{kind: gkAddr, label: label, addr: a, hasAddr: true})
}

// appendSymbolMatches ranks symbols (raw + demangled name) exact → prefix →
// substring and appends them.
func (m *Model) appendSymbolMatches(needle string) {
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
		if !strings.Contains(name, needle) && (dem == "" || !strings.Contains(dem, needle)) {
			continue
		}
		rank := 2
		switch {
		case name == needle || dem == needle:
			rank = 0
		case strings.HasPrefix(name, needle) || strings.HasPrefix(dem, needle):
			rank = 1
		}
		matches = append(matches, ranked{gotoTarget{kind: gkSymbol, label: s.Display(), addr: s.Addr, sym: s, hasAddr: true}, rank})
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

// appendSectionMatches matches section names.
func (m *Model) appendSectionMatches(needle string) {
	for i := range m.file.Sections {
		s := m.file.Sections[i]
		if s.Size == 0 || !containsFold(s.Name, needle) {
			continue
		}
		m.gotoResults = append(m.gotoResults, gotoTarget{
			kind: gkSection, label: s.Name, addr: s.Addr, off: s.Offset, hasAddr: s.Addr != 0,
		})
		if len(m.gotoResults) >= gotoMaxResults {
			return
		}
	}
}

// appendStringMatches matches printable strings (zero-copy over the file image).
func (m *Model) appendStringMatches(needle string) {
	for _, e := range m.file.Strings() {
		if !containsFoldBytes(m.file.StringBytes(e), needle) {
			continue
		}
		m.gotoResults = append(m.gotoResults, gotoTarget{
			kind: gkString, label: sanitizeString(m.file.StringText(e)), addr: e.Addr, off: e.Offset, hasAddr: e.HasAddr,
		})
		if len(m.gotoResults) >= gotoMaxResults {
			return
		}
	}
}

// appendLibMatches matches linked-library names.
func (m *Model) appendLibMatches(needle string) {
	if m.file.Info == nil {
		return
	}
	for _, lib := range m.file.Info.DynamicLibs {
		if containsFold(lib, needle) {
			m.gotoResults = append(m.gotoResults, gotoTarget{kind: gkLib, label: lib})
		}
		if len(m.gotoResults) >= gotoMaxResults {
			return
		}
	}
}

// activateGoto acts on the highlighted result, routing it to the natural view for
// its kind; with no results it falls back to a bare address parse.
func (m *Model) activateGoto() {
	if m.gotoSel < 0 || m.gotoSel >= len(m.gotoResults) {
		if a, err := parseAddr(strings.TrimSpace(m.gotoInput.Value())); err == nil {
			m.gotoAddr(a)
		} else {
			m.setStatus("nothing to go to", true)
		}
		return
	}
	t := m.gotoResults[m.gotoSel]
	// In the Sources view, an address/symbol target navigates by source line.
	if m.mode == modeSources && (t.kind == gkAddr || t.kind == gkSymbol) {
		m.openSourceForAddr(t.addr)
		return
	}
	switch t.kind {
	case gkSymbol:
		m.openSymbol(t.sym)
	case gkSection, gkString:
		if t.hasAddr {
			m.gotoAddr(t.addr)
		} else {
			m.openRawAt(t.off)
		}
	case gkLib:
		m.openLibsFiltered(t.label)
	default:
		m.gotoAddr(t.addr)
	}
}

// openLibsFiltered shows the Libraries view filtered to lib (where the user can
// open it as primary).
func (m *Model) openLibsFiltered(lib string) {
	m.libsFilter.SetValue(lib)
	m.setMode(modeLibs)
	m.setStatus("library: "+lib+"  (press o to open it)", false)
}

// gotoSelectionAddr returns the address of the highlighted result, falling back
// to a bare address typed into the prompt.
func (m *Model) gotoSelectionAddr() (uint64, bool) {
	if m.gotoSel >= 0 && m.gotoSel < len(m.gotoResults) {
		return m.gotoResults[m.gotoSel].addr, true
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
	m.gotoScope = gsAll
	m.gotoAddrPhys = false
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
