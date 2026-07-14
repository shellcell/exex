package ui

// The shell half of the "Jump to" command palette (internal/ui/modals/palette),
// plus the address/symbol navigation the rest of the app calls.
//
// Searching needs the symbol table, the demangled-name index, the section list
// and the string corpus; routing a result to a view needs to know what the views
// are. Both stay here. The overlay owns the prompt, the scope selector and the
// result list.

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/shellcell/exex/internal/binfile"
	"github.com/shellcell/exex/internal/ui/layout"
	palettemodal "github.com/shellcell/exex/internal/ui/modals/palette"
	"github.com/shellcell/exex/internal/ui/scope"
	"github.com/shellcell/exex/internal/ui/views/strs"
)

// gotoMaxResults bounds how many matches we keep (the list scrolls; the visible
// window is sized to the terminal height in renderGotoModal).
const gotoMaxResults = 500

// Search builds the palette's result list. Each scope searches its corpus; "all"
// spans symbols + sections and offers a parseable address. Strings/libraries are
// their own scopes (the string corpus is large enough that scanning it on every
// keystroke must be opt-in). It satisfies palette.Host.
func (m *Model) Search(val string, sc scope.Scope, phys bool) []palettemodal.Target {
	if val == "" {
		return nil
	}
	needle := strings.ToLower(val)
	var out []palettemodal.Target

	if sc == scope.All || sc == scope.Addr {
		out = m.appendAddrTarget(out, val, phys)
	}
	if sc == scope.All || sc == scope.Symbols {
		out = m.appendSymbolMatches(out, needle)
	}
	if sc == scope.All || sc == scope.Sections {
		out = m.appendSectionMatches(out, needle)
	}
	if sc == scope.Strings {
		out = m.appendStringMatches(out, needle)
	}
	if sc == scope.Libs {
		out = m.appendLibMatches(out, needle)
	}
	return out
}

// HasPhysAddrs satisfies palette.Host.
func (m *Model) HasPhysAddrs() bool { return m.file.HasPhysAddrs() }

// appendAddrTarget offers a parseable address, resolving a physical address to
// its virtual one when physical mode is on.
func (m *Model) appendAddrTarget(out []palettemodal.Target, val string, phys bool) []palettemodal.Target {
	a, err := parseAddr(val)
	if err != nil {
		return out
	}
	label := "address  0x" + strconv.FormatUint(a, 16)
	if phys {
		v, ok := m.file.PhysToVirtual(a)
		if !ok {
			return out // physical address not in any section's load range
		}
		label = fmt.Sprintf("physical 0x%x → virtual 0x%x", a, v)
		a = v
	}
	return append(out, palettemodal.Target{Kind: palettemodal.KindAddr, Label: label, Addr: a, HasAddr: true})
}

// appendSymbolMatches ranks symbols (raw + demangled name) exact → prefix →
// substring and appends bounded buckets. The palette never shows more than
// gotoMaxResults entries, so keep at most that many per rank instead of
// collecting/sorting every match on large symbol tables for every keystroke.
func (m *Model) appendSymbolMatches(out []palettemodal.Target, needle string) []palettemodal.Target {
	remain := gotoMaxResults - len(out)
	if remain <= 0 {
		return out
	}
	lowerName, lowerDem := m.file.LowerNames()
	var exact, prefix, substr []palettemodal.Target
	add := func(dst *[]palettemodal.Target, t palettemodal.Target) {
		if len(*dst) < remain {
			*dst = append(*dst, t)
		}
	}
	for i := range m.file.Symbols {
		s := m.file.Symbols[i]
		if s.Addr == 0 {
			continue
		}
		name, dem := lowerName[i], lowerDem[i]
		if !strings.Contains(name, needle) && (dem == "" || !strings.Contains(dem, needle)) {
			continue
		}
		t := palettemodal.Target{Kind: palettemodal.KindSymbol, Label: s.Display(), Addr: s.Addr, Sym: s, HasAddr: true}
		switch {
		case name == needle || dem == needle:
			add(&exact, t)
			if len(exact) >= remain {
				goto flush
			}
		case strings.HasPrefix(name, needle) || strings.HasPrefix(dem, needle):
			add(&prefix, t)
		default:
			add(&substr, t)
		}
	}
flush:
	for _, bucket := range [][]palettemodal.Target{exact, prefix, substr} {
		for _, t := range bucket {
			if len(out) >= gotoMaxResults {
				return out
			}
			out = append(out, t)
		}
	}
	return out
}

// appendSectionMatches matches section names.
func (m *Model) appendSectionMatches(out []palettemodal.Target, needle string) []palettemodal.Target {
	for i := range m.file.Sections {
		s := m.file.Sections[i]
		if s.Size == 0 || !layout.ContainsFold(s.Name, needle) {
			continue
		}
		out = append(out, palettemodal.Target{
			Kind: palettemodal.KindSection, Label: s.Name, Addr: s.Addr, Off: s.Offset, HasAddr: s.Addr != 0,
		})
		if len(out) >= gotoMaxResults {
			return out
		}
	}
	return out
}

// appendStringMatches matches printable strings (zero-copy over the file image).
func (m *Model) appendStringMatches(out []palettemodal.Target, needle string) []palettemodal.Target {
	for _, e := range m.file.Strings() {
		if !layout.ContainsFoldBytes(m.file.StringBytes(e), needle) {
			continue
		}
		out = append(out, palettemodal.Target{
			Kind: palettemodal.KindString, Label: strs.Sanitize(m.file.StringText(e)), Addr: e.Addr, Off: e.Offset, HasAddr: e.HasAddr,
		})
		if len(out) >= gotoMaxResults {
			return out
		}
	}
	return out
}

// appendLibMatches matches linked-library names.
func (m *Model) appendLibMatches(out []palettemodal.Target, needle string) []palettemodal.Target {
	if m.file.Info == nil {
		return out
	}
	for _, lib := range m.file.Info.DynamicLibs {
		if layout.ContainsFold(lib, needle) {
			out = append(out, palettemodal.Target{Kind: palettemodal.KindLib, Label: lib})
		}
		if len(out) >= gotoMaxResults {
			return out
		}
	}
	return out
}

// Activate acts on the highlighted result, routing it to the natural view for its
// kind; with no results it falls back to a bare address parse. It satisfies
// palette.Host.
func (m *Model) Activate(t palettemodal.Target, hasSel bool, typed string) {
	if !hasSel {
		if a, err := parseAddr(typed); err == nil {
			m.gotoAddr(a)
		} else {
			m.setStatus("nothing to go to", true)
		}
		return
	}
	// In the Sources view, an address/symbol target navigates by source line.
	if m.mode == modeSources && (t.Kind == palettemodal.KindAddr || t.Kind == palettemodal.KindSymbol) {
		m.openSourceForAddr(t.Addr)
		return
	}
	switch t.Kind {
	case palettemodal.KindSymbol:
		m.openSymbol(t.Sym)
	case palettemodal.KindSection, palettemodal.KindString:
		if t.HasAddr {
			m.gotoAddr(t.Addr)
		} else {
			m.openRawAt(t.Off)
		}
	case palettemodal.KindLib:
		m.openLibsFiltered(t.Label)
	default:
		m.gotoAddr(t.Addr)
	}
}

// openLibsFiltered shows the Libraries view filtered to lib (where the user can
// open it as primary).
func (m *Model) openLibsFiltered(lib string) {
	m.libs.Filter.SetValue(lib)
	m.setMode(modeLibs)
	m.setStatus("library: "+lib+"  (press o to open it)", false)
}

// openSourceForAddr opens the Sources view at the source location that addr
// maps to.
func (m *Model) openSourceForAddr(addr uint64) {
	file, line := m.file.LookupAddr(addr)
	if file == "" {
		m.setStatus(fmt.Sprintf("no source mapping for 0x%x", addr), true)
		return
	}
	m.sources.Ensure(m.viewContext())
	m.openSourceFileInDisasm(file, line)
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
	m.symbols.Filter.SetValue(q)
	m.symbols.Recompute(m.viewContext())
	m.symbols.Cur = 0
	m.symbols.Top = 0
	m.viewportDetached = false
	m.setMode(modeSymbols)
	m.setStatus(fmt.Sprintf("%d symbols match %q", len(m.symbols.Filtered), q), false)
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
