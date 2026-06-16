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

// gotoMaxResults bounds how many matches we keep (the list scrolls);
// gotoVisible is how many rows the modal shows at once.
const (
	gotoMaxResults = 500
	gotoVisible    = 10
)

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
	type ranked struct {
		t    gotoTarget
		rank int
	}
	var matches []ranked
	for _, s := range m.file.Symbols {
		if s.Addr == 0 {
			continue
		}
		name, dem := strings.ToLower(s.Name), strings.ToLower(s.Demangled)
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

func (m *Model) closeGoto() {
	m.gotoActive = false
	m.gotoInput.Blur()
	m.gotoInput.SetValue("")
	m.gotoResults = m.gotoResults[:0]
	m.gotoSel = 0
	m.gotoTop = 0
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
