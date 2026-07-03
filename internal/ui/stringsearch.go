package ui

// openStringSearch implements the -s CLI flag: it filters the printable strings
// by s and either jumps to the single match (Hex if mapped, else Raw) or opens
// the Strings view with the filter applied when several match. It needs the
// shell's mode switching, so it lives here; the list itself is
// internal/ui/views/strs.

import (
	"fmt"
	"strings"
)

func (m *Model) openStringSearch(s string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return
	}
	ctx := m.viewContext()
	m.strs.Ensure(ctx)
	m.strs.Filter.SetValue(s)
	m.strs.Recompute(ctx)
	m.strs.Cur, m.strs.Top = 0, 0
	switch len(m.strs.Filtered) {
	case 0:
		m.setMode(modeStrings)
		m.setStatus(fmt.Sprintf("no strings match %q", s), true)
	case 1:
		e := m.strs.List[m.strs.Filtered[0]]
		if e.HasAddr {
			m.openHexAt(e.Addr)
		} else {
			m.openRawAt(e.Offset)
		}
		m.setStatus(fmt.Sprintf("string %q", s), false)
	default:
		m.setMode(modeStrings)
		m.setStatus(fmt.Sprintf("%d strings match %q", len(m.strs.Filtered), s), false)
	}
}
