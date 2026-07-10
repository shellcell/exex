package ui

// Overlay modal identity.
//
// Exactly one overlay is on top at a time, but which one used to be decided
// independently by the key dispatcher, the renderer, and four separate switches
// in the mouse handler — each a hand-written chain over the same nine
// `xxxActive` booleans, and they disagreed. The renderer put settings third and
// findResults eleventh; the key dispatcher had them the other way around. So a
// state with two flags set would draw one modal while typing into another, and
// nothing enforced that it couldn't happen.
//
// modalOrder below is now the only ordering in the package. activeModal resolves
// it once; render, keys, and mouse all switch on the result, so they cannot
// disagree. The ordering itself is the old key-dispatch chain, which is what
// users' keystrokes already followed.

type modalKind uint8

const (
	modalNone modalKind = iota
	modalHeader
	modalHelp
	modalCPUFeat
	modalXref
	modalSyscall
	modalJump
	modalFind
	modalFindQuery
	modalFindResults
	modalSettings
	modalGoto
	modalSearch
)

// modalOrder is the single priority ordering over the overlay flags, highest
// first. Adding a modal means adding one row here and one arm to each switch
// that cares — the compiler will not remind you, but the orderings can no longer
// drift apart.
var modalOrder = [...]struct {
	kind   modalKind
	active func(*Model) bool
}{
	{modalHeader, func(m *Model) bool { return m.header.Active() }},
	{modalHelp, func(m *Model) bool { return m.help.Active() }},
	{modalCPUFeat, func(m *Model) bool { return m.cpufeat.Active() }},
	{modalXref, func(m *Model) bool { return m.xref.Active() }},
	{modalSyscall, func(m *Model) bool { return m.syscalls.Active() }},
	{modalJump, func(m *Model) bool { return m.jump.Active() }},
	{modalFind, func(m *Model) bool { return m.find.Active() }},
	{modalFindQuery, func(m *Model) bool { return m.findQueryModal.Active() }},
	{modalFindResults, func(m *Model) bool { return m.findResults.Active() }},
	{modalSettings, func(m *Model) bool { return m.settings.Active() }},
	{modalGoto, func(m *Model) bool { return m.palette.Active() }},
	{modalSearch, func(m *Model) bool { return m.search.Active() }},
}

// activeModal returns the overlay currently on top, or modalNone.
func (m *Model) activeModal() modalKind {
	for _, e := range modalOrder {
		if e.active(m) {
			return e.kind
		}
	}
	return modalNone
}

// renderActiveModal renders the overlay on top, or "" when none is open. Both
// View and the mouse hit-test use it — the hit-test needs the rendered box to
// recover its centred geometry, and rendering it the same way is what keeps the
// clickable rows aligned with the drawn ones.
func (m *Model) renderActiveModal() string {
	switch m.activeModal() {
	case modalHeader:
		return m.header.Render(m.modalContext())
	case modalHelp:
		return m.help.Render(m.modalContext())
	case modalCPUFeat:
		// Migrated modals record their own list row while rendering; the mouse
		// hit-test reads it back through the shell's modalListRow.
		out := m.cpufeat.Render(m.modalContext())
		m.modalListRow = m.cpufeat.ListRow()
		return out
	case modalXref:
		out := m.xref.Render(m.modalContext())
		m.modalListRow = m.xref.ListRow()
		return out
	case modalSyscall:
		out := m.syscalls.Render(m.modalContext())
		m.modalListRow = m.syscalls.ListRow()
		return out
	case modalJump:
		out := m.jump.Render(m.modalContext())
		m.modalListRow = m.jump.ListRow()
		return out
	case modalFind:
		out := m.find.Render(m.modalContext())
		m.modalListRow = m.find.ListRow()
		return out
	case modalFindQuery:
		return m.findQueryModal.Render(m.modalContext())
	case modalFindResults:
		out := m.findResults.Render(m.modalContext())
		m.modalListRow = m.findResults.ListRow()
		return out
	case modalSettings:
		out := m.settings.Render(m.modalContext(), m)
		m.modalListRow = m.settings.ListRow()
		return out
	case modalGoto:
		out := m.palette.Render(m.modalContext(), m)
		m.modalListRow = m.palette.ListRow()
		return out
	case modalSearch:
		return m.search.Render(m.modalContext(), m)
	}
	return ""
}
