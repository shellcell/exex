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
	{modalHeader, func(m *Model) bool { return m.headerActive }},
	{modalHelp, func(m *Model) bool { return m.helpActive }},
	{modalCPUFeat, func(m *Model) bool { return m.cpufeatActive }},
	{modalXref, func(m *Model) bool { return m.xrefActive }},
	{modalSyscall, func(m *Model) bool { return m.syscallActive }},
	{modalJump, func(m *Model) bool { return m.jumpActive }},
	{modalFind, func(m *Model) bool { return m.findActive }},
	{modalFindQuery, func(m *Model) bool { return m.findQueryActive }},
	{modalFindResults, func(m *Model) bool { return m.findResultsActive }},
	{modalSettings, func(m *Model) bool { return m.settingsActive }},
	{modalGoto, func(m *Model) bool { return m.gotoActive }},
	{modalSearch, func(m *Model) bool { return m.searchActive }},
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
		return m.renderHeaderModal()
	case modalHelp:
		return m.renderHelpModal()
	case modalCPUFeat:
		return m.renderCPUFeatModal()
	case modalXref:
		return m.renderXrefModal()
	case modalSyscall:
		return m.renderSyscallModal()
	case modalJump:
		return m.renderJumpModal()
	case modalFind:
		return m.renderFindModal()
	case modalFindQuery:
		return m.renderFindQueryModal()
	case modalFindResults:
		return m.renderFindResultsModal()
	case modalSettings:
		return m.renderSettingsModal()
	case modalGoto:
		return m.renderGotoModal()
	case modalSearch:
		return m.renderSearchModal()
	}
	return ""
}
