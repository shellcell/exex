package ui

// Shared interaction helpers used by the list-style views (sections, symbols,
// strings, libs) so cursor movement, the wrap toggle, and filter-input capture
// live in one place instead of being copy-pasted per view.

import (
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
)

// listPage is the page size (in items) for the current list view's pgup/pgdown,
// as measured at the last render. It advances by one screenful minus one item so
// a row of context carries over between pages. Falls back to a sane estimate
// before the first render has recorded a value.
func (m *Model) listPage() int {
	if m.pageRows > 1 {
		return m.pageRows - 1 // keep one item of context
	}
	if m.pageRows == 1 {
		return 1
	}
	return max(1, m.bodyHeight()-3)
}

// toggleWrap flips the global long-line wrap and reports it in the footer.
func (m *Model) toggleWrap() {
	m.wrap = !m.wrap
	m.clearAllViewCaches()
	m.setStatus(wrapStatus(m.wrap), false)
}

// filterCapture feeds a keystroke to a focused filter input. It returns
// (cmd, true) when the key was consumed by the input (typing, or esc/enter to
// blur) and (nil, false) when the caller should keep handling the key — either
// the input isn't focused, or it's a navigation key that should drive the list
// while the filter stays focused.
func filterCapture(in *textinput.Model, key string, msg tea.KeyMsg, recompute func()) (tea.Cmd, bool) {
	if !in.Focused() {
		return nil, false
	}
	switch key {
	case "esc":
		// Esc falls through to the view's own esc handler, which clears the search
		// text *and* every column filter in one press (doc #27). It blurs the input
		// there too.
		return nil, false
	case "enter":
		in.Blur()
		return nil, true
	case "up", "down", "pgup", "pgdown", "home", "end":
		return nil, false // navigation falls through to the view handler
	}
	var cmd tea.Cmd
	before := in.Value()
	*in, cmd = in.Update(msg)
	if in.Value() != before {
		recompute()
	}
	return cmd, true
}
