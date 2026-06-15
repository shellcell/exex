package ui

// Shared interaction helpers used by the list-style views (sections, symbols,
// strings, libs) so cursor movement, the wrap toggle, and filter-input capture
// live in one place instead of being copy-pasted per view.

import (
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

// navKey applies a standard list-navigation key (up/down/k/j, pgup/pgdown,
// home/end/G) to a cursor over n items, paging by page rows. It returns true
// when it consumed the key (so the caller can stop), and always leaves the
// cursor in [0, n-1] — or 0 for an empty list.
func navKey(cur *int, n, page int, key string) bool {
	switch key {
	case "up", "k":
		*cur--
	case "down", "j":
		*cur++
	case "pgup":
		*cur -= page
	case "pgdown":
		*cur += page
	case "home":
		*cur = 0
	case "end", "G":
		*cur = n - 1
	default:
		return false
	}
	if *cur >= n {
		*cur = n - 1
	}
	if *cur < 0 {
		*cur = 0
	}
	return true
}

// toggleWrap flips the global long-line wrap and reports it in the footer.
func (m *Model) toggleWrap() {
	m.wrap = !m.wrap
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
	case "esc", "enter":
		in.Blur()
		return nil, true
	case "up", "down", "pgup", "pgdown", "home", "end":
		return nil, false // navigation falls through to the view handler
	}
	var cmd tea.Cmd
	*in, cmd = in.Update(msg)
	recompute()
	return cmd, true
}
