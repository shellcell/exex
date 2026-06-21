package ui

// Shared interaction helpers used by the list-style views (sections, symbols,
// strings, libs) so cursor movement, the wrap toggle, and filter-input capture
// live in one place instead of being copy-pasted per view.

import (
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
)

// pageStep returns how many list items make up one screen "page": the number of
// items whose stacked rendered heights fill visibleLines, starting at item from
// (the current top of the viewport), clamped to at least 1. rowHeight gives each
// item's line count (1 for single-line rows). Paging by this many items advances
// the view by about one screen instead of overshooting when rows carry chrome
// (header/filter lines reduce visibleLines) or wrap onto multiple lines.
func pageStep(from, n, visibleLines int, rowHeight func(int) int) int {
	if visibleLines < 1 {
		visibleLines = 1
	}
	used, count := 0, 0
	for i := from; i < n; i++ {
		h := rowHeight(i)
		if h < 1 {
			h = 1
		}
		if count > 0 && used+h > visibleLines {
			break
		}
		used += h
		count++
		if used >= visibleLines {
			break
		}
	}
	if count < 1 {
		count = 1
	}
	return count
}

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

// navKey applies a standard list-navigation key (up/down/k/j, pgup/pgdown,
// home/end/G) to a cursor over n items, paging by page rows. It returns true
// when it consumed the key (so the caller can stop), and always leaves the
// cursor in [0, n-1] — or 0 for an empty list. `[`/`]` page up/down here too:
// only the list views route through navKey (disasm/hex/source-open handle those
// keys themselves), so paging with them is free in exactly the list views.
func navKey(cur *int, n, page int, key string) bool {
	switch key {
	case "up", "k":
		*cur--
	case "down", "j":
		*cur++
	case "pgup", "[":
		*cur -= page
	case "pgdown", "]":
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

// containsFold reports whether s contains substr, ASCII case-insensitively,
// without the allocation that strings.Contains(strings.ToLower(s), substr) costs
// per call. The list filters run this over every row on every keystroke, so the
// allocation matters on large tables (the Strings/Symbols views). substr is
// expected already-lowercased by the caller; non-ASCII bytes compare exactly,
// which is fine for the identifier/path/section text these filters match.
func containsFold(s, substr string) bool {
	if substr == "" {
		return true
	}
	for i := 0; i+len(substr) <= len(s); i++ {
		if hasFoldPrefixLower(s[i:], substr) {
			return true
		}
	}
	return false
}

// hasFoldPrefixLower reports whether s starts with prefix, where prefix is
// already lowercased and s is folded to lower as it is compared.
func hasFoldPrefixLower(s, prefix string) bool {
	for i := 0; i < len(prefix); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != prefix[i] {
			return false
		}
	}
	return true
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
		// Esc clears the filter (and unfocuses), so the list returns to showing
		// everything; Enter just confirms the current filter and unfocuses.
		in.SetValue("")
		in.Blur()
		recompute()
		return nil, true
	case "enter":
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
