package layout

// List/table interaction primitives shared by the views: page-size measurement,
// standard cursor navigation, case-insensitive substring filtering, facet
// cycling, and a bounded per-row render memo. All Model-independent, so a view
// package can build a filterable, scrollable table without importing ui.

// PageStep returns how many list items make up one screen "page": the number of
// items whose stacked rendered heights fill visibleLines, starting at item from
// (the current top of the viewport), clamped to at least 1. rowHeight gives each
// item's line count (1 for single-line rows). Paging by this many items advances
// the view by about one screen instead of overshooting when rows carry chrome
// (header/filter lines reduce visibleLines) or wrap onto multiple lines.
func PageStep(from, n, visibleLines int, rowHeight func(int) int) int {
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

// NavKey applies a standard list-navigation key (up/down/k/j, pgup/pgdown,
// home/end/G) to a cursor over n items, paging by page rows. It returns true
// when it consumed the key (so the caller can stop), and always leaves the
// cursor in [0, n-1] — or 0 for an empty list. `[`/`]` page up/down here too:
// only the list views route through NavKey (disasm/hex/source-open handle those
// keys themselves), so paging with them is free in exactly the list views.
func NavKey(cur *int, n, page int, key string) bool {
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

// ContainsFold reports whether s contains substr, ASCII case-insensitively,
// without the allocation that strings.Contains(strings.ToLower(s), substr) costs
// per call. The list filters run this over every row on every keystroke, so the
// allocation matters on large tables (the Strings/Symbols views). substr is
// expected already-lowercased by the caller; non-ASCII bytes compare exactly,
// which is fine for the identifier/path/section text these filters match.
func ContainsFold(s, substr string) bool {
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

// ContainsFoldBytes is ContainsFold over a byte slice (substr already lowercased),
// so the strings filter can scan zero-copy slices into the file image without
// allocating a string per entry.
func ContainsFoldBytes(b []byte, substr string) bool {
	if substr == "" {
		return true
	}
	for i := 0; i+len(substr) <= len(b); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			c := b[i+j]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != substr[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// CycleStringList advances a facet filter through list: off → first → … → last →
// off. *on tracks whether the filter is active, *cur its current value.
func CycleStringList(on *bool, cur *string, list []string) {
	if len(list) == 0 {
		return
	}
	if !*on {
		*on, *cur = true, list[0]
		return
	}
	for i, v := range list {
		if v == *cur {
			if i == len(list)-1 {
				*on, *cur = false, ""
			} else {
				*cur = list[i+1]
			}
			return
		}
	}
	*on, *cur = true, list[0]
}

// RowMemoCap bounds each RowMemo so a long scroll through a huge table (millions
// of symbol/string rows) can't grow the cache for the whole session. When full
// the memo is flushed wholesale — cheaper than per-entry eviction, and the
// visible window repopulates in one render pass.
const RowMemoCap = 4096

// RowMemo is a lazily-allocated, bounded memo cache for rendered rows (or their
// heights), keyed by K. It centralises the "nil-check → lookup → build → store"
// pattern the list/disasm renderers would otherwise repeat by hand. The zero
// value (nil map) is ready to use.
type RowMemo[K comparable, V any] map[K]V

// Get returns the cached value for key, building and caching it on a miss.
func (m *RowMemo[K, V]) Get(key K, build func() V) V {
	if *m == nil {
		*m = make(RowMemo[K, V])
	} else if v, ok := (*m)[key]; ok {
		return v
	}
	if len(*m) >= RowMemoCap {
		clear(*m)
	}
	v := build()
	(*m)[key] = v
	return v
}

// ReverseInts reverses s in place — the cheap path for flipping a list already
// in its natural ascending order to descending.
func ReverseInts(s []int) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}
