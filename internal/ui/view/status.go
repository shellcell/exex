package view

// The status line: the row above a table showing the filter, how many rows are
// shown, and the view's toggles. Every view builds it through StatusLine so the
// grammar, colours, spacing and order are the same everywhere:
//
//	/ <filter>   <noun> (<shown> / <total>)   <key> <label>:<value>   …
//
// The chips run in the house order — the view toggle (t), then sort (s), then
// the Ctrl-chord facets — and a view simply omits what it does not have.
//
// A chip carries the *key token* that drives it ("t", "ctrl+s"), so clicking one
// is just that key arriving by mouse: the view hands the token back to its own
// Update. No view needs a second, parallel implementation of what its keys do —
// which is what let the Symbols chips drift away from the rest.

import (
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"
)

// StatusItem is one "<key> <label>:<value>" chip.
type StatusItem struct {
	Key   string // the key token that toggles it ("t", "s", "ctrl+t")
	Label string // what it controls ("view", "sort", "type")
	Value string // its current setting ("flat", "name↑", "all")
}

// StatusChip is a rendered chip: the key token it dispatches and the screen
// columns [Start, End) it occupies.
type StatusChip struct {
	Key        string
	Start, End int
}

// ChipAt returns the key token of the chip at screen column x.
func ChipAt(chips []StatusChip, x int) (string, bool) {
	for _, c := range chips {
		if x >= c.Start && x < c.End {
			return c.Key, true
		}
	}
	return "", false
}

// KeyGlyph is a key token's compact label: "ctrl+t" → "^t", "shift+h" → "⇧H".
func KeyGlyph(key string) string {
	if rest, ok := strings.CutPrefix(key, "ctrl+"); ok {
		return "^" + rest
	}
	if rest, ok := strings.CutPrefix(key, "shift+"); ok {
		return "⇧" + strings.ToUpper(rest)
	}
	return key
}

// SortValue renders a sort chip's value: the sort key with the direction arrow,
// so every view spells its sort the same way.
func SortValue(name string, desc bool) string {
	if desc {
		return name + "↓"
	}
	return name + "↑"
}

// OnOff renders a boolean toggle's value.
func OnOff(on bool) string {
	if on {
		return "on"
	}
	return "off"
}

// StatusCache memoises a rendered status line. The row is rebuilt on every
// frame but only *changes* when the view's state does, and styling it chip by
// chip means a dozen lipgloss renders — each one re-serialising a colour into
// ANSI. Views keep one of these and hand it to StatusLine.
//
// It keys on the *Styles pointer, which the shell replaces whenever the theme
// or a display setting changes, so a restyle can never serve a stale line.
type StatusCache struct {
	styles       *Styles
	width        int
	filterValue  string
	noun         string
	shown, total int
	items        []StatusItem

	line  string
	chips []StatusChip
}

// fresh reports whether the cached line still matches these inputs.
func (sc *StatusCache) fresh(c Context, filterValue, noun string, shown, total int, items []StatusItem) bool {
	if sc.line == "" || sc.styles != c.Styles || sc.width != c.Width ||
		sc.filterValue != filterValue || sc.noun != noun ||
		sc.shown != shown || sc.total != total || len(sc.items) != len(items) {
		return false
	}
	for i := range items {
		if sc.items[i] != items[i] {
			return false
		}
	}
	return true
}

// StatusLine renders the status row and the chips' column spans, reusing the
// last render when nothing it depends on has changed. noun is the plural row
// name ("sections", "symbols"); pass "" for a bare count.
//
// Fragments are rendered with the padding stripped from FooterStyle: it carries
// the footer's left/right padding, and rendering a row fragment-by-fragment
// would otherwise add that padding to every fragment — which is what made the
// gaps between chips drift apart from view to view.
func (c Context) StatusLine(cache *StatusCache, filterValue, noun string, shown, total int, items []StatusItem) (string, []StatusChip) {
	if cache != nil && cache.fresh(c, filterValue, noun, shown, total, items) {
		return cache.line, cache.chips
	}
	line, chips := c.renderStatusLine(filterValue, noun, shown, total, items)
	if cache != nil {
		*cache = StatusCache{
			styles: c.Styles, width: c.Width,
			filterValue: filterValue, noun: noun, shown: shown, total: total,
			items: append(cache.items[:0], items...),
			line:  line, chips: chips,
		}
	}
	return line, chips
}

func (c Context) renderStatusLine(filterValue, noun string, shown, total int, items []StatusItem) (string, []StatusChip) {
	muted := c.FooterStyle.Padding(0)

	var b strings.Builder
	col := 0
	write := func(s string) {
		b.WriteString(s)
		col += lipgloss.Width(s)
	}

	write(muted.Render("/ " + filterValue + "   "))
	if noun != "" {
		write(muted.Render(fmt.Sprintf("%s (%d / %d)", noun, shown, total)))
	} else {
		write(muted.Render(fmt.Sprintf("(%d / %d)", shown, total)))
	}

	chips := make([]StatusChip, 0, len(items))
	for _, it := range items {
		// Drop whole chips (with an ellipsis) rather than let the row's hard
		// truncation cut one in half — a half-rendered chip is both unreadable and
		// clickable at the wrong columns.
		w := 3 + lipgloss.Width(KeyGlyph(it.Key)+" "+it.Label+":"+it.Value)
		if col+w > c.Width {
			if col+2 <= c.Width {
				write(muted.Render(" …"))
			}
			break
		}
		write(muted.Render("   "))
		start := col
		write(c.KeyStyle.Render(KeyGlyph(it.Key)))
		write(muted.Render(" " + it.Label + ":"))
		write(c.PlainStyle.Render(it.Value))
		chips = append(chips, StatusChip{Key: it.Key, Start: start, End: col})
	}
	return b.String(), chips
}
