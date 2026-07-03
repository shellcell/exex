package layout

import (
	"strings"

	"charm.land/lipgloss/v2"
)

// Sort-header primitives shared by the table views: labelling the active sort
// column with a direction triangle, mapping a click x-position to a column, and
// the htop-style "click to sort / click again to reverse" toggle. All generic and
// Model-independent, so any view (in ui or its own package) sorts a table the
// same way.

// SortableHeaderCol is the clickable x-range [start,end) of one sortable column,
// tagged with the sort key it selects.
type SortableHeaderCol[T comparable] struct {
	Start, End int
	Sort       T
}

// SortHeaderLabel returns label with a direction triangle appended when it is the
// active sort column, right-padded to width; otherwise the plain label.
func SortHeaderLabel[T comparable](label string, width int, sort, active T, desc bool) string {
	if sort != active {
		return label
	}
	return ActiveSortHeaderLabel(label, width, desc)
}

// ActiveSortHeaderLabel appends the direction triangle to an always-active header
// label (a single-column table with no per-column sort key), right-padded to
// width.
func ActiveSortHeaderLabel(label string, width int, desc bool) string {
	triangle := sortTriangle(desc)
	labelW := lipgloss.Width(label)
	triangleW := lipgloss.Width(triangle)
	if width <= labelW+triangleW {
		return label + triangle
	}
	return label + strings.Repeat(" ", width-labelW-triangleW) + triangle
}

// TrailingSortHeaderLabel is SortHeaderLabel for a trailing column that isn't
// padded to a fixed width (the triangle follows immediately).
func TrailingSortHeaderLabel[T comparable](label string, sort, active T, desc bool) string {
	if sort != active {
		return label
	}
	return ActiveSortHeaderLabel(label, lipgloss.Width(label)+3, desc)
}

func sortTriangle(desc bool) string {
	if desc {
		return "▽"
	}
	return "△"
}

// HitSortableHeader returns the sort key of the column containing x, if any.
func HitSortableHeader[T comparable](cols []SortableHeaderCol[T], x int) (T, bool) {
	for _, col := range cols {
		if x >= col.Start && x < col.End {
			return col.Sort, true
		}
	}
	var zero T
	return zero, false
}

// ApplySortHeaderClick mirrors htop-style header sorting: choosing a different
// column sorts it ascending; clicking the active column reverses the direction.
// It returns whether the sort *field* changed (vs. only the direction).
func ApplySortHeaderClick[T comparable](active *T, desc *bool, sort T) bool {
	if *active == sort {
		*desc = !*desc
		return false
	}
	*active = sort
	*desc = false
	return true
}

// SortDirectionLabel is the human-readable name of a sort direction.
func SortDirectionLabel(desc bool) string {
	if desc {
		return "descending"
	}
	return "ascending"
}
