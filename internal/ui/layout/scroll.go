// Package layout holds the pure, Model-independent scroll/viewport geometry the
// TUI views share: given a cursor, a window height and a per-row height function,
// it computes which row to anchor at the top and which logical item sits at a
// visual row. Keeping it dependency-free (no Model, no lipgloss) makes the
// variable-height scroll math unit-testable in isolation and is the first seam
// carved out of the large ui package.
package layout

// ViewportTop clamps a detached viewport top for variable-height rows.
func ViewportTop(top, n, visible int, rowHeight func(int) int) int {
	if n <= 0 {
		return 0
	}
	if visible < 1 {
		visible = 1
	}
	if top < 0 {
		top = 0
	}
	if top >= n {
		top = n - 1
	}
	maxTop := MaxViewportTop(n, visible, rowHeight)
	if top > maxTop {
		return maxTop
	}
	return top
}

// MaxViewportTop returns the latest top row that can fill the viewport.
func MaxViewportTop(n, visible int, rowHeight func(int) int) int {
	if n <= 0 {
		return 0
	}
	if visible < 1 {
		visible = 1
	}
	rows := 0
	top := n
	for top > 0 {
		h := max(1, rowHeight(top-1))
		if rows+h > visible {
			break
		}
		rows += h
		top--
	}
	if top == n {
		return n - 1
	}
	return top
}

// VisualTop returns the nearest top that keeps cur visible.
func VisualTop(cur, top, n, visible int, rowHeight func(int) int) int {
	if n <= 0 {
		return 0
	}
	if visible < 1 {
		visible = 1
	}
	if cur < 0 {
		cur = 0
	}
	if cur >= n {
		cur = n - 1
	}
	if top < 0 || cur < top {
		top = cur
	}
	if top >= n {
		top = n - 1
	}
	if maxTop := MaxViewportTop(n, visible, rowHeight); top > maxTop {
		top = maxTop
	}
	if top > cur {
		top = cur
	}

	// Find the earliest row that can still keep cur visible by walking backward
	// only as far as the viewport can fit. This preserves the old top while it's
	// valid, but avoids the O(n²) forward scan when the cursor jumps far away
	// (End / Ctrl+E on huge symbol or string tables).
	minTop := cur
	rows := max(1, rowHeight(cur))
	for minTop > 0 {
		h := max(1, rowHeight(minTop-1))
		if rows+h > visible {
			break
		}
		rows += h
		minTop--
	}
	if top < minTop {
		top = minTop
	}
	return top
}

// VisualItemAtRow maps a visual row offset to a logical item index.
func VisualItemAtRow(top, n, row int, rowHeight func(int) int) (int, bool) {
	if row < 0 {
		return 0, false
	}
	pos := 0
	for i := top; i < n; i++ {
		h := max(1, rowHeight(i))
		if row >= pos && row < pos+h {
			return i, true
		}
		pos += h
	}
	return 0, false
}
