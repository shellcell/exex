package ui

// The generic sort-header primitives (SortableHeaderCol, SortHeaderLabel,
// HitSortableHeader, ApplySortHeaderClick, SortDirectionLabel, …) live in
// internal/ui/layout, and each view's click handler lives with its state in
// internal/ui/views/*. This file keeps only the mode dispatch.

func (m *Model) handleSortableHeaderClick(x, bodyRow int) bool {
	return m.current().sortHeaderClick(x, bodyRow)
}

func (m *Model) isTableHeaderRow(bodyRow int) bool {
	return m.current().headerRow(bodyRow)
}
