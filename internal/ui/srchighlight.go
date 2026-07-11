package ui

// Shell glue for the split source/disasm panes. The shared colour policy the
// two layouts use identically (the srcGutter line-number colours and the
// AddrMapStyle instruction-address colours) lives with the renderers in
// views/disasm/sourcepane.go; what stays here needs the shell's mode.

// rightPaneActive reports whether the disasm view is currently showing a second
// (follower) pane that the independent-scroll controls apply to.
func (m *Model) rightPaneActive() bool {
	return m.mode == modeDisasm && m.dasm.ShowSource && m.file.HasDWARF()
}

// scrollRightPane nudges the follower pane's independent scroll offset; the
// renderers clamp it to the pane bounds.
func (m *Model) scrollRightPane(delta int) {
	m.dasm.ScrollRightPane(delta)
}
