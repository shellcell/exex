package ui

// Cross-file exploration: opening a dependency, an archive member, or a fat-Mach-O
// arch slice replaces the whole model (each is a different binfile.File). To make
// that reversible — so "explore dependencies" is navigation, not a one-way trip —
// we keep a stack of the models we came from and a breadcrumb of their names.

import (
	"path/filepath"
	"strings"

	tea "charm.land/bubbletea/v2"
)

// enterFile transfers cross-file context from m (the model being left) to nm (the
// freshly-built model for the newly-opened file): nm inherits m's history with m
// pushed on top, takes m's size, and records its breadcrumb label. Every file
// switch (dependency / member / arch) routes through this so Back works uniformly.
func (m *Model) enterFile(nm *Model, label string) {
	nm.fileStack = append(append([]*Model(nil), m.fileStack...), m)
	nm.fileLabel = label
	nm.width, nm.height = m.width, m.height
}

// goBackFile pops the cross-file stack, returning the model we opened the current
// file from — with its view and cursor exactly as we left it. ok is false at the
// root (nothing to go back to).
func (m *Model) goBackFile() (tea.Model, tea.Cmd, bool) {
	n := len(m.fileStack)
	if n == 0 {
		return m, nil, false
	}
	prev := m.fileStack[n-1]
	prev.fileStack = m.fileStack[:n-1 : n-1]
	prev.width, prev.height = m.width, m.height
	prev.viewDirty = true
	prev.setStatus("back to "+prev.breadcrumbLeaf(), false)
	return prev, nil, true
}

// breadcrumbLeaf is this model's own file name (the last breadcrumb segment).
func (m *Model) breadcrumbLeaf() string {
	if m.fileLabel != "" {
		return m.fileLabel
	}
	if m.file != nil {
		return filepath.Base(m.file.Path)
	}
	return "?"
}

// breadcrumb renders the open-file chain (root ▸ … ▸ current) when we've descended
// into another file; "" at the root so the normal chrome is unchanged.
func (m *Model) breadcrumb() string {
	if len(m.fileStack) == 0 {
		return ""
	}
	parts := make([]string, 0, len(m.fileStack)+1)
	for _, s := range m.fileStack {
		parts = append(parts, s.breadcrumbLeaf())
	}
	parts = append(parts, m.breadcrumbLeaf())
	return strings.Join(parts, " ▸ ")
}
