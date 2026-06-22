package ui

import (
	"testing"

	"charm.land/lipgloss/v2"

	"github.com/rabarbra/exex/internal/config"
)

// TestTreeNodeColor locks in the tree-group-row colour: a blue that matches the
// data-object ("Name") role in every theme — distinct from the old stand-out
// purple, and never the white/emphasis text colour (which it briefly was in
// nord). Checked across the built-in default, the hand-written presets, and a
// Chroma-derived theme; an explicit override still wins.
func TestTreeNodeColor(t *testing.T) {
	for _, name := range []string{"", "nord", "solarized-dark", "solarized-light", "monokai", "dracula"} {
		th := NewTheme(config.Config{Theme: name})
		if got, want := th.treeNodeStyle.GetForeground(), th.symObjectStyle.GetForeground(); got != want {
			t.Errorf("theme %q: tree node fg %v != data-object fg %v", name, got, want)
		}
	}
	// In nord specifically, the tree node must be the Frost blue, not the old white.
	if got := NewTheme(config.Config{Theme: "nord"}).treeNodeStyle.GetForeground(); got != lipgloss.Color("#81a1c1") {
		t.Errorf("nord tree node = %v, want Frost blue #81a1c1", got)
	}
	// An explicit colors.tree_node_fg override still wins.
	th := NewTheme(config.Config{Colors: config.Colors{TreeNodeFG: "201"}})
	if got, want := th.treeNodeStyle.GetForeground(), lipgloss.Color("201"); got != want {
		t.Fatalf("explicit tree_node_fg override = %v, want %v", got, want)
	}
}
