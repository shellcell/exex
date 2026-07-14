package ui

import (
	"strings"
	"testing"

	"github.com/shellcell/exex/internal/binfile"
	"github.com/shellcell/exex/internal/config"
	"github.com/shellcell/exex/internal/ui/layout"
)

func TestInfoViewUsesThemeBodyForeground(t *testing.T) {
	m := &Model{
		layoutState: layoutState{width: 80, height: 20},
		theme:       NewTheme(config.Config{Theme: "solarized-light"}),
		file: &binfile.File{Info: &binfile.Info{
			FileSize:  4096,
			WordBits:  64,
			ByteOrder: "little-endian",
			PIE:       binfile.TriYes,
			NX:        binfile.TriYes,
		}},
	}

	out := m.renderInfo()
	want := layout.RenderStyle("64-bit, little-endian", 0, m.theme.tableRowStyle)
	if !strings.Contains(out, want) {
		t.Fatalf("info value does not use themed body foreground: %q", out)
	}
}
