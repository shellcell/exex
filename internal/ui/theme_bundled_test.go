//go:build !lite

package ui

import (
	"testing"

	"github.com/rabarbra/exex/internal/chromastyles"
)

// TestSettingsThemesAreAllBundled is the guard for the two-registry bug: the
// picker used to enumerate every Chroma palette (75 entries) while only 19 style
// XMLs were embedded, so 55 themes silently dropped the source and disassembly
// panes to the minimal highlighter while the UI chrome themed correctly.
//
// Both lists now come from internal/chromasubset/styles.txt. If they ever drift
// again, this fails instead of shipping a picker that lies.
func TestSettingsThemesAreAllBundled(t *testing.T) {
	for _, name := range settingsThemeList() {
		syntaxTheme := presetColors(name).SyntaxTheme
		if syntaxTheme == "" {
			syntaxTheme = darkSyntaxTheme // the "dark" built-in carries no overlay
		}
		if _, ok := chromastyles.Lookup(syntaxTheme); !ok {
			t.Errorf("theme %q resolves to syntax style %q, which is not bundled", name, syntaxTheme)
		}
	}
}

// TestPresetColorsNormalisesName pins the case/space handling: theme.PaletteFor
// is case-sensitive, so presetColors must fold before looking a Chroma style up.
func TestPresetColorsNormalisesName(t *testing.T) {
	want := presetColors("dracula")
	if want.SyntaxTheme != "dracula" {
		t.Fatalf("baseline lookup failed: SyntaxTheme = %q", want.SyntaxTheme)
	}
	for _, name := range []string{"Dracula", "DRACULA", "  dracula  "} {
		if got := presetColors(name); got.SyntaxTheme != want.SyntaxTheme || got.TitleBG != want.TitleBG {
			t.Errorf("presetColors(%q) = {%q, %q}, want {%q, %q}",
				name, got.SyntaxTheme, got.TitleBG, want.SyntaxTheme, want.TitleBG)
		}
	}
}
