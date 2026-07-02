package ui

import (
	"strings"
	"testing"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/rabarbra/exex/internal/config"
	"github.com/rabarbra/exex/internal/theme"
	"github.com/rabarbra/exex/internal/ui/layout"
)

func TestPresetColorsLookup(t *testing.T) {
	if got := presetColors(""); got.InstructionCall != "" {
		t.Fatalf("empty preset should be zero, got %q", got.InstructionCall)
	}
	if got := presetColors("nope"); got.InstructionCall != "" {
		t.Fatalf("unknown preset should be zero, got %q", got.InstructionCall)
	}
	if got := presetColors("solarized-dark"); got.InstructionCall != solBlue {
		t.Fatalf("solarized-dark call colour = %q, want %q", got.InstructionCall, solBlue)
	}
	if got := presetColors("nord"); got.InstructionCall != nord8 || len(got.HexBytePalette) != 18 {
		t.Fatalf("nord preset incomplete: call=%q palette=%d", got.InstructionCall, len(got.HexBytePalette))
	}
	// Light and dark swap the body/background tones.
	if dark, light := presetColors("solarized-dark"), presetColors("solarized-light"); dark.TableRowFG == light.TableRowFG {
		t.Fatalf("light and dark presets should differ in body text colour (both %q)", dark.TableRowFG)
	}
}

func TestNewThemePresetAndOverridePrecedence(t *testing.T) {
	base := DefaultTheme().classCallStyle.Render("x")
	defaultPreset := NewTheme(config.Config{}).classCallStyle.Render("x")
	if defaultPreset != NewTheme(config.Config{Theme: defaultThemeName}).classCallStyle.Render("x") {
		t.Fatal("empty theme should use the default Nord preset")
	}
	if defaultPreset == base {
		t.Fatal("empty theme did not apply the default Nord preset")
	}

	preset := NewTheme(config.Config{Theme: "solarized-dark"}).classCallStyle.Render("x")
	if preset == base {
		t.Fatal("solarized-dark preset did not change the call-instruction colour")
	}

	// An explicit colour override must win over the preset.
	override := NewTheme(config.Config{
		Theme:  "solarized-dark",
		Colors: config.Colors{InstructionCall: "#ff0000"},
	}).classCallStyle.Render("x")
	if override == preset {
		t.Fatal("colors override did not win over the preset")
	}
}

func TestSourceSyntaxThemeFollowsPresetUnlessOverridden(t *testing.T) {
	if got := sourceSyntaxTheme(config.Config{}); got != defaultThemeName {
		t.Fatalf("default syntax theme = %q, want %q", got, defaultThemeName)
	}
	if got := sourceSyntaxTheme(config.Config{Theme: "dark"}); got != darkSyntaxTheme {
		t.Fatalf("dark syntax theme = %q, want %q", got, darkSyntaxTheme)
	}
	if got := sourceSyntaxTheme(config.Config{Theme: "solarized-light"}); got != "solarized-light" {
		t.Fatalf("solarized-light syntax theme = %q", got)
	}
	if got := sourceSyntaxTheme(config.Config{Theme: "nord"}); got != "nord" {
		t.Fatalf("nord syntax theme = %q", got)
	}
	if got := sourceSyntaxForeground(config.Config{Theme: "solarized-light"}); got != "#586e75" {
		t.Fatalf("solarized-light syntax foreground = %q, want #586e75", got)
	}
	got := sourceSyntaxTheme(config.Config{
		Theme:  "solarized-light",
		Colors: config.Colors{SyntaxTheme: "dracula"},
	})
	if got != "dracula" {
		t.Fatalf("syntax theme override = %q, want dracula", got)
	}
}

func TestHeaderAndCaretColoursAreDistinct(t *testing.T) {
	for _, name := range []string{"", "nord", "solarized-dark", "solarized-light", "dracula"} {
		p := presetColors(effectiveThemeName(name))
		if len(p.ColumnPalette) == 0 {
			continue
		}
		for _, c := range p.ColumnPalette {
			if strings.EqualFold(c, p.HeaderKeyFG) {
				t.Fatalf("theme %q header colour %q also appears in caret palette %v", name, p.HeaderKeyFG, p.ColumnPalette)
			}
			if strings.EqualFold(c, p.HelpHeadFG) {
				t.Fatalf("theme %q help header colour %q also appears in caret palette %v", name, p.HelpHeadFG, p.ColumnPalette)
			}
		}
		for label, c := range map[string]string{
			"table header background":  p.TableHeaderBG,
			"sticky header background": p.StickySymbolBannerBG,
		} {
			if c == "" {
				continue
			}
			if strings.EqualFold(c, p.SourceCurrentLineBG) {
				t.Fatalf("theme %q %s %q matches caret background", name, label, c)
			}
			if strings.EqualFold(c, p.TabActiveBG) {
				t.Fatalf("theme %q %s %q matches active tab background", name, label, c)
			}
		}
	}
}

func TestPathColorKeyGroupsCoarsely(t *testing.T) {
	cases := map[string]string{
		"/usr/lib/clang/foo.h":   "usr/lib",
		"/usr/lib/glib/bar.h":    "usr/lib", // sibling subtree → same key
		"/Users/x/proj/src/a.c":  "Users/x",
		"/Users/x/proj/test/b.c": "Users/x",
		"/opt/thing":             "opt",
		"libfoo.so":              "", // bare name → shared key
	}
	for in, want := range cases {
		if got := pathColorKey(in); got != want {
			t.Errorf("pathColorKey(%q) = %q, want %q", in, got, want)
		}
	}
	// Presets must supply the palettes so path and source-mapping colours follow
	// the theme rather than falling back to the hardcoded defaults.
	for _, name := range []string{"nord", "solarized-dark", "solarized-light"} {
		p := presetColors(name)
		if len(p.PathPalette) == 0 {
			t.Errorf("preset %q has no path palette", name)
		}
		if len(p.ColumnPalette) == 0 {
			t.Errorf("preset %q has no column palette", name)
		}
		if p.SourceCodeLineFG == "" {
			t.Errorf("preset %q has no source-code-line colour", name)
		}
	}
}

func TestChromaThemeDerivesWholeUI(t *testing.T) {
	if _, ok := theme.PaletteFor("dracula"); !ok {
		t.Fatal("expected a generated 'dracula' palette")
	}
	// A Chroma theme name must derive a full UI palette and visibly change it.
	derived := presetColors("dracula")
	if derived.InstructionMnemonicDefault == "" || derived.SyntaxTheme != "dracula" {
		t.Fatalf("dracula did not derive a UI palette: %+v", derived.InstructionMnemonicDefault)
	}
	base := DefaultTheme().mnemonicStyle.Render("x")
	drac := NewTheme(config.Config{Theme: "dracula"}).mnemonicStyle.Render("x")
	if drac == base {
		t.Fatal("dracula theme did not change the mnemonic colour")
	}
}

// TestColorBindingKeysExist guards the single-source colour table: every binding
// key must be a real config.Colors field (a typo'd key would silently drop the
// role from both ApplyColors and deriveColors).
func TestColorBindingKeysExist(t *testing.T) {
	for _, b := range colorBindings {
		if _, ok := colorFieldIndex[b.key]; !ok {
			t.Errorf("binding key %q has no config.Colors field", b.key)
		}
	}
	if len(colorBindings) < 55 {
		t.Fatalf("colour binding table looks truncated: %d entries", len(colorBindings))
	}
}

// TestDefaultThemeMatchesBindingDefaults guards the single-source defaults: every
// binding's built-in `def` colour must match what DefaultTheme actually renders for
// that role. This is what lets DefaultTheme paint colours from the table instead of
// repeating them, and catches drift if a default is changed in only one place.
func TestDefaultThemeMatchesBindingDefaults(t *testing.T) {
	dt := DefaultTheme()
	for _, b := range colorBindings {
		if b.def == "" {
			continue
		}
		rendered := b.target(&dt).Render("x")
		prefix := "38;5;"
		if b.bg {
			prefix = "48;5;"
		}
		token := prefix + b.def
		if !strings.Contains(rendered, token+"m") && !strings.Contains(rendered, token+";") {
			t.Errorf("role %q: DefaultTheme render %q does not carry default colour %q", b.key, rendered, b.def)
		}
	}
}

func TestViewBackgroundIsOptIn(t *testing.T) {
	if got := DefaultTheme().renderViewBackground("plain", 5); got != "plain" {
		t.Fatalf("default view background should be off, got %q", got)
	}
	if got := NewTheme(config.Config{Theme: "nord"}).renderViewBackground("plain", 5); got != "plain" {
		t.Fatalf("preset view background should be off unless configured, got %q", got)
	}
	styled := NewTheme(config.Config{Colors: config.Colors{ViewBG: "#010203"}}).renderViewBackground("plain", 5)
	if styled == "plain" || !strings.Contains(styled, "\x1b[") {
		t.Fatalf("configured view background was not applied: %q", styled)
	}
}

func TestRenderBackgroundReappliesAfterANSIReset(t *testing.T) {
	bg := lipgloss.NewStyle().Background(lipgloss.Color("#010203"))
	fg := lipgloss.NewStyle().Foreground(lipgloss.Color("#abcdef")).Render("x")
	out := renderBackground(fg+" y", 4, bg)
	if got := ansi.StringWidth(out); got != 4 {
		t.Fatalf("background row width = %d, want 4", got)
	}
	if prefix := stylePrefix(bg); strings.Count(out, prefix) < 2 {
		t.Fatalf("background was not reapplied after inner reset: %q", out)
	}
}

func TestModalOverlayUsesThemedForegroundAndBackground(t *testing.T) {
	m := &Model{
		layoutState: layoutState{width: 40, height: 10},
		theme: NewTheme(config.Config{Colors: config.Colors{
			ViewBG:     "#010203",
			TableRowFG: "#040506",
		}}),
	}
	out := m.overlayCenter(layout.PadBody("", m.width, m.height), m.theme.modalStyle.Render("popup text"))

	bgPrefix := stylePrefix(lipgloss.NewStyle().Background(lipgloss.Color("#010203")))
	if !strings.Contains(out, bgPrefix) {
		t.Fatalf("modal overlay missing configured background: %q", out)
	}
	fgPrefix := stylePrefix(lipgloss.NewStyle().Foreground(lipgloss.Color("#040506")))
	if !strings.Contains(out, fgPrefix) {
		t.Fatalf("modal overlay missing themed foreground: %q", out)
	}
}

func TestSetBytePaletteGuards(t *testing.T) {
	// Restore the default ramp no matter what this test does.
	t.Cleanup(func() { setBytePalette(defaultBytePalette[:]) })

	before := byteHex[0x10]
	setBytePalette([]string{"#fff", "#000"}) // wrong length: ignored
	if byteHex[0x10] != before {
		t.Fatal("short palette should have been ignored")
	}

	custom := make([]string, 18)
	for i := range custom {
		custom[i] = "#abcdef"
	}
	setBytePalette(custom)
	if byteHex[0x10] == before {
		t.Fatal("valid 18-entry palette should have rebuilt the ramp")
	}
}
