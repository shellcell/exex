package ui

import (
	"strings"

	"charm.land/lipgloss/v2"

	"github.com/rabarbra/exex/internal/config"
)

// Theme contains all Lip Gloss styles used by a Model.
type Theme struct {
	titleStyle       lipgloss.Style
	tabStyle         lipgloss.Style
	activeTabStyle   lipgloss.Style
	footerStyle      lipgloss.Style
	headerKey        lipgloss.Style
	tableHeaderStyle lipgloss.Style
	tableRowStyle    lipgloss.Style
	tableSelStyle    lipgloss.Style
	// disasmSelSeq is the raw SGR prefix (bold + tableSelStyle's background) that the
	// disasm view re-applies after every reset to draw its selected-line bar, so the
	// bar matches the selection colour the table views use while keeping each token's
	// own foreground colour. Derived from tableSelStyle whenever colours change.
	disasmSelSeq string

	addrStyle       lipgloss.Style
	mnemonicStyle   lipgloss.Style
	symbolNameStyle lipgloss.Style
	sectionStyle    lipgloss.Style

	whiteStyle      lipgloss.Style
	srcCurLineStyle lipgloss.Style
	srcShadowStyle  lipgloss.Style
	srcMappedStyle  lipgloss.Style

	modalStyle      lipgloss.Style
	panelStyle      lipgloss.Style
	paneBorderStyle lipgloss.Style // thin left divider between side-by-side panes
	switchStyle     lipgloss.Style

	helpKeyStyle  lipgloss.Style
	helpDescStyle lipgloss.Style
	helpHeadStyle lipgloss.Style
	treeNodeStyle lipgloss.Style // collapsible group rows in the symbols/sources/libs trees

	viewStyle lipgloss.Style

	errorStyle lipgloss.Style
	infoStyle  lipgloss.Style
	warnStyle  lipgloss.Style

	classCallStyle    lipgloss.Style
	classRetStyle     lipgloss.Style
	classJumpUncStyle lipgloss.Style
	classJumpCndStyle lipgloss.Style
	classSyscallStyle lipgloss.Style
	classNopStyle     lipgloss.Style

	stickySymStyle     lipgloss.Style
	linkAddrIntraStyle lipgloss.Style
	linkAddrInterStyle lipgloss.Style

	// Operand + mnemonic-category token colours for the built-in (non-Chroma)
	// disasm highlighter. Jumps/calls/rets/syscalls/nops reuse the instruction
	// class styles; these cover the remaining mnemonic categories and operands.
	asmRegisterStyle lipgloss.Style
	asmNumberStyle   lipgloss.Style
	asmMoveStyle     lipgloss.Style // mov / load / store / push / pop / lea
	asmArithStyle    lipgloss.Style // add / sub / mul / and / shifts / cmp / test

	hexPointerStyle lipgloss.Style // mapped pointer words in the hex pointer-decode view

	symFuncStyle    lipgloss.Style
	symObjectStyle  lipgloss.Style
	symFileStyle    lipgloss.Style
	symSectionStyle lipgloss.Style
	symTLSStyle     lipgloss.Style
	symCommonStyle  lipgloss.Style
	symOtherStyle   lipgloss.Style

	secTextStyle    lipgloss.Style
	secDataStyle    lipgloss.Style
	secRodataStyle  lipgloss.Style
	secTLSStyle     lipgloss.Style
	secDebugStyle   lipgloss.Style
	secNoteStyle    lipgloss.Style
	secSymtabStyle  lipgloss.Style
	secDynamicStyle lipgloss.Style
	secRelocStyle   lipgloss.Style

	// pathPalette colours file paths in the Libraries and Sources views: a path's
	// directory prefix is hashed to pick one entry, so paths sharing a directory
	// share a colour.
	pathPalette []lipgloss.Style

	// columnPalette colours the source↔disasm column-correlation highlight: the
	// Nth distinct column on a source line, its caret, and the addresses mapped to
	// it all share columnPalette[N].
	columnPalette []lipgloss.Style
}

// NewTheme builds a theme from a config: it starts from the built-in dark
// palette, applies the selected named preset, then layers the user's individual
// colour overrides on top (so a single `colors:` entry always wins over the
// preset). It also rebuilds the global hex byte ramp when a palette is supplied.
func NewTheme(cfg config.Config) Theme {
	t := DefaultTheme()
	preset := presetColors(effectiveThemeName(cfg.Theme))
	user := cfg.Colors
	// The theme-derived view/pane background is opt-in (behavior.background); when
	// off, the UI uses the terminal's own background. An explicit colors.view_bg
	// is always honoured (setting it is itself the opt-in).
	if !cfg.Behavior.Background {
		preset.ViewBG = ""
	}
	t.ApplyColors(preset)
	t.ApplyColors(user)
	// Hex ramp: preset first, then user override (each is a no-op when unset).
	setBytePalette(preset.HexBytePalette)
	setBytePalette(user.HexBytePalette)
	return t
}

// DefaultTheme returns the built-in visual palette. It sets only the non-colour
// attributes that each style needs (bold/underline/padding/border/alignment);
// every foreground/background colour comes from the colorBindings table via
// applyDefaults, so a default colour lives in exactly one place. Styles not
// listed here are left zero and tinted purely by their binding.
func DefaultTheme() Theme {
	border := func() lipgloss.Style {
		return lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("63"))
	}
	t := Theme{
		titleStyle:         lipgloss.NewStyle().Bold(true).Padding(0, 1),
		tabStyle:           lipgloss.NewStyle().Padding(0, 1),
		activeTabStyle:     lipgloss.NewStyle().Padding(0, 1).Bold(true),
		footerStyle:        lipgloss.NewStyle().Padding(0, 1),
		headerKey:          lipgloss.NewStyle().Bold(true),
		tableHeaderStyle:   lipgloss.NewStyle().Bold(true),
		tableSelStyle:      lipgloss.NewStyle().Bold(true),
		symbolNameStyle:    lipgloss.NewStyle(),
		sectionStyle:       lipgloss.NewStyle().AlignHorizontal(lipgloss.Center).Bold(true),
		srcCurLineStyle:    lipgloss.NewStyle().Bold(true),
		modalStyle:         border().Padding(1, 2),
		panelStyle:         border().Padding(0, 1),
		paneBorderStyle:    lipgloss.NewStyle().BorderStyle(lipgloss.NormalBorder()).BorderLeft(true).BorderForeground(lipgloss.Color("240")),
		switchStyle:        lipgloss.NewStyle().Bold(true),
		helpKeyStyle:       lipgloss.NewStyle().Bold(true),
		helpHeadStyle:      lipgloss.NewStyle().Bold(true),
		classCallStyle:     lipgloss.NewStyle().Bold(true),
		classRetStyle:      lipgloss.NewStyle().Bold(true),
		classSyscallStyle:  lipgloss.NewStyle().Bold(true),
		stickySymStyle:     lipgloss.NewStyle().Bold(true),
		linkAddrIntraStyle: lipgloss.NewStyle().Underline(true).Bold(true),
		linkAddrInterStyle: lipgloss.NewStyle().Underline(true).Bold(true),

		pathPalette:   stylePalette("75", "114", "214", "141", "213"),
		columnPalette: stylePalette("203", "220", "84", "39", "213", "51", "215", "141"),
	}
	t.applyDefaults()
	return t
}

// stylePalette builds a slice of foreground-only styles from colour values.
func stylePalette(colors ...string) []lipgloss.Style {
	out := make([]lipgloss.Style, len(colors))
	for i, c := range colors {
		out[i] = lipgloss.NewStyle().Foreground(lipgloss.Color(c))
	}
	return out
}

// ApplyColors overlays the user's config.Colors onto the built-in palette. The
// scalar fg/bg roles come from the single colorBindings table; the handful that
// aren't a plain fg/bg on one style are applied below.
func (t *Theme) ApplyColors(c config.Colors) {
	for _, b := range colorBindings {
		b.apply(t, configColor(c, b.key))
	}
	// Modal/panel border (a border colour, not fg/bg).
	if c.ModalBorderFG != "" {
		t.modalStyle = t.modalStyle.BorderForeground(lipgloss.Color(c.ModalBorderFG))
		t.panelStyle = t.panelStyle.BorderForeground(lipgloss.Color(c.ModalBorderFG))
	}
	// Cycled palettes (Sources/Libraries paths; source↔disasm caret columns).
	if len(c.ColumnPalette) > 0 {
		t.columnPalette = stylePalette(c.ColumnPalette...)
	}
	if len(c.PathPalette) > 0 {
		t.pathPalette = stylePalette(c.PathPalette...)
	}
	t.deriveDisasmSel()
}

// deriveDisasmSel recomputes disasmSelSeq from the current tableSelStyle so the
// disasm selection bar tracks the theme's selection background. It renders a NUL
// sentinel with bold + that background and keeps the opening escape sequence.
func (t *Theme) deriveDisasmSel() {
	r := lipgloss.NewStyle().Bold(true).Background(t.tableSelStyle.GetBackground()).Render("\x00")
	if before, _, found := strings.Cut(r, "\x00"); found {
		t.disasmSelSeq = before
	} else {
		t.disasmSelSeq = r
	}
}

// byteHex holds the pre-rendered "ff"-style hex string with ANSI colour
// already baked in for every byte value. Re-rendering each byte through
// lipgloss on every frame burns measurable time when the disasm window is
// large; this table makes byte output an O(1) lookup.
var byteHex [256]string

// byteASCII holds the pre-rendered, per-byte-coloured ASCII cell ("." for
// non-printable bytes). Like byteHex, this avoids a lipgloss.Render call for
// every byte of every visible row on each frame.
var byteASCII [256]string

// defaultBytePalette is the built-in 18-colour ramp. Index 0 = 0x00 (grey),
// 1..16 = high-nibble buckets for 0x01..0xFE, 17 = 0xFF (white).
var defaultBytePalette = [18]string{
	"#808080", // 0x00       grey
	"#FF71A9", // 0x01..0x0F red
	"#FF7A78", // 0x10..0x1F salmon
	"#FF8123", // 0x20..0x2F red-orange
	"#F79300", // 0x30..0x3F yellow-orange
	"#E69F00", // 0x40..0x4F yellow
	"#C1B200", // 0x50..0x5F green-yellow
	"#82C600", // 0x60..0x6F lime
	"#00D500", // 0x70..0x7F green
	"#00D459", // 0x80..0x8F clover
	"#00D091", // 0x90..0x9F teal
	"#00CCBB", // 0xA0..0xAF cyan
	"#00C7DE", // 0xB0..0xBF light blue
	"#00BEFF", // 0xC0..0xCF blue
	"#6CAFFF", // 0xD0..0xDF blurple
	"#B298FF", // 0xE0..0xEF purple
	"#FF4DFF", // 0xF0..0xFE pink
	"#FFFFFF", // 0xFF       white
}

// init precomputes byte-level hex styles used by byte dump renderers.
func init() { setBytePalette(defaultBytePalette[:]) }

// setBytePalette rebuilds the per-byte hex colour ramp from an 18-entry palette.
// A slice that isn't exactly 18 non-empty entries is ignored, leaving the
// current ramp intact — so callers can pass an unset config palette safely.
func setBytePalette(p []string) {
	if len(p) != 18 {
		return
	}
	for _, c := range p {
		if c == "" {
			return
		}
	}
	// One foreground style per palette colour, reused across the byte values that
	// map onto it. The convention: 0x00 is grey, 0xFF is white, and 0x01..0xFE
	// cycle through a rainbow keyed by the high nibble, making byte patterns pop.
	styles := make([]lipgloss.Style, len(p))
	for i, c := range p {
		styles[i] = lipgloss.NewStyle().Foreground(lipgloss.Color(c))
	}
	for i := 0; i < 256; i++ {
		var idx int
		switch {
		case i == 0x00:
			idx = 0
		case i == 0xFF:
			idx = 17
		default:
			idx = 1 + (i >> 4)
		}
		st := styles[idx]
		byteHex[i] = st.Render(hex2(byte(i)))
		ch := byte('.')
		if i >= 0x20 && i < 0x7f {
			ch = byte(i)
		}
		byteASCII[i] = st.Render(string(ch))
	}
}

// hex2 is a low-allocation %02x.
func hex2(b byte) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[b>>4], digits[b&0xf]})
}
