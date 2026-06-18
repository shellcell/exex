package ui

import (
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

	addrStyle       lipgloss.Style
	mnemonicStyle   lipgloss.Style
	symbolNameStyle lipgloss.Style
	sectionStyle    lipgloss.Style

	whiteStyle      lipgloss.Style
	srcCurLineStyle lipgloss.Style
	srcShadowStyle  lipgloss.Style
	srcMappedStyle  lipgloss.Style

	modalStyle  lipgloss.Style
	panelStyle  lipgloss.Style
	switchStyle lipgloss.Style

	helpKeyStyle  lipgloss.Style
	helpDescStyle lipgloss.Style
	helpHeadStyle lipgloss.Style

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
	preset := presetColors(cfg.Theme)
	t.ApplyColors(preset)
	t.ApplyColors(cfg.Colors)
	// Hex ramp: preset first, then user override (each is a no-op when unset).
	setBytePalette(preset.HexBytePalette)
	setBytePalette(cfg.Colors.HexBytePalette)
	return t
}

// DefaultTheme returns the built-in visual palette.
func DefaultTheme() Theme {
	tabStyle := lipgloss.NewStyle().
		Padding(0, 1).
		Foreground(lipgloss.Color("245"))

	return Theme{
		titleStyle: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("231")).
			Background(lipgloss.Color("66")).
			Padding(0, 1),
		tabStyle: tabStyle,
		activeTabStyle: tabStyle.
			Foreground(lipgloss.Color("231")).
			Background(lipgloss.Color("63")).
			Bold(true),
		footerStyle: lipgloss.NewStyle().
			Foreground(lipgloss.Color("245")).
			Padding(0, 1),
		headerKey: lipgloss.NewStyle().
			Foreground(lipgloss.Color("75")).
			Bold(true),
		tableHeaderStyle: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("231")).
			Background(lipgloss.Color("236")),
		tableRowStyle: lipgloss.NewStyle().
			Foreground(lipgloss.Color("252")),
		tableSelStyle: lipgloss.NewStyle().
			Foreground(lipgloss.Color("231")).
			Background(lipgloss.Color("63")).
			Bold(true),
		addrStyle: lipgloss.NewStyle().
			Foreground(lipgloss.Color("245")),
		mnemonicStyle: lipgloss.NewStyle().
			Foreground(lipgloss.Color("117")),
		symbolNameStyle: lipgloss.NewStyle().
			Foreground(lipgloss.Color("214")).
			Bold(true),
		sectionStyle: lipgloss.NewStyle().
			Foreground(lipgloss.Color("214")).
			AlignHorizontal(lipgloss.Center).
			Bold(true),
		whiteStyle: lipgloss.NewStyle().
			Foreground(lipgloss.Color("252")),
		srcCurLineStyle: lipgloss.NewStyle().
			Foreground(lipgloss.Color("231")).
			Background(lipgloss.Color("63")).
			Bold(true),
		srcShadowStyle: lipgloss.NewStyle().
			Foreground(lipgloss.Color("240")),
		srcMappedStyle: lipgloss.NewStyle().
			Foreground(lipgloss.Color("153")),
		// Background(lipgloss.Color("23")),
		modalStyle: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("63")).
			Padding(1, 2),
		panelStyle: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("63")).
			Padding(0, 1),
		switchStyle: lipgloss.NewStyle().
			Foreground(lipgloss.Color("231")).
			Background(lipgloss.Color("238")).
			Bold(true),
		helpKeyStyle:  lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true),
		helpDescStyle: lipgloss.NewStyle().Foreground(lipgloss.Color("252")),
		helpHeadStyle: lipgloss.NewStyle().Foreground(lipgloss.Color("117")).Bold(true),
		errorStyle:    lipgloss.NewStyle().Foreground(lipgloss.Color("203")),
		infoStyle:     lipgloss.NewStyle().Foreground(lipgloss.Color("114")),
		warnStyle:     lipgloss.NewStyle().Foreground(lipgloss.Color("214")),

		// Instruction class palette — picked so calls/rets/syscalls pop out of a
		// page of "Other" instructions.
		classCallStyle:    lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Bold(true),
		classRetStyle:     lipgloss.NewStyle().Foreground(lipgloss.Color("203")).Bold(true),
		classJumpUncStyle: lipgloss.NewStyle().Foreground(lipgloss.Color("220")),
		classJumpCndStyle: lipgloss.NewStyle().Foreground(lipgloss.Color("213")),
		classSyscallStyle: lipgloss.NewStyle().Foreground(lipgloss.Color("84")).Bold(true),
		classNopStyle:     lipgloss.NewStyle().Foreground(lipgloss.Color("240")),

		stickySymStyle: lipgloss.NewStyle().
			Foreground(lipgloss.Color("231")).
			Background(lipgloss.Color("236")).
			Bold(true).
			Italic(true),
		linkAddrIntraStyle: lipgloss.NewStyle().
			Foreground(lipgloss.Color("85")).
			Underline(true).
			Bold(true),
		linkAddrInterStyle: lipgloss.NewStyle().
			Foreground(lipgloss.Color("51")).
			Underline(true).
			Bold(true),

		symFuncStyle:    lipgloss.NewStyle().Foreground(lipgloss.Color("84")),
		symObjectStyle:  lipgloss.NewStyle().Foreground(lipgloss.Color("75")),
		symFileStyle:    lipgloss.NewStyle().Foreground(lipgloss.Color("245")),
		symSectionStyle: lipgloss.NewStyle().Foreground(lipgloss.Color("213")),
		symTLSStyle:     lipgloss.NewStyle().Foreground(lipgloss.Color("177")),
		symCommonStyle:  lipgloss.NewStyle().Foreground(lipgloss.Color("215")),
		symOtherStyle:   lipgloss.NewStyle().Foreground(lipgloss.Color("250")),

		secTextStyle:    lipgloss.NewStyle().Foreground(lipgloss.Color("84")),
		secDataStyle:    lipgloss.NewStyle().Foreground(lipgloss.Color("75")),
		secRodataStyle:  lipgloss.NewStyle().Foreground(lipgloss.Color("117")),
		secTLSStyle:     lipgloss.NewStyle().Foreground(lipgloss.Color("177")),
		secDebugStyle:   lipgloss.NewStyle().Foreground(lipgloss.Color("240")),
		secNoteStyle:    lipgloss.NewStyle().Foreground(lipgloss.Color("245")),
		secSymtabStyle:  lipgloss.NewStyle().Foreground(lipgloss.Color("213")),
		secDynamicStyle: lipgloss.NewStyle().Foreground(lipgloss.Color("141")),
		secRelocStyle:   lipgloss.NewStyle().Foreground(lipgloss.Color("173")),

		pathPalette:   stylePalette("75", "114", "214", "141", "213"),
		columnPalette: stylePalette("203", "220", "84", "39", "213", "51", "215", "141"),
	}
}

// stylePalette builds a slice of foreground-only styles from colour values.
func stylePalette(colors ...string) []lipgloss.Style {
	out := make([]lipgloss.Style, len(colors))
	for i, c := range colors {
		out[i] = lipgloss.NewStyle().Foreground(lipgloss.Color(c))
	}
	return out
}

// ApplyColors overlays the user's config.Colors onto the built-in palette.
func (t *Theme) ApplyColors(c config.Colors) {
	setFg := func(s *lipgloss.Style, color string) {
		if color != "" {
			*s = s.Foreground(lipgloss.Color(color))
		}
	}
	setBg := func(s *lipgloss.Style, color string) {
		if color != "" {
			*s = s.Background(lipgloss.Color(color))
		}
	}
	// Disasm: instruction-class mnemonic colours.
	setFg(&t.classCallStyle, c.InstructionCall)
	setFg(&t.classRetStyle, c.InstructionRet)
	setFg(&t.classJumpUncStyle, c.InstructionJumpUnconditional)
	setFg(&t.classJumpCndStyle, c.InstructionJumpConditional)
	setFg(&t.classSyscallStyle, c.InstructionSyscall)
	setFg(&t.classNopStyle, c.InstructionNop)
	setFg(&t.mnemonicStyle, c.InstructionMnemonicDefault)
	// Disasm: address + operand-link colours.
	setFg(&t.addrStyle, c.AddressColumn)
	setFg(&t.linkAddrIntraStyle, c.AddressLinkIntraFunction)
	setFg(&t.linkAddrInterStyle, c.AddressLinkInterFunction)
	// Disasm: sticky symbol banner (fg + bg).
	if c.StickySymbolBannerFG != "" {
		t.stickySymStyle = t.stickySymStyle.Foreground(lipgloss.Color(c.StickySymbolBannerFG))
	}
	if c.StickySymbolBannerBG != "" {
		t.stickySymStyle = t.stickySymStyle.Background(lipgloss.Color(c.StickySymbolBannerBG))
	}
	// Symbol-table row colours.
	setFg(&t.symFuncStyle, c.SymbolFunction)
	setFg(&t.symObjectStyle, c.SymbolDataObject)
	setFg(&t.symFileStyle, c.SymbolSourceFile)
	setFg(&t.symSectionStyle, c.SymbolSection)
	setFg(&t.symTLSStyle, c.SymbolTLS)
	setFg(&t.symCommonStyle, c.SymbolCommon)
	setFg(&t.symOtherStyle, c.SymbolOther)
	// Section-table row colours.
	setFg(&t.secTextStyle, c.SectionExecutableCode)
	setFg(&t.secDataStyle, c.SectionWritableData)
	setFg(&t.secRodataStyle, c.SectionReadonlyData)
	setFg(&t.secTLSStyle, c.SectionTLS)
	setFg(&t.secDebugStyle, c.SectionDebugInfo)
	setFg(&t.secNoteStyle, c.SectionNote)
	setFg(&t.secSymtabStyle, c.SectionSymbolTable)
	setFg(&t.secDynamicStyle, c.SectionDynamicLinking)
	setFg(&t.secRelocStyle, c.SectionRelocations)
	// Source pane: position + mapping highlight.
	setFg(&t.srcCurLineStyle, c.SourceCurrentLineFG)
	setBg(&t.srcCurLineStyle, c.SourceCurrentLineBG)
	setFg(&t.srcMappedStyle, c.SourceMappedFG)
	setFg(&t.srcShadowStyle, c.SourceUnmappedFG)
	setFg(&t.whiteStyle, c.SourceCodeLineFG)
	if len(c.ColumnPalette) > 0 {
		t.columnPalette = stylePalette(c.ColumnPalette...)
	}
	// Window chrome: title, tabs, footer, header keys.
	setFg(&t.titleStyle, c.TitleFG)
	setBg(&t.titleStyle, c.TitleBG)
	setFg(&t.tabStyle, c.TabFG)
	setFg(&t.activeTabStyle, c.TabActiveFG)
	setBg(&t.activeTabStyle, c.TabActiveBG)
	setFg(&t.footerStyle, c.FooterFG)
	setFg(&t.headerKey, c.HeaderKeyFG)
	// Tables.
	setFg(&t.tableHeaderStyle, c.TableHeaderFG)
	setBg(&t.tableHeaderStyle, c.TableHeaderBG)
	setFg(&t.tableRowStyle, c.TableRowFG)
	setFg(&t.tableSelStyle, c.TableSelectedFG)
	setBg(&t.tableSelStyle, c.TableSelectedBG)
	// Shared accents.
	setFg(&t.symbolNameStyle, c.SymbolNameFG)
	setFg(&t.sectionStyle, c.SectionBannerFG)
	// Modal overlays + search switches.
	if c.ModalBorderFG != "" {
		t.modalStyle = t.modalStyle.BorderForeground(lipgloss.Color(c.ModalBorderFG))
		t.panelStyle = t.panelStyle.BorderForeground(lipgloss.Color(c.ModalBorderFG))
	}
	setFg(&t.switchStyle, c.SearchSwitchFG)
	setBg(&t.switchStyle, c.SearchSwitchBG)
	// Help overlay.
	setFg(&t.helpKeyStyle, c.HelpKeyFG)
	setFg(&t.helpDescStyle, c.HelpDescFG)
	setFg(&t.helpHeadStyle, c.HelpHeadFG)
	// Status footer.
	setFg(&t.errorStyle, c.StatusErrorFG)
	setFg(&t.infoStyle, c.StatusInfoFG)
	setFg(&t.warnStyle, c.StatusWarnFG)
	// Path-prefix palette (Libraries / Sources).
	if len(c.PathPalette) > 0 {
		t.pathPalette = stylePalette(c.PathPalette...)
	}
}

// byteHex holds the pre-rendered "ff"-style hex string with ANSI colour
// already baked in for every byte value. Re-rendering each byte through
// lipgloss on every frame burns measurable time when the disasm window is
// large; this table makes byte output an O(1) lookup.
var byteHex [256]string

// byteFG holds a precomputed foreground style for every possible byte value.
// The palette follows the hex viewer convention: 0x00 is grey, 0xFF is white,
// and the values in between cycle through a smooth rainbow keyed by the high
// nibble — making structural patterns in raw bytes pop out visually.
var byteFG [256]lipgloss.Style

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
		byteFG[i] = lipgloss.NewStyle().Foreground(lipgloss.Color(p[idx]))
		byteHex[i] = byteFG[i].Render(hex2(byte(i)))
		ch := byte('.')
		if i >= 0x20 && i < 0x7f {
			ch = byte(i)
		}
		byteASCII[i] = byteFG[i].Render(string(ch))
	}
}

// hex2 is a low-allocation %02x.
func hex2(b byte) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[b>>4], digits[b&0xf]})
}
