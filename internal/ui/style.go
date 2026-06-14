package ui

import (
	"github.com/charmbracelet/lipgloss"

	"github.com/rabarbra/exex/internal/config"
)

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("231")).
			Background(lipgloss.Color("66")).
			Padding(0, 1)

	tabStyle = lipgloss.NewStyle().
			Padding(0, 1).
			Foreground(lipgloss.Color("245"))

	activeTabStyle = tabStyle.
			Foreground(lipgloss.Color("231")).
			Background(lipgloss.Color("63")).
			Bold(true)

	footerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("245")).
			Padding(0, 1)

	headerKey = lipgloss.NewStyle().
			Foreground(lipgloss.Color("75")).
			Bold(true)

	tableHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("231")).
				Background(lipgloss.Color("236"))

	tableRowStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("252"))

	tableSelStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("231")).
			Background(lipgloss.Color("63")).
			Bold(true)

	// Address columns are intentionally low-contrast (grey) so the symbol
	// labels and instruction text read as the foreground.
	addrStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("245"))

	mnemonicStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("117"))

	symbolNameStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("214")).
			Bold(true)

	srcLineNoStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("244"))

	srcCurLineStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("231")).
			Background(lipgloss.Color("236")).
			Bold(true)

	modalStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("63")).
			Padding(1, 2)

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("203"))

	infoStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("114"))

	// Instruction class palette — picked so calls/rets/syscalls pop out of a
	// page of "Other" instructions.
	classCallStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Bold(true)  // bright blue
	classRetStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("203")).Bold(true) // red
	classJumpUncStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("220"))            // yellow
	classJumpCndStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("213"))            // magenta
	classSyscallStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("84")).Bold(true)  // green
	classNopStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))            // dim grey

	// Sticky "current symbol" banner above the disasm scroller.
	stickySymStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("231")).
			Background(lipgloss.Color("236")).
			Bold(true).
			Italic(true)

	// linkAddrIntraStyle marks address literals that resolve to somewhere
	// inside the *same* function/symbol as the current instruction — local
	// branches, loop heads, fall-through targets.
	linkAddrIntraStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("85")). // mint green
				Underline(true).
				Bold(true)

	// linkAddrInterStyle marks address literals that resolve to a *different*
	// symbol inside this binary — calls into other functions, jumps to PLT
	// stubs, etc.
	linkAddrInterStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("51")). // cyan
				Underline(true).
				Bold(true)

	// Symbol-type row colours — consumed by styleForSymbol.
	symFuncStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("84"))
	symObjectStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("75"))
	symFileStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	symSectionStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("213"))
	symTLSStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("177"))
	symCommonStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("215"))
	symOtherStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("250"))

	// Section-type row colours — consumed by styleForSection.
	secTextStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("84"))
	secDataStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("75"))
	secRodataStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("117"))
	secTLSStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("177"))
	secDebugStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	secNoteStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	secSymtabStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("213"))
	secDynamicStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("141"))
	secRelocStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("173"))
)

// ApplyColors overlays the user's config.Colors onto the package's built-in
// palette. Each non-empty field overrides the corresponding compiled-in style,
// and empty fields keep their defaults. Re-call to re-skin at runtime.
func ApplyColors(c config.Colors) {
	setFg := func(s *lipgloss.Style, color string) {
		if color != "" {
			*s = s.Foreground(lipgloss.Color(color))
		}
	}
	// Disasm: instruction-class mnemonic colours.
	setFg(&classCallStyle, c.InstructionCall)
	setFg(&classRetStyle, c.InstructionRet)
	setFg(&classJumpUncStyle, c.InstructionJumpUnconditional)
	setFg(&classJumpCndStyle, c.InstructionJumpConditional)
	setFg(&classSyscallStyle, c.InstructionSyscall)
	setFg(&classNopStyle, c.InstructionNop)
	setFg(&mnemonicStyle, c.InstructionMnemonicDefault)
	// Disasm: address + operand-link colours.
	setFg(&addrStyle, c.AddressColumn)
	setFg(&linkAddrIntraStyle, c.AddressLinkIntraFunction)
	setFg(&linkAddrInterStyle, c.AddressLinkInterFunction)
	// Disasm: sticky symbol banner (fg + bg).
	if c.StickySymbolBannerFG != "" {
		stickySymStyle = stickySymStyle.Foreground(lipgloss.Color(c.StickySymbolBannerFG))
	}
	if c.StickySymbolBannerBG != "" {
		stickySymStyle = stickySymStyle.Background(lipgloss.Color(c.StickySymbolBannerBG))
	}
	// Symbol-table row colours.
	setFg(&symFuncStyle, c.SymbolFunction)
	setFg(&symObjectStyle, c.SymbolDataObject)
	setFg(&symFileStyle, c.SymbolSourceFile)
	setFg(&symSectionStyle, c.SymbolSection)
	setFg(&symTLSStyle, c.SymbolTLS)
	setFg(&symCommonStyle, c.SymbolCommon)
	setFg(&symOtherStyle, c.SymbolOther)
	// Section-table row colours.
	setFg(&secTextStyle, c.SectionExecutableCode)
	setFg(&secDataStyle, c.SectionWritableData)
	setFg(&secRodataStyle, c.SectionReadonlyData)
	setFg(&secTLSStyle, c.SectionTLS)
	setFg(&secDebugStyle, c.SectionDebugInfo)
	setFg(&secNoteStyle, c.SectionNote)
	setFg(&secSymtabStyle, c.SectionSymbolTable)
	setFg(&secDynamicStyle, c.SectionDynamicLinking)
	setFg(&secRelocStyle, c.SectionRelocations)
	// Source-pane syntax-highlighting theme.
	if c.SyntaxTheme != "" {
		syntaxTheme = c.SyntaxTheme
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

func init() {
	// Indices: 0 = grey (special, 0x00); 1..16 = high-nibble buckets for
	// 0x01..0xFE; 17 = white (special, 0xFF).
	palette := [18]lipgloss.Color{
		"#808080", // 0x00      grey
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
		"#FFFFFF", // 0xFF      white
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
		byteFG[i] = lipgloss.NewStyle().Foreground(palette[idx])
		byteHex[i] = byteFG[i].Render(hex2(byte(i)))
	}
}

// hex2 is a low-allocation %02x.
func hex2(b byte) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[b>>4], digits[b&0xf]})
}
