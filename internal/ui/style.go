package ui

import "github.com/charmbracelet/lipgloss"

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("231")).
			Background(lipgloss.Color("63")).
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

	addrStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("214"))

	mnemonicStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("117"))

	symbolNameStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("180"))

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
)

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
	}
}
