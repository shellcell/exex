package layout

import (
	"strings"

	"charm.land/lipgloss/v2"
)

// StylePrefix returns the leading SGR sequence a lipgloss style emits (its "open"
// codes), or "" when the style adds no styling.
//
// It costs a full lipgloss render, so anything on a render path should build a
// Painter once instead of calling this per frame.
func StylePrefix(st lipgloss.Style) string {
	sample := st.Render("x")
	i := strings.IndexByte(sample, 'x')
	if i <= 0 {
		return ""
	}
	return sample[:i]
}

// A Painter applies a style's colour, holding the style's SGR sequence rather
// than re-deriving it.
//
// Deriving it means rendering a sample string through lipgloss, which serialises
// the colours into ANSI and allocates — and the callers here (the table header,
// the panel background behind every frame, an address on every disasm row) run
// on every redraw. The zero Painter adds nothing and passes text through
// unchanged.
type Painter struct {
	prefix string
	style  lipgloss.Style
	// simple records that wrapping the text in prefix + reset reproduces what
	// lipgloss would emit. Not every style is like that — an underline style is
	// rendered character by character — so Text falls back to the real render for
	// the ones that aren't, and no theme can silently change what is drawn.
	simple bool
}

// NewPainter captures st's SGR sequence. Build it when the theme is built, not
// when a frame is drawn.
func NewPainter(st lipgloss.Style) Painter {
	p := Painter{prefix: StylePrefix(st), style: st}
	// Verify against lipgloss itself rather than reasoning about which style
	// properties are safe: whatever the library does, Text matches it.
	const probe = "ab"
	p.simple = p.prefix != "" && p.prefix+probe+"\x1b[m" == st.Render(probe)
	return p
}

// Text applies the painter's colour to a single run of *plain* text — byte for
// byte what a lipgloss render of the same style produces, but without the
// render for the styles that allow it.
//
// Only for text that carries no styling of its own: an embedded reset would end
// the colour early, where lipgloss would re-arm it. Use Fill for a line that has
// styled spans inside it.
func (p Painter) Text(s string) string {
	if s == "" || p.prefix == "" {
		return s
	}
	if !p.simple {
		return p.style.Render(s)
	}
	// lipgloss's short reset (ESC[m), not ESC[0m: equivalent to a terminal, but
	// the disasm selection bar re-arms itself by substituting the resets it finds,
	// so the spelling has to be the one it expects.
	return p.prefix + s + "\x1b[m"
}

// Fill applies the painter's colour across every line of s, padding each to w
// columns and re-arming the colour after the per-span resets inside it, so the
// fill survives the styles nested in the line. A painter that adds nothing
// returns s unchanged.
func (p Painter) Fill(s string, w int) string {
	if p.prefix == "" {
		return s
	}
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if w > 0 && lipgloss.Width(line) != w {
			line = PadRight(line, w)
		}
		line = strings.ReplaceAll(line, "\x1b[0m", "\x1b[0m"+p.prefix)
		line = strings.ReplaceAll(line, "\x1b[m", "\x1b[m"+p.prefix)
		lines[i] = p.prefix + line + "\x1b[0m"
	}
	return strings.Join(lines, "\n")
}

// RenderStyle is Fill with the painter built on the spot, for callers that do
// not hold one. It skips NewPainter's probe render: Fill never consults `simple`,
// so paying for it here would make this path cost two lipgloss renders instead
// of the one it always cost.
func RenderStyle(s string, w int, st lipgloss.Style) string {
	return Painter{prefix: StylePrefix(st)}.Fill(s, w)
}
