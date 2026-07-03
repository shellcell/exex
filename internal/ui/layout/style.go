package layout

import (
	"strings"

	"charm.land/lipgloss/v2"
)

// StylePrefix returns the leading SGR sequence a lipgloss style emits (its "open"
// codes), or "" when the style adds no styling.
func StylePrefix(st lipgloss.Style) string {
	sample := st.Render("x")
	i := strings.IndexByte(sample, 'x')
	if i <= 0 {
		return ""
	}
	return sample[:i]
}

// RenderStyle applies st as a full-width background to every line of s: each line
// is padded to w columns and wrapped in st's SGR so the colour fills the row and
// survives the per-span resets inside it. A style that adds nothing returns s
// unchanged.
func RenderStyle(s string, w int, st lipgloss.Style) string {
	prefix := StylePrefix(st)
	if prefix == "" {
		return s
	}
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if w > 0 && lipgloss.Width(line) != w {
			line = PadRight(line, w)
		}
		line = strings.ReplaceAll(line, "\x1b[0m", "\x1b[0m"+prefix)
		line = strings.ReplaceAll(line, "\x1b[m", "\x1b[m"+prefix)
		lines[i] = prefix + line + "\x1b[0m"
	}
	return strings.Join(lines, "\n")
}
