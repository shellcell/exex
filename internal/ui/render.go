package ui

// Presentation glue that still needs the Model or Theme: hex byte rendering,
// path colouring, themed background/title styling, and the modal overlay
// compositor. The Model-independent geometry — padding, truncation, line
// wrapping with hanging indent, and the scroll-window math — lives in the
// internal/ui/layout package; this file wires it into the themed UI.

import (
	"strings"

	"charm.land/lipgloss/v2"

	"github.com/rabarbra/exex/internal/ui/layout"
)

// bytesHex renders up to maxN bytes as compact, per-byte-coloured hex.
// The output is padded with plain spaces to a fixed visible width so columns
// line up regardless of how many bytes the instruction occupied. Uses the
// precomputed byteHex table to avoid re-rendering ANSI codes on every byte.
func bytesHex(b []byte, maxN int) string {
	if len(b) > maxN {
		b = b[:maxN]
	}
	var sb strings.Builder
	for _, x := range b {
		sb.WriteString(byteHex[x])
	}
	visible := len(b) * 2
	want := maxN * 2
	if visible < want {
		sb.WriteString(strings.Repeat(" ", want-visible))
	}
	return sb.String()
}

// bytesHexSpaced is bytesHex with a space between bytes ("01 00 00 14"), padded
// to the maxN-byte column width (maxN*3-1). Used when behavior.spaced_disasm_bytes
// is on, matching the `-o disasm` dump.
func bytesHexSpaced(b []byte, maxN int) string {
	if len(b) > maxN {
		b = b[:maxN]
	}
	var sb strings.Builder
	for i, x := range b {
		if i > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(byteHex[x])
	}
	want := max(0, maxN*3-1)
	if visible := max(0, len(b)*3-1); visible < want {
		sb.WriteString(strings.Repeat(" ", want-visible))
	}
	return sb.String()
}

// emptyBody centres a dim message in the whole body area, for a view that has no
// entries at all (no filter/header rows to keep).
func (m *Model) emptyBody(msg string) string {
	return m.viewContext().EmptyBody(msg)
}

// wrapStatus returns the footer label for the current wrap setting.
func wrapStatus(on bool) string {
	if on {
		return "wrap: on"
	}
	return "wrap: off"
}

// colorPathByPrefix renders display in a single colour chosen from keyPath's
// directory prefix, so paths sharing a directory share a colour. keyPath is the
// full path (used only for the colour key); display is what's drawn — which may
// be a middle-truncated form of the same path. The palette comes from the theme,
// so path colouring follows the active preset.
func (t *Theme) colorPathByPrefix(keyPath, display string) string {
	if display == "" {
		return display
	}
	return t.pathPrefixStyle(pathColorKey(keyPath)).Render(display)
}

// pathColorKey reduces a path to a coarse grouping key: at most its first two
// directory components. This keeps whole subtrees (e.g. everything under
// /usr/lib) one colour instead of giving every leaf directory its own.
func pathColorKey(p string) string {
	segs := strings.Split(strings.Trim(p, "/"), "/")
	// Drop the filename (last segment) so siblings group together — bare names
	// with no directory then all share one colour — and keep up to the first two
	// directory components.
	if len(segs) > 0 {
		segs = segs[:len(segs)-1]
	}
	if len(segs) > 2 {
		segs = segs[:2]
	}
	return strings.Join(segs, "/")
}

// pathPrefixStyle deterministically maps a path prefix to one of the theme's
// path-palette styles.
func (t *Theme) pathPrefixStyle(prefix string) lipgloss.Style {
	if len(t.pathPalette) == 0 {
		return lipgloss.NewStyle()
	}
	h := 0
	for i := 0; i < len(prefix); i++ {
		h = h*33 + int(prefix[i])
	}
	if h < 0 {
		h = -h
	}
	return t.pathPalette[h%len(t.pathPalette)]
}

func (t Theme) renderViewBackground(s string, w int) string {
	return renderBackground(s, w, t.viewStyle)
}

func renderBackground(s string, w int, st lipgloss.Style) string {
	return layout.RenderStyle(s, w, st)
}

func (t Theme) viewTitleLine(s string, w int) string {
	return renderBackground(layout.PadRight(layout.FitANSIWidth(s, w), w), w, t.tableHeaderStyle)
}

func (t Theme) stickyTitleLine(s string, w int) string {
	return renderBackground(layout.PadRight(layout.FitANSIWidth(s, w), w), w, t.stickySymStyle)
}

// tableHeader renders a full-width table header line.
func (m *Model) tableHeader(s string) string {
	return m.viewContext().TableHeader(s)
}

// visualTopForView respects detached viewport state when computing list top.
func (m *Model) visualTopForView(cur, top, n, visible int, rowHeight func(int) int) int {
	return m.viewContext().VisualTop(cur, top, n, visible, rowHeight)
}

// The scroll/viewport geometry (VisualTop, …) and the modal Overlay compositor
// live in the dependency-free internal/ui/layout package.
