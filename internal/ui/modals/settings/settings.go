// Package settings is the settings overlay: a scrollable list of preferences
// grouped under headings, cycled left/right, applied live, and saved on Enter.
//
// The overlay owns the field table, the scroll geometry, the key handling and
// the row→field mapping its mouse hit-test needs. What it does *not* own is what
// a change means: cycling "Symbols as tree" has to rebuild the symbols view,
// "Address width" invalidates every row cache, and "Theme" rebuilds the whole
// palette. Those effects reach across the entire shell, so they stay there and
// this package reaches them through Host.
package settings

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/rabarbra/exex/internal/theme"
	"github.com/rabarbra/exex/internal/ui/layout"
	"github.com/rabarbra/exex/internal/ui/modal"
)

// FieldCount is the number of settings rows; it must match the Metas table and
// the shell's CycleSetting switch.
const FieldCount = 16

// Meta describes one setting for display: which group it belongs to (so the
// modal can draw section headers), its label and a one-line explanation. The
// slice order matches the field index, and groups are contiguous so a header is
// drawn once per block.
type Meta struct {
	Group, Label, Desc string
}

var Metas = [FieldCount]Meta{
	{"Appearance", "Theme", "colour palette for the whole UI"},
	{"Appearance", "Panel background", "solid fill behind the view panels"},
	{"Appearance", "Wrap long lines", "soft-wrap rows wider than the window"},
	{"Startup", "Open in view", "the view shown when a file loads"},
	{"Startup", "Disasm target", "where Disasm lands: entry/main/start/text/lowest"},
	{"Lists & trees", "Symbols as tree", "group symbols by their source path"},
	{"Lists & trees", "Sources as tree", "nest source files into folders"},
	{"Lists & trees", "Libraries as tree", "group libraries by directory"},
	{"Lists & trees", "Start collapsed", "open trees folded to the top level"},
	{"Symbols & names", "Abbreviate args", "shorten long demangled signatures"},
	{"Symbols & names", "Demangle symbols", "show foo::bar() vs raw _ZN3foo…"},
	{"Disassembly", "Show raw bytes", "the machine-code byte column"},
	{"Disassembly", "Show annotations", "inline target, reloc & string notes"},
	{"Disassembly", "Byte spacing", "space-separated vs packed bytes"},
	{"Addresses & hex", "Address width", "narrow 64-bit addrs when the top half is 0"},
	{"Addresses & hex", "Hex bytes / row", "bytes per row in the Hex & Raw views"},
}

// DisasmTargets is the cycle for the "Disasm target" setting.
var DisasmTargets = []string{"entry", "main", "start", "text", "lowest"}

// ViewNames is the cycle for the "Open in view" setting.
var ViewNames = []string{
	"info", "sections", "symbols", "disasm", "hex", "raw", "strings", "libs", "sources",
}

// ThemeList is the cycle for the "Theme" setting: the four built-in names first,
// then every curated Chroma style.
//
// theme.Names() is generated from the same manifest that decides which style
// XMLs get embedded, so every entry here has a real highlighter behind it. The
// three built-ins that are also Chroma styles (nord, solarized-dark,
// solarized-light) are deduplicated so they appear once, as built-ins.
func ThemeList(defaultTheme string) []string {
	out := []string{defaultTheme, "dark", "solarized-dark", "solarized-light"}
	seen := map[string]bool{}
	for _, n := range out {
		seen[n] = true
	}
	for _, n := range theme.Names() {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

// CycleIndex returns the index of cur in list stepped by dir (wrapping); a value
// not in the list is treated as index 0.
func CycleIndex(list []string, cur string, dir int) int {
	i := 0
	for j, v := range list {
		if strings.EqualFold(v, cur) {
			i = j
			break
		}
	}
	return (i + dir + len(list)) % len(list)
}

// CycleHexBytesPerRow steps the bytes-per-row preference through 8 → 16 → 32.
func CycleHexBytesPerRow(cur, dir int) int {
	steps := []int{8, 16, 32}
	i := 1 // default 16
	for j, v := range steps {
		if v == cur {
			i = j
			break
		}
	}
	return steps[(i+dir+len(steps))%len(steps)]
}

// GroupLead reports whether field i begins a new group (so its header row is
// drawn before it).
func GroupLead(i int) bool {
	return i == 0 || Metas[i].Group != Metas[i-1].Group
}

// RowHeight is the rendered height of field i for the scroll geometry: the value
// row, plus a header line when it leads a group, plus a blank separator before
// every group but the first.
func RowHeight(i int) int {
	h := 1
	if GroupLead(i) {
		h++ // group header
		if i != 0 {
			h++ // blank separator above the group
		}
	}
	return h
}

// Host is what the settings overlay needs from the shell. It is wider than
// modal.Host because reading and applying a setting touches shell state the
// overlay must not own.
type Host interface {
	modal.Host
	// SettingValue returns field i's current value as a display string.
	SettingValue(i int) string
	// CycleSetting steps field i by dir and applies the change across the shell.
	CycleSetting(i, dir int)
	// PersistSettings writes the config file and reports the outcome via
	// SetStatus. It does not close the overlay; the caller does.
	PersistSettings()
}

// State is the settings overlay. The zero value is closed.
type State struct {
	active bool
	cur    int // selected field index (0..FieldCount-1)
	top    int // first visible field when the list is taller than the window

	// lineFields maps each rendered list line (from ListRow) to its field index,
	// or -1 for group headers and blank separators. Rebuilt every Render, because
	// the mapping depends on the scroll position and the terminal height.
	lineFields []int
	listRow    int
}

func (s *State) Open()        { s.active, s.cur, s.top = true, 0, 0 }
func (s *State) Close()       { s.active = false }
func (s *State) Active() bool { return s.active }
func (s *State) ListRow() int { return s.listRow }

// Cur returns the selected field index.
func (s *State) Cur() int { return s.cur }

// SetCur selects a field directly (used by tests and the mouse hit-test).
func (s *State) SetCur(i int) { s.cur = layout.Clamp(i, 0, FieldCount-1) }

// List exposes the field list to the shell's shared mouse handling. Selection
// wraps: the settings list cycles top-to-bottom, unlike the flat result lists.
func (s *State) List() (sel *int, top, n int, wrap, ok bool) {
	return &s.cur, s.top, FieldCount, true, true
}

// ClickRow selects the field on a clicked content row. Rows do not map 1:1 to
// fields — group headers and separators are interleaved — so the row→field
// mapping recorded during Render is consulted instead of modal.ClickIndex.
func (s *State) ClickRow(listRow int) bool {
	if listRow < 0 || listRow >= len(s.lineFields) {
		return false
	}
	if f := s.lineFields[listRow]; f >= 0 {
		s.cur = f
		return true
	}
	return false
}

// Update handles one keypress.
func (s *State) Update(host Host, key string) tea.Cmd {
	switch key {
	case "esc", ",":
		s.Close()
	case "up", "k":
		s.cur = (s.cur + FieldCount - 1) % FieldCount
	case "down", "j", "tab":
		s.cur = (s.cur + 1) % FieldCount
	case "left", "h":
		host.CycleSetting(s.cur, -1)
	case "right", "l", " ":
		host.CycleSetting(s.cur, 1)
	case "enter":
		host.PersistSettings()
		s.Close()
	}
	return nil
}

// Activate is the mouse double-click action: step the selected field forward.
func (s *State) Activate(host Host) tea.Cmd {
	host.CycleSetting(s.cur, 1)
	return nil
}

// Column geometry. The value sits *between* its arrows — padding the value out
// to a fixed width instead left the ‹ › fourteen columns apart on "off", which
// read as a divider rather than as a control. The whole ‹ value › block is
// padded instead, so the arrows hug the value and the description column still
// lines up.
const (
	labelW   = 17       // widest label ("Libraries as tree")
	valW     = 20       // widest value ("catppuccin-macchiato")
	controlW = valW + 4 // "‹ " + value + " ›"
	leftW    = 1 + labelW + 2 + controlW
	minDescW = 24 // below this a description is more distracting than useful

	// modalChrome is the border + horizontal padding the frame adds around the
	// content, which the content must leave room for or the overlay overruns the
	// terminal. The old layout could: a 20-character theme name overflowed a
	// 16-wide value column and pushed its description off the right edge.
	modalChrome = 6
)

func (s *State) Render(ctx modal.Context, host Host) string {
	descW := ctx.Width - modalChrome - leftW - 2
	showDesc := descW >= minDescW // drop the description column on narrow terminals

	// Window the field list to the terminal height (title/hint/border cost ~8
	// rows) so the popup never overruns a short window; the selection stays
	// visible as it scrolls. The budget is counted in rendered lines, which
	// include the per-group headers and separators (RowHeight).
	total := 0
	for i := range FieldCount {
		total += RowHeight(i)
	}
	visible := layout.Clamp(ctx.Height-8, 5, total)
	s.top = layout.VisualTop(s.cur, s.top, FieldCount, visible, RowHeight)
	s.listRow = 2 // title(0) + blank(1) → list starts at content row 2

	desc := func(str string) string { return ctx.ShadowStyle.Render(str) }
	group := func(str string) string { return ctx.HeadingStyle.Render(strings.ToUpper(str)) }

	var b strings.Builder
	b.WriteString(ctx.Title("Settings"))
	b.WriteString("\n\n")

	s.lineFields = s.lineFields[:0]
	emit := func(line string, field int) {
		b.WriteString(line)
		b.WriteByte('\n')
		s.lineFields = append(s.lineFields, field)
	}
	used := 0
	for i := s.top; i < FieldCount; i++ {
		h := RowHeight(i)
		if i == s.top && GroupLead(i) && i != 0 {
			h-- // the leading blank separator is suppressed at the window top
		}
		if used+h > visible {
			break
		}
		used += h
		if GroupLead(i) {
			if i != s.top && i != 0 {
				emit("", -1) // blank separator above the group
			}
			emit("  "+group(Metas[i].Group), -1)
		}
		control := "‹ " + layout.TruncateMiddle(host.SettingValue(i), valW) + " ›"
		left := fmt.Sprintf(" %-*s  %s", labelW, Metas[i].Label, layout.PadRight(control, controlW))
		left = layout.PadRight(left, leftW)
		if i == s.cur {
			left = ctx.SelStyle.Render(left)
		}
		row := left
		if showDesc {
			row += "  " + desc(layout.TruncateMiddle(Metas[i].Desc, descW))
		}
		emit(row, i)
	}

	b.WriteString("\n")
	hint := "↑/↓ field · ←/→ change · Enter save · Esc cancel"
	if visible < total {
		hint += fmt.Sprintf("   (%d/%d)", s.cur+1, FieldCount)
	}
	b.WriteString(ctx.Hint(hint))
	return ctx.Frame(b.String())
}
