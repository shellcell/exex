package ui

// The settings popup edits a few preferences live: the colour theme, the
// view-background toggle, default wrap and the startup default view. Changes
// apply immediately; Enter persists them to the config file (preserving the rest
// of it), or warns and keeps them for the session when the file isn't writable.

import (
	"fmt"
	"strconv"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/rabarbra/exex/internal/config"
	"github.com/rabarbra/exex/internal/syntax"
	"github.com/rabarbra/exex/internal/theme"
	"github.com/rabarbra/exex/internal/ui/layout"
	"github.com/rabarbra/exex/internal/ui/views/hexraw"
)

const settingsFieldCount = 16

// settingsMeta describes one setting for display: which group it belongs to (so
// the modal can draw section headers), its label and a one-line explanation. The
// slice order matches the settingsCur / cycleSetting case index, and groups are
// contiguous so a header is drawn once per block.
type settingsMeta struct {
	group, label, desc string
}

var settingsMetas = [settingsFieldCount]settingsMeta{
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

// settingsDisasmTargets is the cycle for the "Disasm target" setting.
var settingsDisasmTargets = []string{"entry", "main", "start", "text", "lowest"}

// settingsGroupLead reports whether field i begins a new group (so its header
// row is drawn before it).
func settingsGroupLead(i int) bool {
	return i == 0 || settingsMetas[i].group != settingsMetas[i-1].group
}

// settingsRowHeight is the rendered height of field i for the scroll geometry:
// the value row, plus a header line when it leads a group, plus a blank
// separator before every group but the first.
func settingsRowHeight(i int) int {
	h := 1
	if settingsGroupLead(i) {
		h++ // group header
		if i != 0 {
			h++ // blank separator above the group
		}
	}
	return h
}

// settingsViewNames is the cycle for the "default view" setting.
var settingsViewNames = []string{
	"info", "sections", "symbols", "disasm", "hex", "raw", "strings", "libs", "sources",
}

// settingsThemeList is the cycle for the "theme" setting: the built-in names
// first, then every Chroma style.
func settingsThemeList() []string {
	out := []string{defaultThemeName, "dark", "solarized-dark", "solarized-light"}
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

func (m *Model) openSettings() {
	m.settingsActive = true
	m.settingsCur = 0
	m.settingsTop = 0
}

func (m *Model) closeSettings() { m.settingsActive = false }

func (m *Model) updateSettings(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc", ",":
		m.closeSettings()
	case "up", "k":
		m.settingsCur = (m.settingsCur + settingsFieldCount - 1) % settingsFieldCount
	case "down", "j", "tab":
		m.settingsCur = (m.settingsCur + 1) % settingsFieldCount
	case "left", "h":
		m.cycleSetting(-1)
	case "right", "l", " ":
		m.cycleSetting(1)
	case "enter":
		m.persistSettings()
	}
	return m, nil
}

func (m *Model) cycleSetting(dir int) {
	// Several settings below are baked into the cached view styles; rebuild it
	// from the post-change values on the next frame.
	m.viewStylesCache = nil
	switch m.settingsCur {
	case 0:
		list := settingsThemeList()
		m.cfg.Theme = list[cycleIndex(list, m.cfg.Theme, dir)]
		m.applyThemeChange()
	case 1:
		m.cfg.Behavior.Background = !m.cfg.Behavior.Background
		m.applyThemeChange()
	case 2:
		m.cfg.Behavior.DefaultWrap = !m.cfg.Behavior.DefaultWrap
		m.wrap = m.cfg.Behavior.DefaultWrap
		m.clearAllViewCaches()
	case 3:
		m.cfg.Behavior.DefaultView = settingsViewNames[cycleIndex(settingsViewNames, m.cfg.Behavior.DefaultView, dir)]
	case 4:
		t := settingsDisasmTargets[cycleIndex(settingsDisasmTargets, m.cfg.Behavior.DefaultDisasmTarget, dir)]
		m.cfg.Behavior.DefaultDisasmTarget = t
		m.disasmTarget = t // future default landings / redirects use the new strategy
	case 5:
		m.cfg.Behavior.TreeSymbols = !m.cfg.Behavior.TreeSymbols
		m.symbols.Tree = m.cfg.Behavior.TreeSymbols
		m.symbols.Recompute(m.viewContext())
	case 6:
		m.cfg.Behavior.TreeSources = !m.cfg.Behavior.TreeSources
		m.sources.Tree = m.cfg.Behavior.TreeSources
		if m.sources.Files != nil {
			m.sources.Recompute(m.viewContext())
		}
	case 7:
		m.cfg.Behavior.TreeLibs = !m.cfg.Behavior.TreeLibs
		m.libs.Tree = m.cfg.Behavior.TreeLibs
		m.libs.BuildRows(m.viewContext())
	case 8:
		m.cfg.Behavior.TreeCollapsed = !m.cfg.Behavior.TreeCollapsed
		m.treeCollapseDefault = m.cfg.Behavior.TreeCollapsed
		// Apply live to whichever trees are currently shown.
		m.symbols.SetAllCollapsed(m.treeCollapseDefault)
		m.sources.SetAllCollapsed(m.viewContext(), m.treeCollapseDefault)
		m.libs.SetAllCollapsed(m.viewContext(), m.treeCollapseDefault)
	case 9:
		m.cfg.Behavior.AbbrevArgs = !m.cfg.Behavior.AbbrevArgs
		m.symbols.SetAbbrevAll(m.cfg.Behavior.AbbrevArgs)
		m.clearSymbolNameCaches()
	case 10:
		m.toggleDemangle() // flips cfg.Behavior.NoDemangle and re-applies/clears live
	case 11:
		m.cfg.Behavior.HideDisasmBytes = !m.cfg.Behavior.HideDisasmBytes
		m.clearDisasmDisplayCaches()
	case 12:
		m.cfg.Behavior.HideAnnotations = !m.cfg.Behavior.HideAnnotations
		m.clearDisasmDisplayCaches()
	case 13:
		m.cfg.Behavior.SpacedDisasmBytes = !m.cfg.Behavior.SpacedDisasmBytes
		m.clearDisasmDisplayCaches()
	case 14:
		m.cfg.Behavior.CompactAddresses = !m.cfg.Behavior.CompactAddresses
		m.file.SetCompactAddr(m.cfg.Behavior.CompactAddresses)
		// The address column width changes in every view, so drop the row/height
		// caches (which key on the width) and force a redraw.
		m.clearAllViewCaches()
		m.clearDisasmDisplayCaches()
		m.viewDirty = true
	case 15:
		m.cfg.Behavior.HexBytesPerRow = cycleHexBytesPerRow(m.cfg.Behavior.HexBytesPerRow, dir)
		// Re-snap the scroll anchors to the new row width and redraw (Hex/Raw render
		// uncached, so nothing else to invalidate).
		m.byteViews.SnapTops(hexraw.BytesPerRow(m.viewContextPtr()))
		m.viewDirty = true
	}
}

// cycleHexBytesPerRow steps the bytes-per-row preference through 8 → 16 → 32.
func cycleHexBytesPerRow(cur, dir int) int {
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

// clearDisasmDisplayCaches drops the caches whose geometry/content depends on the
// disasm byte-column and annotation settings, so a toggle shows immediately. The
// hex view is rendered uncached, so it needs no clear.
func (m *Model) clearDisasmDisplayCaches() {
	m.disasmHeightCache = nil
	m.sourceAsmRowCache = nil
}

// cycleIndex returns the index of cur in list stepped by dir (wrapping); a value
// not in the list is treated as index 0.
func cycleIndex(list []string, cur string, dir int) int {
	i := 0
	for j, v := range list {
		if strings.EqualFold(v, cur) {
			i = j
			break
		}
	}
	return (i + dir + len(list)) % len(list)
}

// applyThemeChange rebuilds the theme (and source highlighter) from the live
// config and drops the colour-dependent caches so the change shows immediately.
func (m *Model) applyThemeChange() {
	m.theme = NewTheme(m.cfg)
	m.srcHighlighter = syntax.NewHighlighter(sourceSyntaxTheme(m.cfg))
	m.clearColorCaches()
	m.viewDirty = true
}

func (m *Model) persistSettings() {
	path, err := config.Save(effectiveThemeName(m.cfg.Theme), m.cfg.Behavior)
	if err != nil {
		m.setStatus(fmt.Sprintf("settings applied for this session (not saved: %v)", err), true)
	} else {
		m.setStatus("settings saved to "+path, false)
	}
	m.closeSettings()
}

// settingsValue returns field i's current value as a display string.
func (m *Model) settingsValue(i int) string {
	onOff := func(b bool) string {
		if b {
			return "on"
		}
		return "off"
	}
	switch i {
	case 0:
		if m.cfg.Theme == "" {
			return defaultThemeName
		}
		return m.cfg.Theme
	case 1:
		return onOff(m.cfg.Behavior.Background)
	case 2:
		return onOff(m.cfg.Behavior.DefaultWrap)
	case 3:
		if m.cfg.Behavior.DefaultView == "" {
			return "info"
		}
		return m.cfg.Behavior.DefaultView
	case 4:
		if m.cfg.Behavior.DefaultDisasmTarget == "" {
			return "lowest"
		}
		return m.cfg.Behavior.DefaultDisasmTarget
	case 5:
		return onOff(m.cfg.Behavior.TreeSymbols)
	case 6:
		return onOff(m.cfg.Behavior.TreeSources)
	case 7:
		return onOff(m.cfg.Behavior.TreeLibs)
	case 8:
		return onOff(m.cfg.Behavior.TreeCollapsed)
	case 9:
		return onOff(m.cfg.Behavior.AbbrevArgs)
	case 10:
		return onOff(!m.cfg.Behavior.NoDemangle)
	case 11:
		return onOff(!m.cfg.Behavior.HideDisasmBytes)
	case 12:
		return onOff(!m.cfg.Behavior.HideAnnotations)
	case 13:
		if m.cfg.Behavior.SpacedDisasmBytes {
			return "spaced"
		}
		return "compact"
	case 14:
		if m.cfg.Behavior.CompactAddresses {
			return "compact"
		}
		return "full"
	case 15:
		return strconv.Itoa(hexraw.BytesPerRow(m.viewContextPtr()))
	}
	return ""
}

func (m *Model) renderSettingsModal() string {
	const labelW, valW = 17, 16 // label column, then "‹ value ›"
	leftW := labelW + valW + 6  // " label ‹ value ›" full control width
	showDesc := m.width >= 84   // drop the description column on narrow terminals

	// Window the field list to the terminal height (title/hint/border cost ~8
	// rows) so the popup never overruns a short window; the selection stays
	// visible as it scrolls. The budget is counted in rendered lines, which
	// include the per-group headers and separators (settingsRowHeight).
	total := 0
	for i := range settingsFieldCount {
		total += settingsRowHeight(i)
	}
	visible := layout.Clamp(m.height-8, 5, total)
	top := layout.VisualTop(m.settingsCur, m.settingsTop, settingsFieldCount, visible, settingsRowHeight)
	m.settingsTop = top
	m.modalListRow = 2 // title(0) + blank(1) → list starts at content row 2

	desc := func(s string) string { return m.theme.srcShadowStyle.Render(s) }
	group := func(s string) string { return m.theme.symbolNameStyle.Render(strings.ToUpper(s)) }

	var b strings.Builder
	b.WriteString(m.theme.modalTitle("Settings"))
	b.WriteString("\n\n")

	m.settingsLineFields = m.settingsLineFields[:0]
	emit := func(line string, field int) {
		b.WriteString(line)
		b.WriteByte('\n')
		m.settingsLineFields = append(m.settingsLineFields, field)
	}
	used := 0
	for i := top; i < settingsFieldCount; i++ {
		h := settingsRowHeight(i)
		if i == top && settingsGroupLead(i) && i != 0 {
			h-- // the leading blank separator is suppressed at the window top
		}
		if used+h > visible {
			break
		}
		used += h
		if settingsGroupLead(i) {
			if i != top && i != 0 {
				emit("", -1) // blank separator above the group
			}
			emit("  "+group(settingsMetas[i].group), -1)
		}
		left := fmt.Sprintf(" %-*s ‹ %-*s ›", labelW, settingsMetas[i].label, valW, m.settingsValue(i))
		left = layout.PadRight(left, leftW)
		if i == m.settingsCur {
			left = m.theme.tableSelStyle.Render(left)
		}
		row := left
		if showDesc {
			row += "  " + desc(settingsMetas[i].desc)
		}
		emit(row, i)
	}

	b.WriteString("\n")
	hint := "↑/↓ field · ←/→ change · Enter save · Esc cancel"
	if visible < total {
		hint += fmt.Sprintf("   (%d/%d)", m.settingsCur+1, settingsFieldCount)
	}
	b.WriteString(m.theme.modalHint(hint))
	return m.theme.modalStyle.Render(b.String())
}
