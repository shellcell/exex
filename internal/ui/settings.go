package ui

// The settings popup edits a few preferences live: the colour theme, the
// view-background toggle, default wrap and the startup default view. Changes
// apply immediately; Enter persists them to the config file (preserving the rest
// of it), or warns and keeps them for the session when the file isn't writable.

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/rabarbra/exex/internal/config"
	"github.com/rabarbra/exex/internal/syntax"
	"github.com/rabarbra/exex/internal/theme"
)

const settingsFieldCount = 12

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
		m.cfg.Behavior.TreeSymbols = !m.cfg.Behavior.TreeSymbols
		m.symbolsTree = m.cfg.Behavior.TreeSymbols
		m.recomputeSymbols()
	case 5:
		m.cfg.Behavior.TreeSources = !m.cfg.Behavior.TreeSources
		m.sourcesTree = m.cfg.Behavior.TreeSources
		if m.sourcesFiles != nil {
			m.recomputeSourceFiles()
		}
	case 6:
		m.cfg.Behavior.TreeLibs = !m.cfg.Behavior.TreeLibs
		m.libsTree = m.cfg.Behavior.TreeLibs
		m.buildLibRows()
	case 7:
		m.cfg.Behavior.TreeCollapsed = !m.cfg.Behavior.TreeCollapsed
		m.treeCollapseDefault = m.cfg.Behavior.TreeCollapsed
		// Apply live to whichever trees are currently shown.
		m.setAllSymbolsCollapsed(m.treeCollapseDefault)
		m.setAllSourcesCollapsed(m.treeCollapseDefault)
		m.setAllLibsCollapsed(m.treeCollapseDefault)
	case 8:
		m.cfg.Behavior.AbbrevArgs = !m.cfg.Behavior.AbbrevArgs
		m.symbolsAbbrev = m.cfg.Behavior.AbbrevArgs
		m.symbolsAbbrevExcept = nil
		m.clearSymbolCaches()
		m.clearSymbolNameCaches()
	case 9:
		m.cfg.Behavior.HideDisasmBytes = !m.cfg.Behavior.HideDisasmBytes
		m.clearDisasmDisplayCaches()
	case 10:
		m.cfg.Behavior.HideAnnotations = !m.cfg.Behavior.HideAnnotations
		m.clearDisasmDisplayCaches()
	case 11:
		m.cfg.Behavior.SpacedDisasmBytes = !m.cfg.Behavior.SpacedDisasmBytes
		m.clearDisasmDisplayCaches()
	}
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

func (m *Model) renderSettingsModal() string {
	themeVal := m.cfg.Theme
	if themeVal == "" {
		themeVal = defaultThemeName
	}
	bgVal := "off"
	if m.cfg.Behavior.Background {
		bgVal = "on"
	}
	wrapVal := "off"
	if m.cfg.Behavior.DefaultWrap {
		wrapVal = "on"
	}
	dv := m.cfg.Behavior.DefaultView
	if dv == "" {
		dv = "info"
	}
	onOff := func(b bool) string {
		if b {
			return "on"
		}
		return "off"
	}
	byteSpacing := "compact"
	if m.cfg.Behavior.SpacedDisasmBytes {
		byteSpacing = "spaced"
	}
	fields := [settingsFieldCount]struct{ label, val string }{
		{"Theme", themeVal},
		{"Background", bgVal},
		{"Default wrap", wrapVal},
		{"Default view", dv},
		{"Tree: symbols", onOff(m.cfg.Behavior.TreeSymbols)},
		{"Tree: sources", onOff(m.cfg.Behavior.TreeSources)},
		{"Tree: libs", onOff(m.cfg.Behavior.TreeLibs)},
		{"Tree collapsed", onOff(m.cfg.Behavior.TreeCollapsed)},
		{"Abbrev args", onOff(m.cfg.Behavior.AbbrevArgs)},
		{"Disasm bytes", onOff(!m.cfg.Behavior.HideDisasmBytes)},
		{"Annotations", onOff(!m.cfg.Behavior.HideAnnotations)},
		{"Byte spacing", byteSpacing},
	}

	const rowW = 44
	// Window the field list to the terminal height (title/hint/border cost ~8
	// rows) so the popup never overruns a short window; the selection stays
	// visible as it scrolls.
	visible := clamp(m.height-8, 3, settingsFieldCount)
	top := visualTop(m.settingsCur, m.settingsTop, settingsFieldCount, visible, func(int) int { return 1 })
	m.settingsTop = top
	end := min(top+visible, settingsFieldCount)

	var b strings.Builder
	b.WriteString(m.theme.modalTitle("Settings"))
	b.WriteString("\n\n")
	for i := top; i < end; i++ {
		f := fields[i]
		row := fmt.Sprintf(" %-13s ‹ %s ›", f.label+":", f.val)
		if i == m.settingsCur {
			row = m.theme.tableSelStyle.Render(padRight(row, rowW))
		} else {
			row = padRight(row, rowW)
		}
		b.WriteString(row)
		b.WriteString("\n")
	}
	b.WriteString("\n")
	hint := "↑/↓ field · ←/→ change · Enter save · Esc cancel"
	if visible < settingsFieldCount {
		hint = fmt.Sprintf("↑/↓ field · ←/→ change · Enter save · Esc cancel   (%d/%d)", m.settingsCur+1, settingsFieldCount)
	}
	b.WriteString(m.theme.modalHint(hint))
	return m.theme.modalStyle.Render(b.String())
}
