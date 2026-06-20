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

const settingsFieldCount = 4

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
	}
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
	path, err := config.Save(effectiveThemeName(m.cfg.Theme), m.cfg.Behavior.Background, m.cfg.Behavior.DefaultWrap, m.cfg.Behavior.DefaultView)
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
	fields := [settingsFieldCount]struct{ label, val string }{
		{"Theme", themeVal},
		{"Background", bgVal},
		{"Default wrap", wrapVal},
		{"Default view", dv},
	}

	const rowW = 44
	var b strings.Builder
	b.WriteString(m.theme.modalTitle("Settings"))
	b.WriteString("\n\n")
	for i, f := range fields {
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
	b.WriteString(m.theme.modalHint("↑/↓ field · ←/→ change · Enter save · Esc cancel"))
	return m.theme.modalStyle.Render(b.String())
}
