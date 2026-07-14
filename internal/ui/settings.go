package ui

// The settings popup edits a few preferences live: the colour theme, the
// view-background toggle, default wrap and the startup default view. Changes
// apply immediately; Enter persists them to the config file (preserving the rest
// of it), or warns and keeps them for the session when the file isn't writable.
//
// The overlay itself lives in internal/ui/modals/settings. What stays here is
// what a change *means*: cycling a field rewrites m.cfg and then reaches across
// the shell — rebuilding the theme, re-sorting a view, dropping row caches. That
// blast radius is the shell's, so the overlay asks for it through settings.Host.

import (
	"fmt"
	"strconv"

	"github.com/shellcell/exex/internal/config"
	"github.com/shellcell/exex/internal/syntax"
	settingsmodal "github.com/shellcell/exex/internal/ui/modals/settings"
	"github.com/shellcell/exex/internal/ui/views/hexraw"
)

func (m *Model) openSettings() { m.settings.Open() }

// CycleSetting steps field i by dir and applies the change. It satisfies
// settings.Host; the index is the position in settings.Metas.
func (m *Model) CycleSetting(i, dir int) {
	// Several settings below are baked into the cached view styles; rebuild it
	// from the post-change values on the next frame.
	m.viewStylesCache = nil
	switch i {
	case 0:
		list := settingsmodal.ThemeList(defaultThemeName)
		m.cfg.Theme = list[settingsmodal.CycleIndex(list, m.cfg.Theme, dir)]
		m.applyThemeChange()
	case 1:
		m.cfg.Behavior.Background = !m.cfg.Behavior.Background
		m.applyThemeChange()
	case 2:
		m.cfg.Behavior.DefaultWrap = !m.cfg.Behavior.DefaultWrap
		m.wrap = m.cfg.Behavior.DefaultWrap
		m.clearAllViewCaches()
	case 3:
		m.cfg.Behavior.DefaultView = settingsmodal.ViewNames[settingsmodal.CycleIndex(settingsmodal.ViewNames, m.cfg.Behavior.DefaultView, dir)]
	case 4:
		t := settingsmodal.DisasmTargets[settingsmodal.CycleIndex(settingsmodal.DisasmTargets, m.cfg.Behavior.DefaultDisasmTarget, dir)]
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
		m.cfg.Behavior.HexBytesPerRow = settingsmodal.CycleHexBytesPerRow(m.cfg.Behavior.HexBytesPerRow, dir)
		// Re-snap the scroll anchors to the new row width and redraw (Hex/Raw render
		// uncached, so nothing else to invalidate).
		m.byteViews.SnapTops(hexraw.BytesPerRow(m.viewContextPtr()))
		m.viewDirty = true
	}
}

// clearDisasmDisplayCaches drops the caches whose geometry/content depends on the
// disasm byte-column and annotation settings, so a toggle shows immediately. The
// hex view is rendered uncached, so it needs no clear.
func (m *Model) clearDisasmDisplayCaches() {
	m.dasm.HeightCache = nil
	m.dasm.AnnCache = nil
	m.dasm.SourceAsmRowCache = nil
}

// applyThemeChange rebuilds the theme (and source highlighter) from the live
// config and drops the colour-dependent caches so the change shows immediately.
func (m *Model) applyThemeChange() {
	m.theme = NewTheme(m.cfg)
	m.srcHighlighter = syntax.NewHighlighter(sourceSyntaxTheme(m.cfg))
	m.clearColorCaches()
	m.viewDirty = true
}

// PersistSettings saves the live config, reporting the outcome. It satisfies
// settings.Host; closing the overlay is the overlay's own business.
func (m *Model) PersistSettings() {
	path, err := config.Save(effectiveThemeName(m.cfg.Theme), m.cfg.Behavior)
	if err != nil {
		m.setStatus(fmt.Sprintf("settings applied for this session (not saved: %v)", err), true)
		return
	}
	m.setStatus("settings saved to "+path, false)
}

// SettingValue returns field i's current value as a display string. It satisfies
// settings.Host; the index is the position in settings.Metas.
func (m *Model) SettingValue(i int) string {
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
