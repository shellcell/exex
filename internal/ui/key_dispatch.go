package ui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

func (m *Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	// The help overlay swallows the next keypress to dismiss itself.
	if m.helpActive {
		m.helpActive = false
		return m, nil
	}
	if m.searchRunning && key == "esc" {
		m.cancelSearch("search cancelled")
		return m, nil
	}

	if m.gotoActive {
		return m.updateGotoInput(msg, key)
	}
	if m.searchActive {
		return m.updateSearchInput(msg, key)
	}
	if cmd, done := m.captureActiveFilter(key, msg); done {
		return m, cmd
	}

	// '?' toggles the keybinding cheat-sheet (after modal/filter capture, so it
	// still types into inputs).
	if key == "?" {
		m.helpActive = true
		return m, nil
	}
	if model, cmd, ok := m.handleGlobalAction(key); ok {
		return model, cmd
	}

	key = normalizeNavKey(key)
	// Apply user key aliases (copy/next/prev) onto canonical tokens.
	if c, ok := m.keyAlias[key]; ok {
		key = c
	}
	return m.dispatchViewKey(msg, key)
}

func (m *Model) updateGotoInput(msg tea.KeyMsg, key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc":
		m.closeGoto()
		return m, nil
	case "up":
		if m.gotoSel > 0 {
			m.gotoSel--
		}
		return m, nil
	case "down":
		if m.gotoSel < len(m.gotoResults)-1 {
			m.gotoSel++
		}
		return m, nil
	case "enter":
		m.activateGoto()
		m.closeGoto()
		return m, nil
	}
	var cmd tea.Cmd
	m.gotoInput, cmd = m.gotoInput.Update(msg)
	m.recomputeGoto()
	return m, cmd
}

func (m *Model) updateSearchInput(msg tea.KeyMsg, key string) (tea.Model, tea.Cmd) {
	if c, ok := m.searchKeyAlias[key]; ok {
		key = c
	}
	switch key {
	case "esc":
		m.searchActive = false
		m.searchInput.Blur()
		return m, nil
	case "ctrl+r":
		m.searchForward = !m.searchForward
		return m, nil
	case "ctrl+o":
		m.searchFromCursor = !m.searchFromCursor
		return m, nil
	case "enter":
		m.searchQuery = strings.TrimSpace(m.searchInput.Value())
		m.searchActive = false
		m.searchInput.Blur()
		return m, m.runSearchFromPrompt()
	}
	var cmd tea.Cmd
	m.searchInput, cmd = m.searchInput.Update(msg)
	return m, cmd
}

func (m *Model) captureActiveFilter(key string, msg tea.KeyMsg) (tea.Cmd, bool) {
	// A focused filter input captures typing keys (esc/enter blur it); navigation
	// keys fall through so they still drive the list. Shared across the three
	// filterable views via filterCapture.
	switch m.mode {
	case modeSymbols:
		return filterCapture(&m.symbolsFilter, key, msg, m.recomputeSymbols)
	case modeSections:
		return filterCapture(&m.sectionsFilter, key, msg, m.recomputeSections)
	case modeSources:
		if m.srcFile == "" {
			return filterCapture(&m.sourcesFilter, key, msg, m.recomputeSourceFiles)
		}
	}
	return nil, false
}

func (m *Model) handleGlobalAction(key string) (tea.Model, tea.Cmd, bool) {
	switch m.keys[key] {
	case actionQuit:
		return m, tea.Quit, true
	case actionViewInfo:
		return m, m.switchMode(modeInfo), true
	case actionViewSections:
		return m, m.switchMode(modeSections), true
	case actionViewSymbols:
		return m, m.switchMode(modeSymbols), true
	case actionViewDisasm:
		return m, m.switchMode(modeDisasm), true
	case actionViewHex:
		return m, m.switchMode(modeHex), true
	case actionViewLibs:
		return m, m.switchMode(modeLibs), true
	case actionViewRaw:
		return m, m.switchMode(modeRaw), true
	case actionViewStrings:
		return m, m.switchMode(modeStrings), true
	case actionViewSources:
		return m, m.switchMode(modeSources), true
	case actionGoto:
		m.gotoActive = true
		m.gotoInput.Focus()
		m.recomputeGoto()
		return m, nil, true
	case actionToggleSource:
		m.toggleSourcePane()
		return m, nil, true
	}
	return m, nil, false
}

func (m *Model) toggleSourcePane() {
	if m.mode != modeDisasm {
		return
	}
	if !m.file.HasDWARF() {
		m.setStatus("no debug info — source pane unavailable", true)
		return
	}
	switch {
	case !m.showSource:
		m.showSource = true
		m.sourceFirst = false
	case !m.sourceFirst && m.ensureSourceForDisasmCursor():
		m.sourceFirst = true
	default:
		m.showSource = !m.showSource
		m.sourceFirst = false
	}
}

func normalizeNavKey(key string) string {
	// macOS keyboards often lack Home/End and dedicated PgUp/PgDn; accept the
	// emacs-style ctrl+a / ctrl+e as begin/end and Cmd+Up / Cmd+Down as page
	// up / page down (modals and filter inputs were handled above, so this only
	// affects view navigation).
	switch key {
	case "ctrl+a":
		return "home"
	case "ctrl+e":
		return "end"
	case "cmd+up", "super+up", "alt+up":
		return "pgup"
	case "cmd+down", "super+down", "alt+down":
		return "pgdown"
	}
	return key
}

func (m *Model) dispatchViewKey(msg tea.KeyMsg, key string) (tea.Model, tea.Cmd) {
	switch m.mode {
	case modeSections:
		return m.updateSections(key)
	case modeSymbols:
		return m.updateSymbols(key)
	case modeDisasm:
		return m.updateDisasm(key)
	case modeHex:
		return m.updateHex(key)
	case modeRaw:
		return m.updateRaw(key)
	case modeStrings:
		return m.updateStrings(key)
	case modeSources:
		return m.updateSources(key)
	case modeLibs:
		return m.updateLibs(key)
	case modeInfo:
		return m.updateInfo(msg, key)
	}
	return m, nil
}
