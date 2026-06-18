package ui

import (
	"strings"

	tea "charm.land/bubbletea/v2"
)

// handleKey routes a key message through modal, global, and active-view handlers.
func (m *Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := canonicalKeyString(msg.String())

	// A keypress cancels any in-flight wheel momentum so it can't keep scrolling
	// after the user has moved on.
	m.pendingWheel = 0

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
	if model, cmd, ok := m.handleDisasmPaneKey(key); ok {
		return model, cmd
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

	key = m.normalizeNavKey(key)
	// Apply user key aliases (copy/next/prev) onto canonical tokens.
	if c, ok := m.keyAlias[key]; ok {
		key = c
	}
	before := m.activeCursorState()
	reattach := keyReattachesViewport(key)
	model, cmd := m.dispatchViewKey(msg, key)
	if reattach || before != m.activeCursorState() {
		m.viewportDetached = false
	}
	return model, cmd
}

func canonicalKeyString(key string) string {
	if strings.Contains(key, "+") {
		return strings.ToLower(key)
	}
	return key
}

// cursorState snapshots cursor fields that should reattach a detached viewport.
type cursorState struct {
	mode        mode
	sectionsCur int
	symbolsCur  int
	disasmCur   int
	hexCur      int
	rawCur      int
	stringsCur  int
	sourcesCur  int
	libsCur     int
	srcFile     string
	srcCur      int
}

// activeCursorState captures all cursors relevant to viewport attachment.
func (m *Model) activeCursorState() cursorState {
	return cursorState{
		mode:        m.mode,
		sectionsCur: m.sectionsCur,
		symbolsCur:  m.symbolsCur,
		disasmCur:   m.disasmCur,
		hexCur:      m.hexCur,
		rawCur:      m.rawCur,
		stringsCur:  m.stringsCur,
		sourcesCur:  m.sourcesCur,
		libsCur:     m.libsCur,
		srcFile:     m.srcFile,
		srcCur:      m.srcCur,
	}
}

// keyReattachesViewport reports whether key is explicit viewport navigation.
func keyReattachesViewport(key string) bool {
	switch key {
	case "up", "down", "k", "j", "pgup", "pgdown", "home", "end", "G":
		return true
	}
	return false
}

func (m *Model) handleDisasmPaneKey(key string) (tea.Model, tea.Cmd, bool) {
	if m.mode != modeDisasm {
		return m, nil, false
	}
	switch {
	case key == "shift+tab":
		m.switchSourcePane()
		return m, nil, true
	case key == "tab":
		m.toggleSourcePane()
		return m, nil, true
	case m.rightPaneActive() && key == "shift+up":
		m.scrollRightPane(-1)
		return m, nil, true
	case m.rightPaneActive() && key == "shift+down":
		m.scrollRightPane(1)
		return m, nil, true
	}
	return m, nil, false
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
		before := m.activeCursorState()
		m.searchQuery = strings.TrimSpace(m.searchInput.Value())
		m.searchActive = false
		m.searchInput.Blur()
		cmd := m.runSearchFromPrompt()
		if before != m.activeCursorState() {
			m.viewportDetached = false
			m.pinCurrentByteSectionStart()
		}
		return m, cmd
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
	m.showSource = !m.showSource
	m.rightScroll = 0
}

func (m *Model) switchSourcePane() {
	if m.mode != modeDisasm {
		return
	}
	if !m.file.HasDWARF() {
		m.setStatus("no debug info — source pane unavailable", true)
		return
	}
	if m.sourceFirst {
		m.sourceFirst = false
		m.rightScroll = 0
		return
	}
	if m.ensureSourcePaneAvailable() {
		m.sourceFirst = true
		m.rightScroll = 0
		return
	}
	m.setStatus("no source mapping for current instruction", true)
}

func (m *Model) ensureSourcePaneAvailable() bool {
	if m.ensureSourceForDisasmCursor() {
		return true
	}
	if m.ensureSourceBelowDisasmCursor() {
		return true
	}
	if m.hasOpenSourceFile() {
		return true
	}
	m.ensureSources()
	if len(m.sourcesFiltered) == 0 {
		return false
	}
	start := m.sourcesCur
	if start < 0 || start >= len(m.sourcesFiltered) {
		start = 0
	}
	for offset := 0; offset < len(m.sourcesFiltered); offset++ {
		idx := (start + offset) % len(m.sourcesFiltered)
		file := m.sourcesFiles[m.sourcesFiltered[idx]]
		src := m.file.SourceLines(file)
		if src == nil {
			continue
		}
		m.sourcesCur = idx
		m.srcFile = file
		m.srcCodeLines = m.mappedSourceLines(file)
		m.srcCur = 1
		if len(src) == 0 {
			m.srcCur = 0
		}
		m.srcTop = 0
		m.syncSourceAsm()
		return true
	}
	return false
}

// normalizeNavKey maps platform-specific navigation aliases to canonical keys.
func (m *Model) normalizeNavKey(key string) string {
	key = canonicalKeyString(key)
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
