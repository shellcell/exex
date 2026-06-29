package ui

import (
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
)

// handleKey routes a key message through modal, global, and active-view handlers.
func (m *Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := keyName(msg)

	// Diagnostic for terminal-specific key issues: with EXEX_KEYLOG=1 the footer
	// shows how each keypress was decoded, so an unmapped chord can be reported.
	if m.keyLog {
		k := msg.Key()
		m.setStatus(fmt.Sprintf("KEY str=%q code=%d text=%q mod=%d → %q",
			msg.String(), k.Code, k.Text, k.Mod, key), false)
	}

	// A keypress cancels any in-flight wheel momentum so it can't keep scrolling
	// after the user has moved on.
	m.pendingWheel = 0

	// While the help overlay is up, scroll keys page through it (it can be taller
	// than the terminal); any other key dismisses it.
	if m.headerActive {
		switch key {
		case "up", "k":
			m.headerScroll--
		case "down", "j":
			m.headerScroll++
		case "pgup":
			m.headerScroll -= headerPageStep
		case "pgdown":
			m.headerScroll += headerPageStep
		case "home", "g":
			m.headerScroll = 0
		case "end", "G":
			m.headerScroll = 1 << 20
		default:
			m.headerActive = false
		}
		return m, nil
	}
	if m.helpActive {
		switch key {
		case "up", "k":
			m.helpScroll--
		case "down", "j":
			m.helpScroll++
		case "pgup":
			m.helpScroll -= helpPageStep
		case "pgdown":
			m.helpScroll += helpPageStep
		case "home", "g":
			m.helpScroll = 0
		case "end", "G":
			m.helpScroll = 1 << 20 // clamped to the bottom in renderHelpModal
		default:
			m.helpActive = false
		}
		return m, nil
	}
	if m.searchRunning && key == "esc" {
		m.cancelSearch("search cancelled")
		return m, nil
	}
	if m.xrefRunning && key == "esc" {
		m.cancelXref()
		return m, nil
	}
	if m.syscallRunning && key == "esc" {
		m.cancelSyscall()
		return m, nil
	}
	if m.cpufeatRunning && key == "esc" {
		m.cancelCPUFeat()
		return m, nil
	}
	if m.cpufeatActive {
		return m.updateCPUFeatModal(key)
	}

	if m.xrefActive {
		return m.updateXrefModal(msg, key)
	}
	if m.syscallActive {
		return m.updateSyscallModal(msg, key)
	}
	if m.settingsActive {
		return m.updateSettings(key)
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
		m.helpScroll = 0
		return m, nil
	}
	// `tab` doubles as the mode-toggle (the `t` key) in every non-disasm view —
	// arches in Info, sections/segments in Sections, tree/flat in Symbols/Libs/
	// Sources, ascii/pointers in Hex/Raw. In the disasm view `tab` drives the
	// source pane, which handleDisasmPaneKey already consumed above, so this only
	// fires for the other views.
	if key == "tab" {
		key = "t"
	}
	if model, cmd, ok := m.handleGlobalAction(key); ok {
		return model, cmd
	}

	key = m.normalizeNavKey(key)
	// Apply user key aliases (copy/jump/sort/filter/…) onto canonical tokens.
	if c, ok := m.keyAlias[key]; ok {
		key = c
	}

	// shift+l (delivered as "L", or any configured copy-line key now aliased to it)
	// copies the whole current row in every row-based view; handled centrally so
	// the behaviour is identical across views.
	if key == "L" && m.copyCurrentLine() {
		return m, nil
	}
	// Coalesce held navigation keys so a key-repeat flood can't block input.
	if m.isRepeatNavKey(key) {
		return m.enqueueNavKey(key)
	}
	m.pendingKeyN = 0 // any non-repeat key ends held-nav coalescing
	before := m.activeCursorState()
	reattach := keyReattachesViewport(key)
	model, cmd := m.dispatchViewKey(msg, key)
	if reattach || before != m.activeCursorState() {
		m.viewportDetached = false
	}
	return model, cmd
}

// keyTickMsg fires after keyCoalesceInterval to apply accumulated held-key moves.
type keyTickMsg struct{}

// keyCoalesceInterval bounds how often coalesced held-key moves are applied.
const keyCoalesceInterval = wheelCoalesceInterval

// isRepeatNavKey reports whether key is a held-repeatable movement key worth
// coalescing. Info scrolls a bubbles viewport that needs the raw key message, so
// it is excluded (and is cheap anyway).
func (m *Model) isRepeatNavKey(key string) bool {
	if m.mode == modeInfo {
		return false
	}
	switch key {
	case "up", "down", "k", "j", "pgup", "pgdown", "[", "]":
		return true
	}
	return false
}

// enqueueNavKey applies a navigation key, coalescing a held key's repeats so
// only the first lands immediately and the rest are batched onto a tick.
func (m *Model) enqueueNavKey(key string) (tea.Model, tea.Cmd) {
	if m.keyTicking {
		if key == m.pendingKey {
			m.pendingKeyN++     // accumulate; applied on the next tick
			m.viewDirty = false // nothing new to draw yet — reuse the last frame
			return m, nil
		}
		// A different held key: apply it now and let it take over the in-flight
		// tick chain.
		m.applyNavKey(key, 1)
		m.pendingKey, m.pendingKeyN = key, 0
		return m, nil
	}
	m.applyNavKey(key, 1)
	m.pendingKey, m.pendingKeyN = key, 0
	m.keyTicking = true
	return m, tea.Tick(keyCoalesceInterval, func(time.Time) tea.Msg { return keyTickMsg{} })
}

// handleKeyTick applies the moves accumulated since the last tick, stopping the
// chain once the held key has drained.
func (m *Model) handleKeyTick() (tea.Model, tea.Cmd) {
	if m.pendingKeyN <= 0 {
		m.keyTicking = false
		return m, nil
	}
	n := m.pendingKeyN
	m.pendingKeyN = 0
	m.applyNavKey(m.pendingKey, n)
	return m, tea.Tick(keyCoalesceInterval, func(time.Time) tea.Msg { return keyTickMsg{} })
}

// applyNavKey dispatches a navigation key n times, preserving the viewport
// reattach behaviour of the normal key path.
func (m *Model) applyNavKey(key string, n int) {
	for i := 0; i < n; i++ {
		before := m.activeCursorState()
		m.dispatchViewKey(nil, key)
		if keyReattachesViewport(key) || before != m.activeCursorState() {
			m.viewportDetached = false
		}
	}
}

func canonicalKeyString(key string) string {
	if strings.Contains(key, "+") {
		return strings.ToLower(key)
	}
	return key
}

// macOptionGlyph maps the characters a US-layout macOS keyboard produces for
// Option+<letter> back to the base letter. With ghostty's default
// (macos-option-as-alt = false) Option+t arrives as "†" with *no* modifier bit,
// so this glyph table is the only way to recover the intended ⌥ chord without
// asking the user to reconfigure the terminal.
var macOptionGlyph = map[rune]rune{
	'å': 'a', '∫': 'b', 'ç': 'c', '∂': 'd', 'ƒ': 'f', '©': 'g', '˙': 'h',
	'∆': 'j', '˚': 'k', '¬': 'l', 'µ': 'm', 'ø': 'o', 'π': 'p', 'œ': 'q',
	'®': 'r', 'ß': 's', '†': 't', '√': 'v', '∑': 'w', '≈': 'x', '¥': 'y', 'Ω': 'z',
}

// keyName derives the canonical key token the handlers match on, robustly across
// terminals — the documented ⌥ (Option) chords are the hard part on macOS, where
// Option+letter reaches us in any of three shapes depending on the terminal:
//   - Alt/Super/Meta modifier + base letter (option-as-alt, or Cmd) → "alt+<l>"
//   - Alt modifier + a composed Text (Kitty protocol, e.g. ⌥t → "†")  → "alt+<l>"
//   - no modifier at all, just the composed glyph (ghostty default)   → "alt+<l>"
//
// tea.Key.String() returns the composed Text and drops the modifier, so it can't
// be trusted for these; we read the modifier bits and the glyph table instead.
// Shift-only and unmodified keys keep String(), so "A" (Shift+a) and the special
// keys ("enter", "tab", …) are unchanged.
func keyName(msg tea.KeyMsg) string {
	k := msg.Key()
	// The composed-glyph case (may carry no modifier): map the glyph to its letter.
	glyph := k.Code
	if k.Text != "" {
		glyph = []rune(k.Text)[0]
	}
	if base, ok := macOptionGlyph[glyph]; ok {
		return "alt+" + string(base)
	}
	if k.Mod&(tea.ModAlt|tea.ModSuper|tea.ModMeta) != 0 {
		if c := k.Code; c >= 'a' && c <= 'z' {
			return "alt+" + string(c)
		}
		if c := k.Code; c >= 'A' && c <= 'Z' {
			return "alt+" + string(c-'A'+'a')
		}
	}
	if k.Mod&^tea.ModShift != 0 {
		return canonicalKeyString(k.Keystroke())
	}
	return canonicalKeyString(msg.String())
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
	memberSel   int
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
		memberSel:   m.memberSel,
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
	case "tab":
		m.gotoScope = (m.gotoScope + 1) % gsScopeCount
		m.recomputeGoto()
		return m, nil
	case "shift+tab":
		m.gotoScope = (m.gotoScope + gsScopeCount - 1) % gsScopeCount
		m.recomputeGoto()
		return m, nil
	case "alt+p":
		// Toggle physical-address interpretation (only meaningful when LMA differs).
		if m.file.HasPhysAddrs() {
			m.gotoAddrPhys = !m.gotoAddrPhys
			m.recomputeGoto()
		}
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
	case "ctrl+t":
		m.cycleSearchMode()
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
	case modeStrings:
		return filterCapture(&m.stringsFilter, key, msg, m.recomputeStrings)
	case modeLibs:
		return filterCapture(&m.libsFilter, key, msg, m.buildLibRows)
	case modeRelocs:
		return filterCapture(&m.libsFilter, key, msg, m.recomputeRelocs)
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
	case actionViewRelocs:
		return m, m.switchMode(modeRelocs), true
	case actionGoto:
		m.gotoActive = true
		m.gotoInput.Focus()
		m.recomputeGoto()
		return m, nil, true
	case actionToggleSource:
		m.toggleSourcePane()
		return m, nil, true
	case actionSettings:
		m.openSettings()
		return m, nil, true
	case actionBack:
		if nm, cmd, ok := m.goBackFile(); ok {
			return nm, cmd, true
		}
		return m, nil, false
	case actionCPUFeatures:
		return m, m.startCPUFeatScan(), true
	case actionHeader:
		m.headerActive = true
		m.headerScroll = 0
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
	// macOS keyboards often lack Home/End and dedicated PgUp/PgDn (doc #27):
	//   page up:   ctrl+up,  option/alt+up,   PgUp
	//   page down: ctrl+down, option/alt+down, PgDn
	//   top:       Home, ctrl+a, cmd+up
	//   bottom:    End,  ctrl+e, cmd+down
	// (Modals and filter inputs were handled above, so this only affects view
	// navigation.)
	switch key {
	case "ctrl+a", "cmd+up", "super+up":
		return "home"
	case "ctrl+e", "cmd+down", "super+down":
		return "end"
	case "ctrl+up", "alt+up":
		return "pgup"
	case "ctrl+down", "alt+down":
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
	case modeRelocs:
		return m.updateRelocs(key)
	case modeInfo:
		return m.updateInfo(msg, key)
	}
	return m, nil
}
