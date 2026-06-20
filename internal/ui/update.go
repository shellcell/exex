package ui

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/atotto/clipboard"
)

func (m *Model) Init() tea.Cmd {
	var cmds []tea.Cmd
	// Demangle the symbol table in the background so a large binary renders
	// immediately; names switch from raw to demangled when it completes.
	if len(m.file.Symbols) > 0 {
		cmds = append(cmds, m.demangleCmd())
	}
	// If the configured default view is Disasm, switchMode already flagged a
	// decode; kick it off here (New can't return a Cmd).
	if m.disasmDecoding && !m.disasmBuilt && m.dis != nil {
		cmds = append(cmds, m.decodeDisasmCmd(m.disasmPendingAddr))
	}
	return tea.Batch(cmds...)
}

func (m *Model) setStatus(s string, isError bool) {
	m.status = s
	m.statusError = isError
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// Assume each message changes the screen; the rare no-op paths (coalesced
	// wheel events) clear this so View() can reuse the previous frame.
	m.viewDirty = true
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.resize(msg.Width, msg.Height)
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)

	case tea.MouseMsg:
		return m.handleMouse(msg)

	case wheelTickMsg:
		return m.handleWheelTick()

	case keyTickMsg:
		return m.handleKeyTick()

	case disasmReadyMsg:
		return m.handleDisasmReady(msg)

	case disasmSearchProgressMsg:
		return m.handleDisasmSearchProgress(msg)

	case xrefDoneMsg:
		return m.handleXrefDone(msg)

	case disasmPrefetchMsg:
		return m, nil

	case demangleDoneMsg:
		// Background demangle finished: store the names (and refresh the symbols
		// filter, which matches on demangled text too) so the next render shows
		// readable names everywhere.
		m.file.ApplyDemangled(msg.names)
		m.recomputeSymbols()
		return m, nil

	default:
		// Anything else (clipboard paste — both the bracketed-paste tea.PasteMsg
		// and the unexported pasteMsg the textinput's ctrl+v command returns —
		// plus cursor/blink messages) is forwarded to whichever input is active so
		// paste works in the goto/search modals and the list filters.
		return m.forwardToFocusedInput(msg)
	}
}

// forwardToFocusedInput delivers a message to the currently-active text input
// (a modal or a focused list filter) and recomputes that view's results only
// when the input's text actually changed (so a stray non-text message can't
// trigger a needless full re-filter).
func (m *Model) forwardToFocusedInput(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch {
	case m.gotoActive:
		before := m.gotoInput.Value()
		m.gotoInput, cmd = m.gotoInput.Update(msg)
		if m.gotoInput.Value() != before {
			m.recomputeGoto()
		}
	case m.searchActive:
		m.searchInput, cmd = m.searchInput.Update(msg)
	case m.symbolsFilter.Focused():
		before := m.symbolsFilter.Value()
		m.symbolsFilter, cmd = m.symbolsFilter.Update(msg)
		if m.symbolsFilter.Value() != before {
			m.recomputeSymbols()
		}
	case m.sectionsFilter.Focused():
		before := m.sectionsFilter.Value()
		m.sectionsFilter, cmd = m.sectionsFilter.Update(msg)
		if m.sectionsFilter.Value() != before {
			m.recomputeSections()
		}
	case m.stringsFilter.Focused():
		before := m.stringsFilter.Value()
		m.stringsFilter, cmd = m.stringsFilter.Update(msg)
		if m.stringsFilter.Value() != before {
			m.recomputeStrings()
		}
	case m.sourcesFilter.Focused():
		before := m.sourcesFilter.Value()
		m.sourcesFilter, cmd = m.sourcesFilter.Update(msg)
		if m.sourcesFilter.Value() != before {
			m.recomputeSourceFiles()
		}
	}
	return m, cmd
}

func (m *Model) resize(width, height int) {
	if m.width != width {
		m.clearAllViewCaches()
	}
	m.width, m.height = width, height
	bodyH := m.bodyHeight()
	m.headerVP.SetWidth(m.width)
	m.headerVP.SetHeight(bodyH)
	m.srcVP.SetWidth(m.width / 2)
	m.srcVP.SetHeight(bodyH)
}

func (m *Model) handleDisasmReady(msg disasmReadyMsg) (tea.Model, tea.Cmd) {
	// Ignore late delivery if a synchronous jump already loaded a newer span.
	if !m.disasmDecoding || msg.addr != m.disasmPendingAddr {
		return m, nil
	}
	m.disasmInst = msg.insts
	m.disasmPosLo = msg.posLo
	m.disasmPosHi = msg.posHi
	m.sourceAsmRowCache = nil
	m.disasmHeightCache = nil
	m.disasmBuilt = true
	m.disasmDecoding = false
	m.disasmPendingAddr = 0
	if len(m.disasmInst) == 0 {
		m.setStatus("no executable code to disassemble", true)
		return m, nil
	}
	if !m.disasmPositioned && m.disasmInitAddr != 0 {
		m.loadDisasmAt(m.disasmInitAddr)
	}
	return m, nil
}

func (m *Model) handleDisasmSearchProgress(msg disasmSearchProgressMsg) (tea.Model, tea.Cmd) {
	if !m.searchRunning || msg.seq != m.searchSeq {
		return m, nil
	}
	m.cacheDisasmSearchHits(msg.found, msg.forward)
	m.noteDisasmSearchCoverage(msg.scannedLo, msg.scannedHi)
	if msg.done {
		m.searchRunning = false
		m.searchCancelable = false
		if msg.hit != nil {
			m.setDisasmWindow(msg.hit.win, msg.hit.insts)
			m.disasmCur = msg.hit.idx
			m.disasmTop = msg.hit.idx
			m.disasmPositioned = true
			m.setMode(modeDisasm)
			m.searchCursorMode = searchCursorAtMatch
			m.searchCursorAddr = msg.hit.addr
			m.setStatus("match: "+strings.TrimSpace(msg.hit.text), false)
			return m, m.prefetchDisasmAroundCmd(msg.hit.addr)
		}
		if msg.next.forward {
			m.searchResults.forwardExhausted = true
			m.searchCursorMode = searchCursorAfterEnd
		} else {
			m.searchResults.backwardExhausted = true
			m.searchCursorMode = searchCursorBeforeStart
		}
		m.searchCursorAddr = 0
		m.setStatus("not found: "+m.searchQuery, true)
		return m, nil
	}
	m.setStatus(msg.status, false)
	return m, m.searchDisasmStepCmd(msg.next)
}

// demangleDoneMsg carries the result of the background symbol demangle.
type demangleDoneMsg struct{ names []string }

// demangleCmd demangles the symbol table off the UI goroutine so a large binary
// shows up immediately (with raw names) instead of blocking on startup.
func (m *Model) demangleCmd() tea.Cmd {
	f := m.file
	return func() tea.Msg { return demangleDoneMsg{names: f.ComputeDemangled()} }
}

// copyToClipboard puts text on the system clipboard and reports success or
// failure to the user via the status footer.
func (m *Model) copyToClipboard(text, what string) {
	if err := clipboard.WriteAll(text); err != nil {
		m.setStatus(fmt.Sprintf("clipboard: %v", err), true)
		return
	}
	m.setStatus(fmt.Sprintf("copied %s: %s", what, text), false)
}

// copyBlob puts a large multi-line payload on the clipboard and reports a short
// summary (not the payload) in the footer — for content too big to echo, like a
// whole function's disassembly.
func (m *Model) copyBlob(text, summary string) {
	if err := clipboard.WriteAll(text); err != nil {
		m.setStatus(fmt.Sprintf("clipboard: %v", err), true)
		return
	}
	m.setStatus(summary, false)
}
