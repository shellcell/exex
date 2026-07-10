package ui

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/atotto/clipboard"
	"github.com/rabarbra/exex/internal/binfile"
)

func (m *Model) Init() tea.Cmd {
	var cmds []tea.Cmd
	// Demangle the symbol table in the background so a large binary renders
	// immediately; names switch from raw to demangled when it completes. Skipped
	// when the user disabled demangling (the pass allocates 1+ GB on large C++/
	// Swift binaries) — toggling it on later computes lazily.
	if len(m.file.Symbols) > 0 && !m.cfg.Behavior.NoDemangle {
		cmds = append(cmds, m.demangleCmd())
	}
	// If the configured default view is Disasm, switchMode already flagged a
	// decode; kick it off here (New can't return a Cmd).
	if m.dasm.Decoding && !m.dasm.Built && m.dis != nil {
		cmds = append(cmds, m.decodeDisasmCmd(m.dasm.PendingAddr))
	}
	// Pre-warm the initial disasm window right after the first frame. This keeps
	// startup responsive while making the view ready for the common next action.
	cmds = append(cmds, func() tea.Msg { return prewarmMsg{} })
	return tea.Batch(cmds...)
}

// prewarmMsg fires just after the first render to kick the deferred disasm decode
// in the background, so opening the Disasm view is usually instant without
// blocking the initial screen.
type prewarmMsg struct{}

// handlePrewarm starts the deferred disasm decode in the background, unless
// already done/in-flight (e.g. the default view is disasm). DWARF/source parsing
// remains on-demand because it is large and only source-aware views need it.
func (m *Model) handlePrewarm() (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	if m.dis != nil && !m.dasm.Built && !m.dasm.Decoding {
		m.dasm.Decoding = true
		m.dasm.PendingAddr = m.disasmInitAddr
		cmds = append(cmds, m.decodeDisasmCmd(m.disasmInitAddr))
	}
	return m, tea.Batch(cmds...)
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

	case prewarmMsg:
		return m.handlePrewarm()

	case disasmReadyMsg:
		return m.handleDisasmReady(msg)

	case disasmSearchProgressMsg:
		return m.handleDisasmSearchProgress(msg)

	case xrefDoneMsg:
		return m.handleXrefDone(msg)

	case syscallDoneMsg:
		return m.handleSyscallDone(msg)

	case cpufeatDoneMsg:
		return m.handleCPUFeatDone(msg)

	case syscallFullDoneMsg:
		return m.handleSyscallFullDone(msg)

	case findPartialMsg:
		return m.handleFindPartial(msg)

	case disasmPrefetchMsg:
		return m, nil

	case demangleDoneMsg:
		if msg.file != m.file {
			return m, nil
		}
		// Background demangle finished: keep the computed names so the setting can
		// be toggled later without recomputing, and apply them unless the user has
		// turned demangling off.
		m.demangledNames = msg.names
		if !m.cfg.Behavior.NoDemangle {
			m.applyDemangledNames(msg.names)
		}
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
	case m.palette.Active():
		cmd = m.palette.HandleInput(m, msg)
	case m.search.Active():
		cmd = m.search.HandleInput(msg)
	case m.symbols.Filter.Focused():
		before := m.symbols.Filter.Value()
		m.symbols.Filter, cmd = m.symbols.Filter.Update(msg)
		if m.symbols.Filter.Value() != before {
			m.symbols.Recompute(m.viewContext())
		}
	case m.sections.Filter.Focused():
		before := m.sections.Filter.Value()
		m.sections.Filter, cmd = m.sections.Filter.Update(msg)
		if m.sections.Filter.Value() != before {
			m.sections.Recompute()
		}
	case m.strs.Filter.Focused():
		before := m.strs.Filter.Value()
		m.strs.Filter, cmd = m.strs.Filter.Update(msg)
		if m.strs.Filter.Value() != before {
			m.strs.Recompute(m.viewContext())
		}
	case m.sources.Filter.Focused():
		before := m.sources.Filter.Value()
		m.sources.Filter, cmd = m.sources.Filter.Update(msg)
		if m.sources.Filter.Value() != before {
			m.sources.Recompute(m.viewContext())
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
	m.srcVP.SetWidth(m.width / 2)
	m.srcVP.SetHeight(bodyH)
}

func (m *Model) handleDisasmReady(msg disasmReadyMsg) (tea.Model, tea.Cmd) {
	// Ignore late delivery if a synchronous jump already loaded a newer span.
	if (msg.file != nil && msg.file != m.file) || !m.dasm.Decoding || msg.addr != m.dasm.PendingAddr {
		return m, nil
	}
	m.dasm.Inst = msg.span.Insts
	m.dasm.PosLo, m.dasm.PosHi = msg.span.PosLo, msg.span.PosHi
	m.sourceAsmRowCache = nil
	m.dasm.HeightCache = nil
	m.dasm.Built = true
	m.dasm.Decoding = false
	m.dasm.PendingAddr = 0
	// A prewarm decode (the user isn't in the disasm view yet) only stores the
	// window — it must not switch the view or post a status. Positioning happens
	// when the user actually opens disasm (switchMode sees disasmBuilt).
	if m.mode != modeDisasm {
		return m, nil
	}
	if len(m.dasm.Inst) == 0 {
		m.setStatus("no executable code to disassemble", true)
		return m, nil
	}
	if !m.dasm.Positioned && m.disasmInitAddr != 0 {
		m.loadDisasmAt(m.disasmInitAddr)
	}
	return m, nil
}

func (m *Model) handleDisasmSearchProgress(msg disasmSearchProgressMsg) (tea.Model, tea.Cmd) {
	if msg.file != m.file || !m.searchRunning || msg.seq != m.searchSeq {
		return m, nil
	}
	m.cacheDisasmSearchHits(msg.found, msg.forward)
	m.noteDisasmSearchCoverage(msg.scannedLo, msg.scannedHi)
	if msg.done {
		m.searchRunning = false
		m.searchCancelable = false
		m.searchCancel = nil
		if msg.hit != nil {
			m.setDisasmSpan(m.disasmService().SpanFor(msg.hit.win, msg.hit.insts))
			m.dasm.Cur = msg.hit.idx
			m.dasm.Top = msg.hit.idx
			m.dasm.Positioned = true
			m.setMode(modeDisasm)
			m.searchCursorMode = searchCursorAtMatch
			m.searchCursorAddr = msg.hit.addr
			m.setStatus("match: "+strings.TrimSpace(msg.hit.text), false)
			return m, m.prefetchDisasmAroundCmd(msg.hit.addr)
		}
		m.searchResults.SetExhausted(msg.next.forward)
		if msg.next.forward {
			m.searchCursorMode = searchCursorAfterEnd
		} else {
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
type demangleDoneMsg struct {
	file  *binfile.File
	names []string
}

// applyDemangledNames stores the demangled names onto the symbol table, then
// invalidates the now-stale display order, tree and name-keyed caches.
func (m *Model) applyDemangledNames(names []string) {
	m.file.ApplyDemangled(names)
	m.invalidateSymbolNameState()
}

// invalidateSymbolNameState drops everything that bakes in symbol display names,
// shared by the demangle apply and clear paths. Names change both the display
// order and every tree path, so the pre-change tree (and any collapse-default) is
// stale; they also appear in the disasm "<name>:" labels and disasm/hex
// annotations, whose cached row heights wrap by name length.
func (m *Model) invalidateSymbolNameState() {
	m.symbols.OnNamesChanged(m.viewContext())
	m.clearSymbolNameCaches()
	m.refreshModalSymbolNames()
}

func (m *Model) refreshModalSymbolNames() {
	m.xrefCache = nil
	if m.xref.Active() {
		m.xrefLabel = m.xrefLabelForTarget(m.xrefTarget)
		m.xref.SetLabel(m.xrefLabel)
		m.xref.RelabelSymbols(m.symbolDisplayAt)
	}
	m.syscallCached = nil
	if m.syscalls.Active() {
		m.syscalls.RelabelSymbols(m.symbolDisplayAt)
	}
}

func (m *Model) symbolDisplayAt(addr uint64) string {
	if sym, ok := m.file.SymbolAt(addr); ok {
		return sym.Display()
	}
	return ""
}

// toggleDemangle flips the demangle preference and applies it live: re-applying
// the cached demangled names, or clearing them back to the raw mangled form
// (in place, with no allocation).
func (m *Model) toggleDemangle() {
	m.cfg.Behavior.NoDemangle = !m.cfg.Behavior.NoDemangle
	if m.cfg.Behavior.NoDemangle {
		m.file.ClearDemangled()
		m.invalidateSymbolNameState()
		return
	}
	names := m.demangledNames
	if names == nil { // the background pass hasn't finished (or never ran) — compute now
		names = m.file.ComputeDemangled()
		m.demangledNames = names
	}
	m.applyDemangledNames(names)
}

// demangleCmd demangles the symbol table off the UI goroutine so a large binary
// shows up immediately (with raw names) instead of blocking on startup.
func (m *Model) demangleCmd() tea.Cmd {
	f := m.file
	return func() tea.Msg { return demangleDoneMsg{file: f, names: f.ComputeDemangled()} }
}

// copyToClipboard puts text on the system clipboard and reports success or
// failure to the user via the status footer.
func (m *Model) copyToClipboard(text, what string) {
	m.lastCopy = text // test seam: records the last copy regardless of clipboard availability
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
	m.lastCopy = text // test seam (see copyToClipboard)
	if err := clipboard.WriteAll(text); err != nil {
		m.setStatus(fmt.Sprintf("clipboard: %v", err), true)
		return
	}
	m.setStatus(summary, false)
}
