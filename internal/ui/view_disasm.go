package ui

// This file owns the disassembly view's key handling (updateDisasm) and the
// in-instruction address extraction it shares with rendering. The decode/cache
// engine lives in disasm_decode.go, navigation/history in disasm_nav.go, and
// rendering in disasm_render.go.

import (
	"fmt"
	"strconv"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/rabarbra/exex/internal/dump"
)

func (m *Model) updateDisasm(key string) (tea.Model, tea.Cmd) {
	// Independent scroll of the follower (right) pane: shift+up / shift+down peek
	// further into the pane that isn't being navigated. Any other key re-syncs it
	// to the cursor.
	if m.rightPaneActive() {
		switch key {
		case "shift+up":
			m.scrollRightPane(-1)
			return m, nil
		case "shift+down":
			m.scrollRightPane(1)
			return m, nil
		}
	}
	m.rightScroll = 0

	if m.sourceFirst && m.srcFile != "" {
		switch key {
		case "esc", "backspace":
			m.sourceFirst = false
			return m, nil
		case "tab":
			m.sourceFirst = false
			return m, nil
		}
		return m.updateSourceOpenSrc(key)
	}
	switch key {
	case "left":
		m.goBack()
		return m, nil
	case "right":
		m.goForward()
		return m, nil
	case "]":
		m.jumpSymbol(true)
		return m, nil
	case "[":
		m.jumpSymbol(false)
		return m, nil
	case "/":
		m.openSearch()
		return m, nil
	case "x":
		return m, m.startXrefScan()
	case "y":
		return m, m.startSyscallScan()
	case "w":
		m.toggleWrap()
		return m, nil
	case "n":
		return m, m.runSearch(true, false)
	case "N":
		return m, m.runSearch(false, false)
	case "up", "k":
		m.stepDisasm(false)
	case "down", "j":
		m.stepDisasm(true)
	case "pgup":
		m.moveDisasmPage(false)
		m.ensureDisasmViewport(m.disasmViewportHeight())
	case "pgdown":
		m.moveDisasmPage(true)
		m.ensureDisasmViewport(m.disasmViewportHeight())
	case "home":
		m.jumpDisasmBoundary(false)
	case "end", "G":
		m.jumpDisasmBoundary(true)
	case "enter":
		if len(m.disasmInst) == 0 {
			return m, nil
		}
		inst := m.disasmInst[m.disasmCur]
		if target, ok := m.followableAddr(inst.Text); ok {
			m.loadDisasmAt(target)
		} else {
			m.setStatus("no in-file address to follow", true)
		}
	case "h":
		if len(m.disasmInst) == 0 {
			return m, nil
		}
		m.jumpHexAtAddr(m.disasmInst[m.disasmCur].Addr)
	case "m":
		if len(m.disasmInst) == 0 {
			return m, nil
		}
		m.jumpRawAtAddr(m.disasmInst[m.disasmCur].Addr)
	case "A":
		if len(m.disasmInst) == 0 {
			return m, nil
		}
		addr := m.disasmInst[m.disasmCur].Addr
		m.copyToClipboard(fmt.Sprintf("0x%0*x", m.file.AddrHexWidth(), addr), "address")
	case "S":
		if len(m.disasmInst) == 0 {
			return m, nil
		}
		addr := m.disasmInst[m.disasmCur].Addr
		if sym, ok := m.file.SymbolAt(addr); ok {
			m.copyToClipboard(sym.Name, "symbol")
		} else {
			m.setStatus("no symbol at this address", true)
		}
	case "C":
		m.copyFunctionDisasm()
	case "e":
		m.toggleSymbolAbbrevAll()
	}
	return m, nil
}

// copyFunctionDisasm copies the disassembly of the function under the cursor to
// the clipboard as plain "addr: bytes  text" lines — the natural unit for bug
// reports, diffs and pasting into an LLM. The range comes from the symbol extent.
func (m *Model) copyFunctionDisasm() {
	if len(m.disasmInst) == 0 {
		m.setStatus("no disassembly loaded", true)
		return
	}
	sym, ok := m.file.SymbolAt(m.disasmInst[m.disasmCur].Addr)
	if !ok || sym.Size == 0 {
		m.setStatus("cursor is not inside a sized function", true)
		return
	}
	insts := m.functionInsts(sym)
	if len(insts) == 0 {
		m.setStatus("no instructions to copy for this function", true)
		return
	}
	text := dump.FunctionText(sym, insts, m.file.AddrHexWidth())
	m.copyBlob(text, fmt.Sprintf("copied %d instructions of %s", len(insts), sym.Display()))
}

// extractTargetAt finds the first 0x-prefixed hex number in text starting at
// or after `from`. Returns the address, the byte range it occupied in text,
// and whether anything was found. A "0x…" immediately preceded by "#" is an ARM
// immediate (e.g. "[sp,#0x8]"), never a followable address, so it is skipped —
// without this, hex immediates would be mis-coloured as links and annotated.
func extractTargetAt(text string, from int) (addr uint64, start, end int, ok bool) {
	search := from
	var idx int
	for {
		rel := strings.Index(text[search:], "0x")
		if rel < 0 {
			return 0, 0, 0, false
		}
		idx = search + rel
		if idx > 0 && text[idx-1] == '#' {
			search = idx + 2 // ARM immediate, not an address — keep looking
			continue
		}
		break
	}
	rest := text[idx+2:]
	n := 0
	for n < len(rest) {
		c := rest[n]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			n++
			continue
		}
		break
	}
	if n == 0 {
		return 0, 0, 0, false
	}
	v, err := strconv.ParseUint(rest[:n], 16, 64)
	if err != nil {
		return 0, 0, 0, false
	}
	return v, idx, idx + 2 + n, true
}

// followableAddr returns the first hex literal in text that maps to somewhere
// inside this binary.
func (m *Model) followableAddr(text string) (uint64, bool) {
	from := 0
	for {
		addr, _, end, ok := extractTargetAt(text, from)
		if !ok {
			return 0, false
		}
		if m.file.IsMapped(addr) {
			return addr, true
		}
		from = end
	}
}

// renderInstText applies the class colour to the mnemonic + operands while
// highlighting any in-file address as a follow-able target. Targets inside
// the *same* function/symbol as the current instruction get linkAddrIntraStyle
// (local branches); targets in other symbols get linkAddrInterStyle (calls
// into other functions, PLT stubs, etc.).
//
