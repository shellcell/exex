package ui

// Cross-references: from the disasm cursor, find every instruction in the
// executable image whose resolved target address is the one under the cursor —
// callers of a function, branches to a label, code that loads a global's
// address. The scan runs off the UI goroutine (a large image can take a moment)
// and its results open a jump-to modal. Only *direct* references are found: the
// target has to appear as a resolved literal in the instruction text, so
// indirect calls through a register or GOT slot aren't covered (the GOT slot's
// own symbol name partly bridges that gap).

import (
	"fmt"

	tea "charm.land/bubbletea/v2"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/disasm"
	xrefmodal "github.com/rabarbra/exex/internal/ui/modals/xref"
)

// xrefMaxHits caps how many references are collected (the modal scrolls).
const xrefMaxHits = 500

func scanCancelled(done <-chan struct{}) bool {
	if done == nil {
		return false
	}
	select {
	case <-done:
		return true
	default:
		return false
	}
}

// xrefState holds the cross-reference scan's async bookkeeping and its result
// cache. The overlay's own state lives on m.xref (internal/ui/modals/xref).
type xrefState struct {
	xrefRunning bool // background scan in flight
	xrefSeq     int  // guards against stale async results
	xrefCancel  chan struct{}
	xrefTarget  uint64
	xrefLabel   string // display name of the target (symbol or 0x…)
	xrefCache   map[xrefCacheKey]xrefCacheEntry
}

type xrefCacheKey struct {
	target uint64
	all    bool
}

type xrefCacheEntry struct {
	label string
	hits  []xrefmodal.Hit
}

// xrefDoneMsg delivers a finished cross-reference scan.
type xrefDoneMsg struct {
	file   *binfile.File
	seq    int
	target uint64
	hits   []xrefmodal.Hit
}

// startXrefScan launches a cross-reference scan for the address under the disasm
// cursor (a symbol start finds its callers; any other address finds branches and
// loads that target it).
func (m *Model) startXrefScan() tea.Cmd {
	if m.dis == nil || len(m.disasmInst) == 0 {
		m.setStatus("no disassembly to cross-reference", true)
		return nil
	}
	target := m.disasmInst[m.disasmCur].Addr
	label := m.xrefLabelForTarget(target)
	m.stopXrefScan()
	m.xrefSeq++
	m.xrefRunning = false
	key := xrefCacheKey{target: target, all: m.file.DisasmAll()}
	if cached, ok := m.xrefCache[key]; ok {
		m.xrefTarget = target
		m.xrefLabel = cached.label
		if len(cached.hits) == 0 {
			m.setStatus("no references to "+cached.label+" (cached)", true)
			return nil
		}
		m.xref.Open(cached.label, cached.hits)
		m.setStatus(fmt.Sprintf("%d references to %s (cached)", len(cached.hits), cached.label), false)
		return nil
	}
	m.xrefRunning = true
	m.xrefTarget = target
	m.xrefLabel = label
	done := make(chan struct{})
	m.xrefCancel = done
	m.setStatus("finding references to "+label+" … (Esc cancels)", false)
	return m.xrefScanCmd(target, m.xrefSeq, done)
}

func (m *Model) xrefLabelForTarget(target uint64) string {
	label := fmt.Sprintf("0x%x", target)
	if sym, ok := m.file.SymbolAt(target); ok {
		if off := target - sym.Addr; off == 0 {
			label = sym.Display()
		} else {
			label = fmt.Sprintf("%s+0x%x", sym.Display(), off)
		}
	}
	return label
}

// xrefScanCmd decodes the whole executable image in chunks (reusing the decode
// cache) off the UI goroutine and collects instructions that reference target.
// scanDisasmRefs collects every instruction whose resolved operand address
// equals target — the xref query, and one of the find query's disasm matchers.
// scanDisasmRefs collects every instruction whose resolved operand address equals
// target. The scan itself is analysis, not presentation: it lives on the
// disassembly service (explorer.DisasmService.ScanMatching), which already owns
// the image, the chunk size and the worker budget it needs.
func (m *Model) scanDisasmRefs(target uint64, done <-chan struct{}) []xrefmodal.Hit {
	matches := m.disasmService().ScanMatching(
		func(text string) bool { return instReferences(text, target) }, xrefMaxHits, done)
	hits := make([]xrefmodal.Hit, len(matches))
	for i, mt := range matches {
		hits[i] = xrefmodal.Hit{Addr: mt.Addr, Text: mt.Text, Sym: mt.Sym}
	}
	return hits
}

func (m *Model) xrefScanCmd(target uint64, seq int, done <-chan struct{}) tea.Cmd {
	file := m.file
	scan := m.scanDisasmRefs
	return func() tea.Msg {
		return xrefDoneMsg{file: file, seq: seq, target: target, hits: scan(target, done)}
	}
}

// instReferences reports whether the instruction text contains a resolved
// address literal equal to target.
func instReferences(text string, target uint64) bool {
	for from := 0; ; {
		addr, _, end, ok := disasm.FindAddrOperand(text, from)
		if !ok {
			return false
		}
		if addr == target {
			return true
		}
		from = end
	}
}

// handleXrefDone stores a finished scan and opens the modal (or reports none).
func (m *Model) handleXrefDone(msg xrefDoneMsg) (tea.Model, tea.Cmd) {
	if msg.file != m.file || !m.xrefRunning || msg.seq != m.xrefSeq {
		return m, nil // cancelled or superseded
	}
	m.xrefRunning = false
	m.xrefCancel = nil
	key := xrefCacheKey{target: msg.target, all: m.file.DisasmAll()}
	if m.xrefCache == nil {
		m.xrefCache = map[xrefCacheKey]xrefCacheEntry{}
	}
	m.xrefCache[key] = xrefCacheEntry{label: m.xrefLabel, hits: msg.hits}
	if len(msg.hits) == 0 {
		m.setStatus("no references to "+m.xrefLabel, true)
		return m, nil
	}
	m.xref.Open(m.xrefLabel, msg.hits)
	capped := ""
	if len(msg.hits) >= xrefMaxHits {
		capped = "+"
	}
	m.setStatus(fmt.Sprintf("%d%s references to %s", len(msg.hits), capped, m.xrefLabel), false)
	return m, nil
}

// cancelXref abandons an in-flight scan (its result is ignored by seq).
func (m *Model) cancelXref() {
	m.xrefSeq++
	m.xrefRunning = false
	m.stopXrefScan()
	m.setStatus("xref search cancelled", false)
}

func (m *Model) stopXrefScan() {
	if m.xrefCancel != nil {
		close(m.xrefCancel)
		m.xrefCancel = nil
	}
}
