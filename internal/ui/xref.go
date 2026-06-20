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
	"runtime"
	"sort"
	"strings"
	"sync"

	tea "charm.land/bubbletea/v2"
)

// xrefMaxHits caps how many references are collected (the modal scrolls).
const xrefMaxHits = 500

// xrefLead is the resync context decoded before each scan chunk; small (vs the
// interactive overlap) since chunks are contiguous, and a multiple of 4 to keep
// arm64/riscv instruction alignment.
const xrefLead = 1 << 10

// xrefHit is one referencing instruction.
type xrefHit struct {
	addr uint64 // address of the instruction making the reference
	text string // its (trimmed) assembly text
	sym  string // display name of the symbol it lives in, or ""
}

// xrefState holds the cross-reference scan + modal state.
type xrefState struct {
	xrefActive  bool // results modal open
	xrefRunning bool // background scan in flight
	xrefSeq     int  // guards against stale async results
	xrefTarget  uint64
	xrefLabel   string // display name of the target (symbol or 0x…)
	xrefResults []xrefHit
	xrefSel     int
	xrefTop     int
}

// xrefDoneMsg delivers a finished cross-reference scan.
type xrefDoneMsg struct {
	seq    int
	target uint64
	hits   []xrefHit
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
	label := fmt.Sprintf("0x%x", target)
	if sym, ok := m.file.SymbolAt(target); ok {
		if off := target - sym.Addr; off == 0 {
			label = sym.Display()
		} else {
			label = fmt.Sprintf("%s+0x%x", sym.Display(), off)
		}
	}
	m.xrefSeq++
	m.xrefRunning = true
	m.xrefTarget = target
	m.xrefLabel = label
	m.setStatus("finding references to "+label+" … (Esc cancels)", false)
	return m.xrefScanCmd(target, m.xrefSeq)
}

// xrefScanCmd decodes the whole executable image in chunks (reusing the decode
// cache) off the UI goroutine and collects instructions that reference target.
func (m *Model) xrefScanCmd(target uint64, seq int) tea.Cmd {
	svc := m.disasmService()
	img := m.file.ExecImage()
	file := m.file
	chunk := m.disasmSearchChunkBytes()
	// A one-shot full-image scan can use every core (unlike interactive search,
	// which caps workers to stay responsive). Honour an explicit config override.
	maxWorkers := runtime.GOMAXPROCS(0)
	if m.disasmSearchWorkers > 0 {
		maxWorkers = m.disasmSearchWorkers
	}
	return func() tea.Msg {
		// Split the executable image into chunks and decode + scan them in
		// parallel — decoding dominates the cost, so this scales with cores. (The
		// old scan decoded the whole image on one goroutine.)
		var starts []int
		for pos := 0; pos < img.Len(); {
			win := img.Window(pos, chunk)
			if len(win.Data) == 0 || win.End <= pos {
				break
			}
			starts = append(starts, pos)
			pos = win.End
		}

		results := make([][]xrefHit, len(starts))
		workers := max(min(maxWorkers, len(starts)), 1)
		sem := make(chan struct{}, workers)
		var wg sync.WaitGroup
		for i, start := range starts {
			wg.Add(1)
			sem <- struct{}{}
			go func(i, start int) {
				defer wg.Done()
				defer func() { <-sem }()
				var hits []xrefHit
				for _, inst := range svc.DecodeRange(start, chunk, xrefLead) {
					if !instReferences(inst.Text, target) {
						continue
					}
					sym := ""
					if s, ok := file.SymbolAt(inst.Addr); ok {
						sym = s.Display()
					}
					hits = append(hits, xrefHit{addr: inst.Addr, text: strings.TrimSpace(inst.Text), sym: sym})
				}
				results[i] = hits
			}(i, start)
		}
		wg.Wait()

		// Merge in address order, de-duplicating instructions that straddle a
		// chunk edge (decoded in two windows), and cap the total.
		seen := map[uint64]bool{}
		var hits []xrefHit
		for _, rs := range results {
			for _, h := range rs {
				if seen[h.addr] {
					continue
				}
				seen[h.addr] = true
				hits = append(hits, h)
			}
			if len(hits) >= xrefMaxHits {
				break
			}
		}
		sort.Slice(hits, func(i, j int) bool { return hits[i].addr < hits[j].addr })
		if len(hits) > xrefMaxHits {
			hits = hits[:xrefMaxHits]
		}
		return xrefDoneMsg{seq: seq, target: target, hits: hits}
	}
}

// instReferences reports whether the instruction text contains a resolved
// address literal equal to target.
func instReferences(text string, target uint64) bool {
	for from := 0; ; {
		addr, _, end, ok := extractTargetAt(text, from)
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
	if !m.xrefRunning || msg.seq != m.xrefSeq {
		return m, nil // cancelled or superseded
	}
	m.xrefRunning = false
	if len(msg.hits) == 0 {
		m.setStatus("no references to "+m.xrefLabel, true)
		return m, nil
	}
	m.xrefResults = msg.hits
	m.xrefSel = 0
	m.xrefTop = 0
	m.xrefActive = true
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
	m.setStatus("xref search cancelled", false)
}

// updateXrefModal drives the results list: select with up/down, Enter jumps to
// the referencing instruction, Esc closes.
func (m *Model) updateXrefModal(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc":
		m.xrefActive = false
	case "up", "k":
		if m.xrefSel > 0 {
			m.xrefSel--
		}
	case "down", "j":
		if m.xrefSel < len(m.xrefResults)-1 {
			m.xrefSel++
		}
	case "enter":
		if m.xrefSel >= 0 && m.xrefSel < len(m.xrefResults) {
			addr := m.xrefResults[m.xrefSel].addr
			m.xrefActive = false
			m.loadDisasmAt(addr)
		}
	}
	return m, nil
}

func (m *Model) renderXrefModal() string {
	var sb strings.Builder
	addrW := m.file.AddrHexWidth()
	rowW := modalListWidth(m.width)
	// As many rows as the screen allows, after the modal's chrome (title, target
	// line(s), two blanks, footer, border + padding).
	visible := clamp(m.height-8, 3, 40)

	// Column budget: " 0x<addr>  <sym>  <text>". The instruction text in an xref
	// is short (call/lea/branch), so cap it and give the rest to the symbol.
	avail := rowW - len(" ") - (2 + addrW) - len("  ") - len("  ")
	textW := clamp(avail/3, 12, 40)
	symW := max(8, avail-textW)

	// Title bar; the target name (a possibly long demangled symbol) goes on its
	// own line(s), wrapped to the modal width so it never widens past the view.
	sb.WriteString(m.theme.modalTitle("Cross-references"))
	sb.WriteString("\n")
	for _, r := range renderLineRowsIndented(m.theme.symbolNameStyle.Render(m.xrefLabel), rowW, true, 0) {
		sb.WriteString(r)
		sb.WriteString("\n")
	}
	sb.WriteString("\n")
	top := visualTop(m.xrefSel, m.xrefTop, len(m.xrefResults), visible, func(int) int { return 1 })
	m.xrefTop = top
	end := min(top+visible, len(m.xrefResults))
	for i := top; i < end; i++ {
		h := m.xrefResults[i]
		loc := h.sym
		if loc == "" {
			loc = "—"
		}
		line := fmt.Sprintf(" 0x%0*x  %s  %s",
			addrW, h.addr,
			padVisual(truncateMiddle(loc, symW), symW),
			truncateMiddle(h.text, textW))
		line = padRight(line, rowW)
		if i == m.xrefSel {
			line = m.theme.tableSelStyle.Render(line)
		}
		sb.WriteString(line)
		sb.WriteString("\n")
	}

	sb.WriteString("\n")
	sb.WriteString(m.theme.modalHint(
		fmt.Sprintf("↑/↓ select · Enter jump · Esc close   (%d/%d)", m.xrefSel+1, len(m.xrefResults))))
	return m.theme.modalStyle.Render(sb.String())
}
