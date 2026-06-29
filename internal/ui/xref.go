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
	"strconv"
	"strings"
	"sync"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
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
	xrefShown   []int // indices into xrefResults after sort + filter
	xrefSel     int
	xrefTop     int

	// Sort + free-text filter over the results (mirrors the syscalls modal).
	xrefSort      xrefSortKey
	xrefSortDesc  bool
	xrefFilter    textinput.Model
	xrefFiltering bool
	xrefTotal     int // results before the text filter
}

// xrefSortKey selects how the modal orders references.
type xrefSortKey uint8

const (
	xrefSortAddr xrefSortKey = iota // referencing address
	xrefSortLoc                     // containing symbol
	xrefSortKind                    // instruction kind (groups calls / jumps / loads)
	xrefSortKeyCount
)

func (k xrefSortKey) String() string {
	switch k {
	case xrefSortLoc:
		return "location"
	case xrefSortKind:
		return "kind"
	default:
		return "address"
	}
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
	m.ensureXrefFilter()
	m.xrefFilter.SetValue("")
	m.xrefFilter.Blur()
	m.xrefFiltering = false
	m.rebuildXrefRows()
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

// ensureXrefFilter guarantees the filter input is fully constructed before it is
// focused or rendered (so a model built without New() can't panic).
func (m *Model) ensureXrefFilter() {
	if m.xrefFilter.Prompt == "" {
		m.xrefFilter = newPromptInput("location · text · 0xaddr", "/ ")
	}
}

// rebuildXrefRows recomputes xrefShown (indices into xrefResults) for the active
// sort and text filter.
func (m *Model) rebuildXrefRows() {
	rows := m.xrefShown[:0]
	for i := range m.xrefResults {
		rows = append(rows, i)
	}
	desc := m.xrefSortDesc
	sort.SliceStable(rows, func(a, b int) bool {
		x, y := m.xrefResults[rows[a]], m.xrefResults[rows[b]]
		if desc {
			x, y = y, x
		}
		return xrefLess(x, y, m.xrefSort)
	})
	m.xrefTotal = len(rows)
	if needle := strings.ToLower(strings.TrimSpace(m.xrefFilter.Value())); needle != "" {
		kept := rows[:0]
		for _, idx := range rows {
			if xrefMatches(m.xrefResults[idx], needle) {
				kept = append(kept, idx)
			}
		}
		rows = kept
	}
	m.xrefShown = rows
	if m.xrefSel >= len(rows) {
		m.xrefSel = max(0, len(rows)-1)
	}
}

func xrefLess(a, b xrefHit, key xrefSortKey) bool {
	switch key {
	case xrefSortLoc:
		if a.sym != b.sym {
			return a.sym < b.sym
		}
		return a.addr < b.addr
	case xrefSortKind:
		if ka, kb := xrefKind(a.text), xrefKind(b.text); ka != kb {
			return ka < kb
		}
		return a.addr < b.addr
	default:
		return a.addr < b.addr
	}
}

func xrefMatches(h xrefHit, needle string) bool {
	return containsFold(h.sym, needle) || containsFold(h.text, needle) ||
		containsFold("0x"+strconv.FormatUint(h.addr, 16), needle)
}

// xrefKind buckets a referencing instruction so the modal can colour and sort it:
// 0 call, 1 jump/branch, 2 address-load, 3 other.
func xrefKind(text string) int {
	op := firstToken(text)
	switch {
	case strings.HasPrefix(op, "call") || strings.HasPrefix(op, "bl"):
		return 0
	case op == "jmp" || op == "b" || (len(op) > 0 && op[0] == 'j') || strings.HasPrefix(op, "b."):
		return 1
	case isAddrLoadOp(op):
		return 2
	}
	return 3
}

func (m *Model) xrefKindStyle(text string) lipgloss.Style {
	switch xrefKind(text) {
	case 0:
		return m.theme.infoStyle // call → green
	case 1:
		return m.theme.warnStyle // jump/branch → yellow
	case 2:
		return m.theme.headerKey // address load → blue
	default:
		return m.theme.srcShadowStyle // other → dim
	}
}

// updateXrefModal drives the results list. While the filter box is focused,
// typing edits it; otherwise s/r sort, / filters, Enter jumps and Esc closes.
func (m *Model) updateXrefModal(msg tea.KeyMsg, key string) (tea.Model, tea.Cmd) {
	m.ensureXrefFilter()
	rows := m.xrefShown
	if m.xrefFiltering {
		switch key {
		case "esc":
			m.xrefFilter.SetValue("")
			m.xrefFilter.Blur()
			m.xrefFiltering = false
			m.xrefSel, m.xrefTop = 0, 0
			m.rebuildXrefRows()
		case "up":
			if m.xrefSel > 0 {
				m.xrefSel--
			}
		case "down":
			if m.xrefSel < len(rows)-1 {
				m.xrefSel++
			}
		case "enter":
			return m.xrefJump()
		default:
			if key == "tab" {
				m.xrefFilter.Blur()
				m.xrefFiltering = false
				return m, nil
			}
			var cmd tea.Cmd
			m.xrefFilter, cmd = m.xrefFilter.Update(msg)
			m.xrefSel, m.xrefTop = 0, 0
			m.rebuildXrefRows()
			return m, cmd
		}
		return m, nil
	}
	switch key {
	case "esc":
		m.xrefActive = false
	case "/":
		m.xrefFiltering = true
		return m, m.xrefFilter.Focus()
	case "s":
		m.xrefSort = (m.xrefSort + 1) % xrefSortKeyCount
		m.xrefSel, m.xrefTop = 0, 0
		m.rebuildXrefRows()
		m.setStatus("sort: "+m.xrefSort.String(), false)
	case "r":
		m.xrefSortDesc = !m.xrefSortDesc
		m.xrefSel, m.xrefTop = 0, 0
		m.rebuildXrefRows()
	case "up", "k":
		if m.xrefSel > 0 {
			m.xrefSel--
		}
	case "down", "j":
		if m.xrefSel < len(rows)-1 {
			m.xrefSel++
		}
	case "enter":
		return m.xrefJump()
	}
	return m, nil
}

// xrefJump follows the selected reference to its instruction in the disasm view.
func (m *Model) xrefJump() (tea.Model, tea.Cmd) {
	if m.xrefSel < 0 || m.xrefSel >= len(m.xrefShown) {
		return m, nil
	}
	addr := m.xrefResults[m.xrefShown[m.xrefSel]].addr
	m.xrefActive = false
	m.loadDisasmAt(addr)
	return m, nil
}

func (m *Model) renderXrefModal() string {
	m.ensureXrefFilter()
	var sb strings.Builder
	addrW := m.file.AddrHexWidth()
	rowW := modalListWidth(m.width)
	rows := m.xrefShown
	visible := clamp(m.height-10, 3, 40) // 2 extra header lines (filter + legend)

	// Column budget: " 0x<addr>  <sym>  <text>". The instruction text in an xref
	// is short (call/lea/branch), so cap it and give the rest to the symbol.
	avail := rowW - len(" ") - (2 + addrW) - len("  ") - len("  ")
	textW := clamp(avail/3, 12, 40)
	symW := max(8, avail-textW)

	// Title + target name (a possibly long demangled symbol), then a filter box and
	// a colour/sort legend before the rows.
	sb.WriteString(m.theme.modalTitle("Cross-references"))
	sb.WriteString("\n")
	targetRows := renderLineRowsIndented(m.theme.symbolNameStyle.Render(m.xrefLabel), rowW, true, 0)
	for _, r := range targetRows {
		sb.WriteString(r)
		sb.WriteString("\n")
	}
	countStr := fmt.Sprintf("  %d", len(rows))
	if m.xrefTotal != len(rows) {
		countStr = fmt.Sprintf("  %d of %d", len(rows), m.xrefTotal)
	}
	m.xrefFilter.SetWidth(clamp(rowW-len(countStr)-4, 12, 60))
	sb.WriteString(fitANSIWidth(m.xrefFilter.View()+m.theme.modalHint(countStr), rowW))
	sb.WriteString("\n")
	dir := "↑"
	if m.xrefSortDesc {
		dir = "↓"
	}
	legend := m.theme.infoStyle.Render("call") + m.theme.modalHint(" · ") +
		m.theme.warnStyle.Render("jump") + m.theme.modalHint(" · ") +
		m.theme.headerKey.Render("load") + m.theme.modalHint("    sort: "+m.xrefSort.String()+dir)
	sb.WriteString(fitANSIWidth(legend, rowW))
	sb.WriteString("\n\n")
	m.modalListRow = 1 + len(targetRows) + 2 + 1 // title + target line(s) + filter + legend + blank
	top := visualTop(m.xrefSel, m.xrefTop, len(rows), visible, func(int) int { return 1 })
	m.xrefTop = top
	end := min(top+visible, len(rows))
	for i := top; i < end; i++ {
		h := m.xrefResults[rows[i]]
		loc := h.sym
		if loc == "" {
			loc = "—"
		}
		line := fmt.Sprintf(" 0x%0*x  %s  %s",
			addrW, h.addr,
			padVisual(truncateMiddle(loc, symW), symW),
			m.xrefKindStyle(h.text).Render(truncateMiddle(h.text, textW)))
		line = padRight(line, rowW)
		if i == m.xrefSel {
			line = m.theme.tableSelStyle.Render(ansi.Strip(line))
		}
		sb.WriteString(line)
		sb.WriteString("\n")
	}

	sb.WriteString("\n")
	footer := fmt.Sprintf("↑/↓ select · ↵ jump · s/r sort · / filter · Esc close   (%d/%d)",
		min(m.xrefSel+1, len(rows)), len(rows))
	if m.xrefFiltering {
		footer = fmt.Sprintf("type to filter · ↵ jump · Tab done · Esc clear   (%d/%d)",
			min(m.xrefSel+1, len(rows)), len(rows))
	}
	sb.WriteString(m.theme.modalHint(fitANSIWidth(footer, rowW)))
	return m.theme.modalStyle.Render(sb.String())
}
