package ui

// System-call extraction: scan the executable image for every instruction that
// enters the kernel directly (syscall / svc / int 0x80 / ecall) plus calls to
// vDSO/__kernel_ helpers, and open a jump-to modal listing them. Sites inside
// the function under the cursor are marked and the selection lands on the first
// of them, so the modal answers both "syscalls in this function" and "syscalls
// in the whole binary" at once. The scan mirrors the cross-reference scan: it
// runs off the UI goroutine over the decode cache and is cancellable.

import (
	"fmt"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"

	tea "charm.land/bubbletea/v2"

	"github.com/rabarbra/exex/internal/dump"
)

// syscallMaxHits caps how many syscall sites are collected (the modal scrolls).
const syscallMaxHits = 2000

// syscallLead matches the cross-reference scan's resync context (a 4-multiple to
// keep arm64/riscv instruction alignment across contiguous chunks).
const syscallLead = 1 << 10

// syscallScanBack is how many preceding instructions are scanned for the load of
// the syscall-number register (matches dump's recovery window).
const syscallScanBack = 32

// syscallScope selects which sites the modal lists.
type syscallScope uint8

const (
	sysScopeFunc   syscallScope = iota // only the function under the cursor
	sysScopeAll                        // every site in the binary
	sysScopeUnique                     // one row per distinct syscall number
	sysScopeFull                       // unique across the binary + its linked libs
	sysScopeCount
)

// syscallState holds the syscall scan + modal state.
type syscallState struct {
	syscallActive  bool // results modal open
	syscallRunning bool // background scan in flight
	syscallSeq     int  // guards against stale async results
	syscallResults []dump.SyscallSite
	syscallScope   syscallScope
	syscallShown   []syscallRow // rows for the active scope, rebuilt on scan/scope change
	syscallSel     int
	syscallTop     int
	syscallFnLo    uint64 // function-under-cursor range, to mark/pre-select its sites
	syscallFnHi    uint64
	syscallFnName  string

	// Full scope (binary + linked libraries), scanned lazily off-thread.
	syscallFull        []dump.SyscallSite
	syscallFullNotes   []string // libraries that couldn't be scanned
	syscallFullObjs    int      // objects scanned
	syscallFullDone    bool
	syscallFullRunning bool
	syscallFullSeq     int
}

// syscallRow is one displayed line: a representative site and, in unique scope,
// how many sites share its number.
type syscallRow struct {
	site  dump.SyscallSite
	count int
}

// inFunc reports whether addr is inside the function the scan was launched from.
func (m *Model) inFunc(addr uint64) bool {
	return m.syscallFnHi > m.syscallFnLo && addr >= m.syscallFnLo && addr < m.syscallFnHi
}

// rebuildSyscallRows recomputes the displayed rows for the active scope into the
// cached syscallShown slice. Called only when the scan results or scope change,
// so per-frame rendering and per-event mouse mapping reuse the slice instead of
// re-deriving (and re-allocating) it every time.
func (m *Model) rebuildSyscallRows() {
	rows := m.syscallShown[:0]
	switch m.syscallScope {
	case sysScopeFunc:
		for _, s := range m.syscallResults {
			if m.inFunc(s.Addr) {
				rows = append(rows, syscallRow{site: s, count: 1})
			}
		}
	case sysScopeUnique:
		rows = uniqueSyscallRows(m.syscallResults, rows)
	case sysScopeFull:
		rows = uniqueSyscallRows(m.syscallFull, rows)
	default: // sysScopeAll
		for _, s := range m.syscallResults {
			rows = append(rows, syscallRow{site: s, count: 1})
		}
	}
	m.syscallShown = rows
}

// uniqueSyscallRows aggregates sites into one row per distinct syscall (number,
// or vDSO/unresolved text), counting occurrences. The first site of each kind is
// kept as the representative (carrying its origin, for the full scope).
func uniqueSyscallRows(sites []dump.SyscallSite, rows []syscallRow) []syscallRow {
	idx := make(map[string]int, len(sites))
	var key [24]byte
	for _, s := range sites {
		var k string
		switch {
		case s.HasNum:
			k = "n" + string(strconv.AppendInt(key[:0], s.Num, 10))
		case s.VDSO:
			k = "v" + s.Text
		default:
			k = "u" + s.Text
		}
		if j, ok := idx[k]; ok {
			rows[j].count++
			continue
		}
		idx[k] = len(rows)
		rows = append(rows, syscallRow{site: s, count: 1})
	}
	return rows
}

// scopeLabel names the active scope for the modal subtitle.
func (m *Model) scopeLabel() string {
	switch m.syscallScope {
	case sysScopeFunc:
		if m.syscallFnName != "" {
			return "in " + m.syscallFnName
		}
		return "this function"
	case sysScopeUnique:
		return "unique"
	case sysScopeFull:
		if m.syscallFullRunning {
			return "full (+libs) — scanning…"
		}
		if m.syscallFullDone {
			return fmt.Sprintf("full · binary + %d libs", max(0, m.syscallFullObjs-1))
		}
		return "full (+libs)"
	default:
		return "whole binary"
	}
}

// syscallDoneMsg delivers a finished syscall scan.
type syscallDoneMsg struct {
	seq   int
	sites []dump.SyscallSite
}

// startSyscallScan launches a syscall-site scan over the executable image,
// remembering the function under the cursor so its sites can be highlighted.
func (m *Model) startSyscallScan() tea.Cmd {
	if m.dis == nil || len(m.disasmInst) == 0 {
		m.setStatus("no disassembly to scan", true)
		return nil
	}
	m.syscallFnLo, m.syscallFnHi, m.syscallFnName = 0, 0, ""
	addr := m.disasmInst[m.disasmCur].Addr
	if sym, ok := m.file.SymbolAt(addr); ok && sym.Size > 0 {
		m.syscallFnLo, m.syscallFnHi = sym.Addr, sym.Addr+sym.Size
		m.syscallFnName = sym.Display()
	}
	m.syscallSeq++
	m.syscallRunning = true
	m.setStatus("scanning for syscalls … (Esc cancels)", false)
	return m.syscallScanCmd(m.syscallSeq)
}

// syscallScanCmd decodes the executable image in parallel chunks (reusing the
// decode cache) off the UI goroutine and collects syscall sites.
func (m *Model) syscallScanCmd(seq int) tea.Cmd {
	svc := m.disasmService()
	img := m.file.ExecImage()
	file := m.file
	arch := m.file.Arch()
	symAt := dump.VDSOSymAt(file) // nil unless the binary has vDSO symbols
	chunk := m.disasmSearchChunkBytes()
	maxWorkers := runtime.GOMAXPROCS(0)
	if m.disasmSearchWorkers > 0 {
		maxWorkers = m.disasmSearchWorkers
	}
	return func() tea.Msg {
		var starts []int
		for pos := 0; pos < img.Len(); {
			win := img.Window(pos, chunk)
			if len(win.Data) == 0 || win.End <= pos {
				break
			}
			starts = append(starts, pos)
			pos = win.End
		}

		results := make([][]dump.SyscallSite, len(starts))
		workers := max(min(maxWorkers, len(starts)), 1)
		sem := make(chan struct{}, workers)
		var wg sync.WaitGroup
		for i, start := range starts {
			wg.Add(1)
			sem <- struct{}{}
			go func(i, start int) {
				defer wg.Done()
				defer func() { <-sem }()
				var hits []dump.SyscallSite
				decoded := svc.DecodeRange(start, chunk, syscallLead)
				for p, inst := range decoded {
					ok, vdso := dump.ClassifySyscallSite(inst, symAt)
					if !ok {
						continue
					}
					sym := ""
					if s, ok := file.SymbolAt(inst.Addr); ok {
						sym = s.Display()
					}
					h := dump.SyscallSite{
						Addr: inst.Addr,
						Text: strings.TrimSpace(inst.Text),
						Sym:  sym,
						VDSO: vdso,
					}
					if !vdso {
						lo := p - syscallScanBack
						if lo < 0 {
							lo = 0
						}
						if n, ok := dump.ResolveSyscallNum(decoded[lo:p], arch); ok {
							h.Num, h.HasNum = n, true
						}
					}
					hits = append(hits, h)
				}
				results[i] = hits
			}(i, start)
		}
		wg.Wait()

		seen := map[uint64]bool{}
		var sites []dump.SyscallSite
		for _, rs := range results {
			for _, h := range rs {
				if seen[h.Addr] {
					continue
				}
				seen[h.Addr] = true
				sites = append(sites, h)
			}
			if len(sites) >= syscallMaxHits {
				break
			}
		}
		sort.Slice(sites, func(i, j int) bool { return sites[i].Addr < sites[j].Addr })
		if len(sites) > syscallMaxHits {
			sites = sites[:syscallMaxHits]
		}
		return syscallDoneMsg{seq: seq, sites: sites}
	}
}

// handleSyscallDone stores a finished scan and opens the modal (or reports none),
// landing the selection on the first site inside the function under the cursor.
func (m *Model) handleSyscallDone(msg syscallDoneMsg) (tea.Model, tea.Cmd) {
	if !m.syscallRunning || msg.seq != m.syscallSeq {
		return m, nil // cancelled or superseded
	}
	m.syscallRunning = false
	if len(msg.sites) == 0 {
		m.setStatus("no syscalls found", true)
		return m, nil
	}
	m.syscallResults = msg.sites
	m.syscallSel = 0
	m.syscallTop = 0
	inFn := 0
	for _, s := range msg.sites {
		if m.inFunc(s.Addr) {
			inFn++
		}
	}
	// Land in the function scope when the cursor's function has syscalls (the
	// common "what does this function call?" question); otherwise show them all.
	if inFn > 0 {
		m.syscallScope = sysScopeFunc
	} else {
		m.syscallScope = sysScopeAll
	}
	m.rebuildSyscallRows()
	m.syscallActive = true
	capped := ""
	if len(msg.sites) >= syscallMaxHits {
		capped = "+"
	}
	if inFn > 0 && m.syscallFnName != "" {
		m.setStatus(fmt.Sprintf("%d%s syscalls · %d in %s (t: scope)", len(msg.sites), capped, inFn, m.syscallFnName), false)
	} else {
		m.setStatus(fmt.Sprintf("%d%s syscalls (t: scope)", len(msg.sites), capped), false)
	}
	return m, nil
}

// cancelSyscall abandons an in-flight scan (its result is ignored by seq).
func (m *Model) cancelSyscall() {
	m.syscallSeq++
	m.syscallRunning = false
	m.setStatus("syscall scan cancelled", false)
}

// syscallFullDoneMsg delivers a finished full (binary + libs) scan.
type syscallFullDoneMsg struct {
	seq   int
	sites []dump.SyscallSite
	objs  int
	notes []string
}

// startSyscallFullScan scans the binary and its linked libraries off the UI
// goroutine (opening and decoding each library is I/O- and CPU-heavy, so it must
// not block rendering). The result feeds the modal's full scope.
func (m *Model) startSyscallFullScan() tea.Cmd {
	m.syscallFullSeq++
	m.syscallFullRunning = true
	seq := m.syscallFullSeq
	file := m.file
	return func() tea.Msg {
		sites, objs, notes := dump.CollectSyscallsFull(file)
		return syscallFullDoneMsg{seq: seq, sites: sites, objs: objs, notes: notes}
	}
}

// handleSyscallFullDone stores a finished full scan and refreshes the rows if the
// modal is still in full scope.
func (m *Model) handleSyscallFullDone(msg syscallFullDoneMsg) (tea.Model, tea.Cmd) {
	if msg.seq != m.syscallFullSeq {
		return m, nil // superseded
	}
	m.syscallFullRunning = false
	m.syscallFullDone = true
	m.syscallFull = msg.sites
	m.syscallFullObjs = msg.objs
	m.syscallFullNotes = msg.notes
	if m.syscallActive && m.syscallScope == sysScopeFull {
		m.syscallSel, m.syscallTop = 0, 0
		m.rebuildSyscallRows()
		m.setStatus("syscalls: "+m.scopeLabel(), false)
	}
	return m, nil
}

// updateSyscallModal drives the results list: select with up/down, Enter jumps
// to the site, t cycles the scope (function · whole binary · unique), Esc closes.
func (m *Model) updateSyscallModal(key string) (tea.Model, tea.Cmd) {
	rows := m.syscallShown
	switch key {
	case "esc":
		m.syscallActive = false
	case "t":
		m.syscallScope = (m.syscallScope + 1) % sysScopeCount
		m.syscallSel, m.syscallTop = 0, 0
		m.rebuildSyscallRows()
		m.setStatus("syscalls: "+m.scopeLabel(), false)
		// Entering full scope kicks off the (lazy) binary + libraries scan.
		if m.syscallScope == sysScopeFull && !m.syscallFullDone && !m.syscallFullRunning {
			return m, m.startSyscallFullScan()
		}
	case "up", "k":
		if m.syscallSel > 0 {
			m.syscallSel--
		}
	case "down", "j":
		if m.syscallSel < len(rows)-1 {
			m.syscallSel++
		}
	case "enter":
		if m.syscallSel >= 0 && m.syscallSel < len(rows) {
			site := rows[m.syscallSel].site
			// Full-scope rows can come from a linked library — a different address
			// space, so the cursor address means nothing here. Only follow sites in
			// this binary.
			if site.Origin != "" && site.Origin != "this binary" {
				m.setStatus("site is in "+site.Origin+" — open it as primary to inspect", true)
				return m, nil
			}
			m.syscallActive = false
			m.loadDisasmAt(site.Addr)
		}
	}
	return m, nil
}

func (m *Model) renderSyscallModal() string {
	var sb strings.Builder
	addrW := m.file.AddrHexWidth()
	rowW := modalListWidth(m.width)
	visible := clamp(m.height-8, 3, 40)
	rows := m.syscallShown
	if m.syscallSel >= len(rows) {
		m.syscallSel = max(0, len(rows)-1)
	}
	full := m.syscallScope == sysScopeFull
	aggregated := m.syscallScope == sysScopeUnique || full

	// Column budget: "● <addr|count>  #num  <sym|origin>  <text>".
	avail := rowW - len("● ") - (2 + addrW) - len("  ") - 4 - len("  ") - len("  ") - 6
	textW := clamp(avail/3, 10, 32)
	symW := max(8, avail-textW)

	sb.WriteString(m.theme.modalTitle("System calls"))
	sb.WriteString("\n")
	subtitle := m.scopeLabel() + "  ·  t: scope (function · binary · unique · full+libs)"
	sb.WriteString(m.theme.modalHint(fitANSIWidth(subtitle, rowW)))
	sb.WriteString("\n\n")
	m.modalListRow = 3 // title + subtitle + blank
	top := visualTop(m.syscallSel, m.syscallTop, len(rows), visible, func(int) int { return 1 })
	m.syscallTop = top
	end := min(top+visible, len(rows))
	for i := top; i < end; i++ {
		h := rows[i].site
		loc := h.Sym
		if full { // in the full scope the originating object is more useful than the symbol
			loc = h.Origin
		}
		if loc == "" {
			loc = "—"
		}
		mark := " "
		if !aggregated && m.inFunc(h.Addr) {
			mark = "●"
		}
		text := truncateMiddle(h.Text, textW)
		if h.VDSO {
			text += " ·vdso"
		}
		num := "    "
		if h.HasNum {
			num = padVisual(fmt.Sprintf("#%d", h.Num), 4)
		} else if h.VDSO {
			num = "vdso"
		}
		// In aggregated scopes (unique / full) show a use count instead of an address.
		first := fmt.Sprintf("0x%0*x", addrW, h.Addr)
		if aggregated {
			first = padVisual(fmt.Sprintf("%d×", rows[i].count), 2+addrW)
		}
		line := fmt.Sprintf("%s %s  %s  %s  %s",
			mark, first, num,
			padVisual(truncateMiddle(loc, symW), symW),
			text)
		line = padVisual(line, rowW)
		if i == m.syscallSel {
			line = m.theme.tableSelStyle.Render(line)
		}
		sb.WriteString(line)
		sb.WriteString("\n")
	}
	// Full scope: while the library scan runs, or if it found nothing, say so.
	if full && len(rows) == 0 {
		msg := "scanning binary + libraries…"
		if m.syscallFullDone {
			msg = "no syscalls found in the binary or its libraries"
		}
		sb.WriteString(" " + m.theme.srcShadowStyle.Render(msg) + "\n")
	}
	// Full scope: list libraries that couldn't be scanned, mirroring the dump.
	if full && len(m.syscallFullNotes) > 0 {
		sb.WriteString("\n")
		sb.WriteString(" " + m.theme.warnStyle.Render(fmt.Sprintf("%d unresolved libraries:", len(m.syscallFullNotes))) + "\n")
		shown := m.syscallFullNotes
		if len(shown) > 4 {
			shown = shown[:4]
		}
		for _, n := range shown {
			sb.WriteString(" " + m.theme.srcShadowStyle.Render(fitANSIWidth(n, rowW)) + "\n")
		}
		if len(m.syscallFullNotes) > 4 {
			sb.WriteString(" " + m.theme.srcShadowStyle.Render(fmt.Sprintf("  … and %d more", len(m.syscallFullNotes)-4)) + "\n")
		}
	}

	sb.WriteString("\n")
	sb.WriteString(m.theme.modalHint(
		fmt.Sprintf("↑/↓ select · Enter jump · t scope · Esc close   (%d/%d)", min(m.syscallSel+1, len(rows)), len(rows))))
	return m.theme.modalStyle.Render(sb.String())
}
