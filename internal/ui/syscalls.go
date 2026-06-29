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

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

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

// syscallSortKey selects how the modal orders its rows. Each key has a "natural"
// direction (number/name/address ascending, count descending) that `r` reverses.
type syscallSortKey uint8

const (
	sysSortNumber syscallSortKey = iota // grouped: numbered (by number), vDSO, unresolved
	sysSortName                         // resolved name (A→Z)
	sysSortCount                        // occurrences (most-used first)
	sysSortAddr                         // first site's address (execution order)
	sysSortKeyCount
)

func (k syscallSortKey) String() string {
	switch k {
	case sysSortName:
		return "name"
	case sysSortCount:
		return "count"
	case sysSortAddr:
		return "address"
	default:
		return "number"
	}
}

// syscallState holds the syscall scan + modal state.
type syscallState struct {
	syscallActive  bool // results modal open
	syscallRunning bool // background scan in flight
	syscallSeq     int  // guards against stale async results
	syscallResults []dump.SyscallSite
	syscallScope   syscallScope
	syscallShown   []syscallRow // rows for the active scope, rebuilt on scan/scope/sort/filter change
	syscallSel     int
	syscallTop     int

	// Sort + free-text filter applied to the active scope's rows.
	syscallSort      syscallSortKey
	syscallSortDesc  bool
	syscallFilter    textinput.Model
	syscallFiltering bool // filter input focused (typing edits it)
	syscallTotal     int  // rows in the active scope before the text filter
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
	sortSyscallRows(rows, m.syscallSort, m.syscallSortDesc)
	m.syscallTotal = len(rows)

	// Apply the free-text filter (compacting in place — kept index never overtakes
	// the read index, so the shared backing array is safe to reuse).
	if needle := strings.ToLower(strings.TrimSpace(m.syscallFilter.Value())); needle != "" {
		kept := rows[:0]
		for _, r := range rows {
			if syscallRowMatches(r, needle) {
				kept = append(kept, r)
			}
		}
		rows = kept
	}
	m.syscallShown = rows
	if m.syscallSel >= len(rows) {
		m.syscallSel = max(0, len(rows)-1)
	}
}

// sortSyscallRows orders rows by the chosen key. The default (number) groups them
// like the dump: numbered first (ascending), then vDSO, then unresolved.
func sortSyscallRows(rows []syscallRow, key syscallSortKey, desc bool) {
	less := func(i, j int) bool {
		a, b := rows[i], rows[j]
		switch key {
		case sysSortName:
			if a.site.Name != b.site.Name {
				return a.site.Name < b.site.Name
			}
			return syscallNumberLess(a.site, b.site)
		case sysSortCount:
			if a.count != b.count {
				return a.count > b.count // most-used first
			}
			return syscallNumberLess(a.site, b.site)
		case sysSortAddr:
			return a.site.Addr < b.site.Addr
		default: // sysSortNumber
			return syscallNumberLess(a.site, b.site)
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if desc {
			return less(j, i)
		}
		return less(i, j)
	})
}

// syscallNumberLess is the dump's canonical order: numbered sites first (by
// number), then vDSO calls, then unresolved sites (by instruction text).
func syscallNumberLess(a, b dump.SyscallSite) bool {
	if a.HasNum != b.HasNum {
		return a.HasNum
	}
	if a.HasNum {
		return a.Num < b.Num
	}
	if a.VDSO != b.VDSO {
		return a.VDSO
	}
	return a.Text < b.Text
}

// syscallRowMatches reports whether a row matches the (lower-cased) filter needle,
// testing the resolved name, the number (decimal and 0x hex), the symbol/origin
// and the instruction text — so "write", "4", "0x4" or "_start" all narrow.
func syscallRowMatches(r syscallRow, needle string) bool {
	s := r.site
	if containsFold(s.Name, needle) || containsFold(s.Sym, needle) ||
		containsFold(s.Origin, needle) || containsFold(s.Text, needle) {
		return true
	}
	if s.HasNum {
		if containsFold(strconv.FormatInt(s.Num, 10), needle) ||
			containsFold("0x"+strconv.FormatInt(s.Num, 16), needle) {
			return true
		}
	}
	return s.VDSO && containsFold("vdso", needle)
}

// syscallCategory classifies a site for colouring: resolved-to-a-name, number-only
// (known number but no table entry), vDSO, or unresolved.
type syscallCategory uint8

const (
	catNamed      syscallCategory = iota // number resolved to a table name
	catNumberOnly                        // number known, not in the table
	catVDSO                              // vDSO / __kernel_ helper call
	catUnresolved                        // couldn't recover the number
)

func syscallCategoryOf(s dump.SyscallSite) syscallCategory {
	switch {
	case s.HasNum && s.Name != "":
		return catNamed
	case s.HasNum:
		return catNumberOnly
	case s.VDSO:
		return catVDSO
	default:
		return catUnresolved
	}
}

// syscallCatStyle maps a category to its theme colour.
func (m *Model) syscallCatStyle(c syscallCategory) lipgloss.Style {
	switch c {
	case catNamed:
		return m.theme.infoStyle // green
	case catNumberOnly:
		return m.theme.warnStyle // yellow
	case catVDSO:
		return m.theme.headerKey // blue/cyan
	default:
		return m.theme.srcShadowStyle // dim
	}
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

// syscallScopeBar renders the four scopes as a segmented control with the active
// one highlighted, so the t-cycle's options and current position are explicit
// rather than hidden behind a keystroke.
func (m *Model) syscallScopeBar() string {
	names := [sysScopeCount]string{"function", "binary", "unique", "full+libs"}
	var b strings.Builder
	b.WriteString(m.theme.modalHint("scope "))
	for i, n := range names {
		if i > 0 {
			b.WriteString(m.theme.srcShadowStyle.Render(" "))
		}
		if syscallScope(i) == m.syscallScope {
			b.WriteString(m.theme.tableSelStyle.Render(" " + n + " "))
		} else {
			b.WriteString(m.theme.srcShadowStyle.Render(" " + n + " "))
		}
	}
	if m.syscallScope == sysScopeFunc && m.syscallFnName != "" {
		b.WriteString(m.theme.modalHint("  " + m.syscallFnName))
	}
	return b.String()
}

// syscallLegend renders the colour key (named / num-only / vdso / unresolved) and
// the active sort, so the row colouring is self-explanatory.
func (m *Model) syscallLegend() string {
	sep := m.theme.srcShadowStyle.Render(" · ")
	dir := "↑"
	if m.syscallSortDesc {
		dir = "↓"
	}
	return m.syscallCatStyle(catNamed).Render("named") + sep +
		m.syscallCatStyle(catNumberOnly).Render("num-only") + sep +
		m.syscallCatStyle(catVDSO).Render("vdso") + sep +
		m.syscallCatStyle(catUnresolved).Render("unresolved") +
		m.theme.modalHint("    sort: "+m.syscallSort.String()+dir)
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
		// Resolve names the same way the dump does (the modal runs its own scan).
		for i := range sites {
			if sites[i].HasNum {
				if name, ok := dump.SyscallName(file, sites[i].Num); ok {
					sites[i].Name = name
				}
			}
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
	m.syscallFilter.SetValue("") // a fresh scan starts unfiltered
	m.syscallFilter.Blur()
	m.syscallFiltering = false
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

// updateSyscallModal drives the results list. When the filter box is focused,
// typing edits it and only the arrows/Enter/Esc/Tab are special; otherwise t
// cycles scope, s/r sort, / focuses the filter, Enter jumps and Esc closes.
func (m *Model) updateSyscallModal(msg tea.KeyMsg, key string) (tea.Model, tea.Cmd) {
	m.ensureSyscallFilter()
	rows := m.syscallShown
	if m.syscallFiltering {
		switch key {
		case "esc": // clear the filter and leave the box (modal stays open)
			m.clearSyscallFilter()
			return m, nil
		case "up":
			if m.syscallSel > 0 {
				m.syscallSel--
			}
			return m, nil
		case "down":
			if m.syscallSel < len(rows)-1 {
				m.syscallSel++
			}
			return m, nil
		case "enter":
			return m.syscallJump()
		default:
			if key == "tab" { // commit the filter, return to command keys
				m.syscallFilter.Blur()
				m.syscallFiltering = false
				return m, nil
			}
			var cmd tea.Cmd
			m.syscallFilter, cmd = m.syscallFilter.Update(msg)
			m.syscallSel, m.syscallTop = 0, 0
			m.rebuildSyscallRows()
			return m, cmd
		}
	}

	switch key {
	case "esc":
		m.syscallActive = false
	case "/":
		m.syscallFiltering = true
		return m, m.syscallFilter.Focus()
	case "t":
		m.syscallScope = (m.syscallScope + 1) % sysScopeCount
		m.syscallSel, m.syscallTop = 0, 0
		m.rebuildSyscallRows()
		m.setStatus("syscalls: "+m.scopeLabel(), false)
		// Entering full scope kicks off the (lazy) binary + libraries scan.
		if m.syscallScope == sysScopeFull && !m.syscallFullDone && !m.syscallFullRunning {
			return m, m.startSyscallFullScan()
		}
	case "s":
		m.syscallSort = (m.syscallSort + 1) % sysSortKeyCount
		m.syscallSel, m.syscallTop = 0, 0
		m.rebuildSyscallRows()
		m.setStatus("sort: "+m.syscallSort.String(), false)
	case "r":
		m.syscallSortDesc = !m.syscallSortDesc
		m.syscallSel, m.syscallTop = 0, 0
		m.rebuildSyscallRows()
	case "up", "k":
		if m.syscallSel > 0 {
			m.syscallSel--
		}
	case "down", "j":
		if m.syscallSel < len(rows)-1 {
			m.syscallSel++
		}
	case "enter":
		return m.syscallJump()
	}
	return m, nil
}

// syscallJump follows the selected site to the disassembly, refusing sites that
// live in a linked library (a different address space).
func (m *Model) syscallJump() (tea.Model, tea.Cmd) {
	rows := m.syscallShown
	if m.syscallSel < 0 || m.syscallSel >= len(rows) {
		return m, nil
	}
	site := rows[m.syscallSel].site
	if site.Origin != "" && site.Origin != "this binary" {
		m.setStatus("site is in "+site.Origin+" — open it as primary to inspect", true)
		return m, nil
	}
	m.syscallActive = false
	m.loadDisasmAt(site.Addr)
	return m, nil
}

// ensureSyscallFilter guarantees the filter input is a fully-constructed
// textinput (its cursor's blink context is non-nil) before it is focused or
// rendered, so the modal can't panic even if the model was built without the
// New() initialiser. The zero value has an empty Prompt; a real one is "/ ".
func (m *Model) ensureSyscallFilter() {
	if m.syscallFilter.Prompt == "" {
		m.syscallFilter = newPromptInput("name · #num · symbol", "/ ")
	}
}

// clearSyscallFilter empties the filter, defocuses it and rebuilds the rows.
func (m *Model) clearSyscallFilter() {
	m.syscallFilter.SetValue("")
	m.syscallFilter.Blur()
	m.syscallFiltering = false
	m.syscallSel, m.syscallTop = 0, 0
	m.rebuildSyscallRows()
}

func (m *Model) renderSyscallModal() string {
	m.ensureSyscallFilter()
	var sb strings.Builder
	addrW := m.file.AddrHexWidth()
	rowW := modalListWidth(m.width)
	visible := clamp(m.height-10, 3, 40) // 2 extra header lines (scope bar + legend)
	rows := m.syscallShown
	if m.syscallSel >= len(rows) {
		m.syscallSel = max(0, len(rows)-1)
	}
	full := m.syscallScope == sysScopeFull
	aggregated := m.syscallScope == sysScopeUnique || full

	// Column budget: "● <addr|count>  <name|#num>  <sym|origin>  <text>".
	const sysNameW = 16
	avail := rowW - len("● ") - (2 + addrW) - len("  ") - sysNameW - len("  ") - len("  ") - 6
	textW := clamp(avail/3, 10, 32)
	symW := max(8, avail-textW)

	// Header: title, scope segmented control, filter box (with shown/total count),
	// and the colour/sort legend — then a blank line before the rows.
	sb.WriteString(m.theme.modalTitle("System calls"))
	sb.WriteString("\n")
	sb.WriteString(fitANSIWidth(m.syscallScopeBar(), rowW))
	sb.WriteString("\n")
	countStr := fmt.Sprintf("  %d", len(rows))
	if m.syscallTotal != len(rows) {
		countStr = fmt.Sprintf("  %d of %d", len(rows), m.syscallTotal)
	}
	m.syscallFilter.SetWidth(clamp(rowW-len(countStr)-4, 12, 60))
	sb.WriteString(fitANSIWidth(m.syscallFilter.View()+m.theme.modalHint(countStr), rowW))
	sb.WriteString("\n")
	sb.WriteString(fitANSIWidth(m.syscallLegend(), rowW))
	sb.WriteString("\n\n")
	m.modalListRow = 5 // title + scope + filter + legend + blank
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
		label := ""
		switch {
		case h.Name != "" && h.HasNum:
			label = fmt.Sprintf("#%d %s", h.Num, h.Name)
		case h.Name != "":
			label = h.Name
		case h.HasNum:
			label = fmt.Sprintf("#%d", h.Num)
		case h.VDSO:
			label = "vdso"
		}
		// Colour the syscall label by resolution category (named / num-only / vdso /
		// unresolved) so the eye can pick out which numbers actually mapped to a name.
		num := m.syscallCatStyle(syscallCategoryOf(h)).Render(padVisual(truncateMiddle(label, sysNameW), sysNameW))
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
		if i == m.syscallSel { // strip the category colour so the selection bar reads cleanly
			line = m.theme.tableSelStyle.Render(ansi.Strip(line))
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
	footer := fmt.Sprintf("↑/↓ select · ↵ jump · t scope · s/r sort · / filter · Esc close   (%d/%d)",
		min(m.syscallSel+1, len(rows)), len(rows))
	if m.syscallFiltering {
		footer = fmt.Sprintf("type to filter · ↵ jump · Tab done · Esc clear   (%d/%d)",
			min(m.syscallSel+1, len(rows)), len(rows))
	}
	sb.WriteString(m.theme.modalHint(fitANSIWidth(footer, rowW)))
	return m.theme.modalStyle.Render(sb.String())
}
