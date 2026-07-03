package ui

// Global value search: given a value picked from the caret (an address, the
// pointer it holds, a symbol, a string, a section), find *every* place that value
// occurs or is referenced across the binary's content — disasm operands that name
// the address, data words that hold it, strings that contain the text, and
// relocations that target it. Results are aggregated into one list, each tagged
// with the view it belongs to and filterable by that view (Tab cycles the facet),
// mirroring the goto portal's layout. The scan runs off the UI goroutine (the
// disasm pass decodes the whole image) and is cancellable, like the xref scan it
// reuses.

import (
	"fmt"
	"sort"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/rabarbra/exex/internal/bytesearch"
	"github.com/rabarbra/exex/internal/ui/layout"
	"github.com/rabarbra/exex/internal/ui/views/strs"
)

// findMaxPerFacet caps hits collected per source, so a value that appears
// everywhere (0, a common byte) can't blow up memory or the list.
const findMaxPerFacet = 500

// findFacet selects which source's hits are shown; ffAll shows every source.
type findFacet uint8

const (
	ffAll findFacet = iota
	ffDisasm
	ffData
	ffStrings
	ffRelocs
	ffCount
)

func (f findFacet) String() string {
	switch f {
	case ffDisasm:
		return "disasm"
	case ffData:
		return "data"
	case ffStrings:
		return "strings"
	case ffRelocs:
		return "relocs"
	default:
		return "all"
	}
}

// findQuery is the resolved value to search for: an address (for disasm refs,
// data words and reloc targets) and/or text (for string and reloc-symbol
// matches). Derived from the chosen seed.
type findQuery struct {
	label   string // e.g. "_main", "0x1000" — for the modal title
	addr    uint64
	hasAddr bool
	text    string
}

// findHit is one occurrence: which source/view it came from, its address and/or
// file offset, a context string, and the symbol covering it.
type findHit struct {
	facet   findFacet
	addr    uint64
	off     uint64
	hasAddr bool
	text    string
	sym     string
}

// queryForSeed resolves a chosen seed into a search query.
func (m *Model) queryForSeed(s findSeed) findQuery {
	q := findQuery{label: s.preview}
	switch s.scope {
	case gsAddr:
		if a, err := parseAddr(s.value); err == nil {
			q.addr, q.hasAddr = a, true
		}
		q.label = s.value
	default:
		// Symbol / String / Section / Library seeds carry text, and an address when
		// the seed named a located thing.
		q.text = s.value
		q.addr, q.hasAddr = s.addr, s.hasAddr
	}
	return q
}

// startFindSearch opens the results modal and launches the per-source scans for
// the selected seed. Each applicable source runs as its own command, so
// tea.Batch executes them concurrently and their hits stream into the list as
// each finishes — the fast data/strings/relocs scans appear almost immediately
// while the disasm decode (the slow one) fills in when it completes.
func (m *Model) startFindSearch(s findSeed) tea.Cmd {
	m.findActive = false
	q := m.queryForSeed(s)
	if !q.hasAddr && q.text == "" {
		m.setStatus("nothing searchable in that seed", true)
		return nil
	}
	m.stopFindSearch()
	m.findSeq++
	seq := m.findSeq
	m.findQuery = q
	m.findHits = nil
	m.findShown = nil
	m.findResSel, m.findResTop = 0, 0
	m.findFacet = ffAll
	m.findTotal = 0
	m.ensureFindFilter()
	m.findFilter.SetValue("")
	m.findFilter.Blur()
	m.findFiltering = false
	m.findResultsActive = true
	m.findRunning = true
	done := make(chan struct{})
	m.findCancel = done

	m.findFacetPending = [5]bool{}
	var cmds []tea.Cmd
	if q.hasAddr {
		cmds = append(cmds, m.findDisasmCmd(q, seq, done), m.findDataCmd(q, seq, done))
		m.findFacetPending[ffDisasm], m.findFacetPending[ffData] = true, true
	}
	if q.text != "" {
		cmds = append(cmds, m.findStringsCmd(q, seq, done))
		m.findFacetPending[ffStrings] = true
	}
	if q.hasAddr || q.text != "" {
		cmds = append(cmds, m.findRelocsCmd(q, seq, done))
		m.findFacetPending[ffRelocs] = true
	}
	m.findPending = len(cmds)
	m.setStatus("searching for "+q.label+" …", false)
	return tea.Batch(cmds...)
}

// findPartialMsg delivers one source's hits as it finishes, tagged with the facet
// so the modal can mark that view's scan complete (an empty facet whose scan is
// still running shows "searching…", not "no occurrences").
type findPartialMsg struct {
	seq   int
	facet findFacet
	hits  []findHit
}

// findDisasmCmd scans the executable image for operand references to the address
// (the parallel xref scanner) — the slowest source, streamed in when ready.
func (m *Model) findDisasmCmd(q findQuery, seq int, done <-chan struct{}) tea.Cmd {
	scanRefs := m.scanDisasmRefs
	return func() tea.Msg {
		var hits []findHit
		for _, h := range scanRefs(q.addr, done) {
			hits = append(hits, findHit{facet: ffDisasm, addr: h.addr, hasAddr: true, text: h.text, sym: h.sym})
		}
		return findPartialMsg{seq: seq, facet: ffDisasm, hits: hits}
	}
}

// findDataCmd finds every file offset holding the address as a pointer-width
// little-endian word.
func (m *Model) findDataCmd(q findQuery, seq int, done <-chan struct{}) tea.Cmd {
	file := m.file
	ptrBytes := m.file.PointerBytes()
	sectionAt := m.sectionAtOffset
	addrForOff := m.addrForOffset
	return func() tea.Msg {
		pat := make([]byte, ptrBytes)
		v := q.addr
		for i := range pat {
			pat[i] = byte(v)
			v >>= 8
		}
		raw := file.Raw()
		var hits []findHit
		for pos, n := 0, 0; n < findMaxPerFacet; n++ {
			if scanCancelled(done) {
				break
			}
			idx := bytesearch.FindBytes(raw, pat, pos, true)
			if idx < 0 {
				break
			}
			off := uint64(idx)
			h := findHit{facet: ffData, off: off, text: "pointer word"}
			if a, ok := addrForOff(off); ok {
				h.addr, h.hasAddr = a, true
			}
			if sec := sectionAt(off); sec != nil {
				h.sym = sec.Name
			}
			hits = append(hits, h)
			pos = idx + 1
		}
		return findPartialMsg{seq: seq, facet: ffData, hits: hits}
	}
}

// findStringsCmd finds strings whose bytes contain the seed text.
func (m *Model) findStringsCmd(q findQuery, seq int, done <-chan struct{}) tea.Cmd {
	file := m.file
	return func() tea.Msg {
		needle := strings.ToLower(q.text)
		var hits []findHit
		for _, e := range file.Strings() {
			if len(hits) >= findMaxPerFacet || scanCancelled(done) {
				break
			}
			if !layout.ContainsFoldBytes(file.StringBytes(e), needle) {
				continue
			}
			hits = append(hits, findHit{facet: ffStrings, addr: e.Addr, off: e.Offset, hasAddr: e.HasAddr, text: strs.Sanitize(file.StringText(e)), sym: e.Section})
		}
		return findPartialMsg{seq: seq, facet: ffStrings, hits: hits}
	}
}

// findRelocsCmd finds relocations patching the address or binding the symbol.
func (m *Model) findRelocsCmd(q findQuery, seq int, done <-chan struct{}) tea.Cmd {
	file := m.file
	return func() tea.Msg {
		var hits []findHit
		for _, r := range file.Relocations() {
			if len(hits) >= findMaxPerFacet || scanCancelled(done) {
				break
			}
			if !((q.hasAddr && r.Offset == q.addr) || (q.text != "" && r.Sym == q.text)) {
				continue
			}
			ctx := r.Type
			if r.Sym != "" {
				ctx += " " + r.Sym
			}
			hits = append(hits, findHit{facet: ffRelocs, addr: r.Offset, hasAddr: r.Offset != 0, text: ctx, sym: r.Section})
		}
		return findPartialMsg{seq: seq, facet: ffRelocs, hits: hits}
	}
}

// handleFindPartial appends one source's hits as it finishes, keeping the list
// live during the search. When the last source reports, the scan is done.
func (m *Model) handleFindPartial(msg findPartialMsg) (tea.Model, tea.Cmd) {
	if msg.seq != m.findSeq || !m.findRunning {
		return m, nil // superseded or cancelled
	}
	m.findHits = append(m.findHits, msg.hits...)
	if int(msg.facet) < len(m.findFacetPending) {
		m.findFacetPending[msg.facet] = false
	}
	m.findPending--
	if m.findPending <= 0 {
		m.findRunning = false
		m.findCancel = nil
		if len(m.findHits) == 0 {
			m.setStatus("no occurrences of "+m.findQuery.label, false)
		} else {
			m.setStatus(fmt.Sprintf("%d occurrences of %s", len(m.findHits), m.findQuery.label), false)
		}
	}
	m.rebuildFindRows()
	return m, nil
}

func (m *Model) stopFindSearch() {
	if m.findCancel != nil {
		close(m.findCancel)
		m.findCancel = nil
	}
}

func (m *Model) cancelFindSearch() {
	m.findSeq++
	m.findRunning = false
	m.stopFindSearch()
}

// rebuildFindRows recomputes the displayed indices for the active facet + text
// filter.
func (m *Model) rebuildFindRows() {
	m.findShown = m.findShown[:0]
	total := 0
	needle := strings.ToLower(strings.TrimSpace(m.findFilter.Value()))
	for i := range m.findHits {
		h := &m.findHits[i]
		if m.findFacet != ffAll && h.facet != m.findFacet {
			continue
		}
		total++
		if needle != "" && !findHitMatches(h, needle) {
			continue
		}
		m.findShown = append(m.findShown, i)
	}
	m.findTotal = total
	// Stable display order — grouped by facet, then address — so streamed-in hits
	// don't reshuffle the list as each source reports.
	sort.SliceStable(m.findShown, func(a, b int) bool {
		ha, hb := &m.findHits[m.findShown[a]], &m.findHits[m.findShown[b]]
		if ha.facet != hb.facet {
			return ha.facet < hb.facet
		}
		if ha.addr != hb.addr {
			return ha.addr < hb.addr
		}
		return ha.off < hb.off
	})
	if m.findResSel >= len(m.findShown) {
		m.findResSel = max(0, len(m.findShown)-1)
	}
}

func findHitMatches(h *findHit, needle string) bool {
	return layout.ContainsFold(h.text, needle) || layout.ContainsFold(h.sym, needle) ||
		layout.ContainsFold(fmt.Sprintf("0x%x", h.addr), needle)
}

// findFacetCounts returns the per-facet hit counts for the scope bar.
func (m *Model) findFacetCounts() [ffCount]int {
	var c [ffCount]int
	for i := range m.findHits {
		c[m.findHits[i].facet]++
	}
	return c
}

func (m *Model) ensureFindFilter() {
	if m.findFilter.Prompt == "" {
		m.findFilter = newPromptInput("filter results", "/ ")
	}
}

// updateFindResultsModal drives the results list: Tab cycles the view facet, /
// filters, Enter jumps, Esc closes (cancelling any running scan).
func (m *Model) updateFindResultsModal(msg tea.KeyMsg, key string) (tea.Model, tea.Cmd) {
	m.ensureFindFilter()
	if m.findFiltering {
		switch key {
		case "esc":
			m.findFilter.SetValue("")
			m.findFilter.Blur()
			m.findFiltering = false
			m.rebuildFindRows()
			return m, nil
		case "enter":
			return m.findJump()
		case "up":
			m.findMoveResSel(-1)
			return m, nil
		case "down":
			m.findMoveResSel(1)
			return m, nil
		case "tab":
			m.findFilter.Blur()
			m.findFiltering = false
			return m, nil
		}
		var cmd tea.Cmd
		m.findFilter, cmd = m.findFilter.Update(msg)
		m.findResSel, m.findResTop = 0, 0
		m.rebuildFindRows()
		return m, cmd
	}

	switch key {
	case "esc":
		m.findResultsActive = false
		m.cancelFindSearch()
	case "tab":
		m.findFacet = (m.findFacet + 1) % ffCount
		m.findResSel, m.findResTop = 0, 0
		m.rebuildFindRows()
	case "shift+tab":
		m.findFacet = (m.findFacet + ffCount - 1) % ffCount
		m.findResSel, m.findResTop = 0, 0
		m.rebuildFindRows()
	case "/":
		m.findFiltering = true
		return m, m.findFilter.Focus()
	case "up", "k":
		m.findMoveResSel(-1)
	case "down", "j":
		m.findMoveResSel(1)
	case "enter", " ":
		return m.findJump()
	}
	return m, nil
}

func (m *Model) findMoveResSel(d int) {
	n := len(m.findShown)
	if n == 0 {
		return
	}
	m.findResSel = layout.Clamp(m.findResSel+d, 0, n-1)
}

// findJump navigates to the selected hit in the view its facet belongs to.
func (m *Model) findJump() (tea.Model, tea.Cmd) {
	if m.findResSel < 0 || m.findResSel >= len(m.findShown) {
		return m, nil
	}
	h := m.findHits[m.findShown[m.findResSel]]
	m.findResultsActive = false
	m.cancelFindSearch()
	switch h.facet {
	case ffDisasm:
		m.jumpDisasmAtAddr(h.addr)
	case ffData:
		if h.hasAddr {
			m.openHexAt(h.addr)
		} else {
			m.openRawAt(h.off)
		}
	case ffStrings:
		if h.hasAddr {
			m.jumpStringsAtAddr(h.addr)
		} else {
			m.jumpStringsAtOffset(h.off)
		}
	case ffRelocs:
		m.jumpRelocsAtAddr(h.addr)
	default:
		if h.hasAddr {
			m.gotoAddr(h.addr)
		} else {
			m.openRawAt(h.off)
		}
	}
	return m, nil
}

// findFacetStyle colours a facet badge/tab by its view.
func (m *Model) findFacetStyle(f findFacet) lipgloss.Style {
	switch f {
	case ffDisasm:
		return m.theme.headerKey
	case ffData:
		return m.theme.warnStyle
	case ffStrings:
		return m.theme.infoStyle
	case ffRelocs:
		return m.theme.errorStyle
	default:
		return m.theme.srcShadowStyle
	}
}

// facetStillScanning reports whether the active facet's source scan is still
// running (so an empty list should say "searching", not "no occurrences").
func (m *Model) facetStillScanning() bool {
	if m.findFacet == ffAll {
		return m.findRunning
	}
	return int(m.findFacet) < len(m.findFacetPending) && m.findFacetPending[m.findFacet]
}

// findRunningNote reports how many of the source scans are still in flight, so
// the modal shows that results are still streaming in.
func (m *Model) findRunningNote() string {
	if m.findPending <= 1 {
		return "1 source"
	}
	return fmt.Sprintf("%d sources", m.findPending)
}

// findVisibleRows is the fixed number of result rows, so the modal height is
// constant (no vertical bounce as results stream in or the filter narrows).
func (m *Model) findVisibleRows() int {
	return layout.Clamp(m.height-12, 4, 40)
}

func (m *Model) renderFindResultsModal() string {
	m.ensureFindFilter()
	var sb strings.Builder
	rowW := modalListWidth(m.width)
	visible := m.findVisibleRows()

	sb.WriteString(m.theme.modalTitle("Find " + m.findQuery.label))
	if m.findRunning {
		// Which sources are still scanning (the disasm decode is the slow one).
		sb.WriteString("  " + m.theme.warnStyle.Render("● searching "+m.findRunningNote()))
	} else {
		sb.WriteString("  " + m.theme.infoStyle.Render(fmt.Sprintf("✓ %d found", len(m.findHits))))
	}
	sb.WriteByte('\n')
	sb.WriteByte('\n')
	sb.WriteString(" " + layout.FitANSIWidth(m.findFacetBar(), rowW-1))
	sb.WriteByte('\n')
	countStr := fmt.Sprintf("  %d", len(m.findShown))
	if m.findTotal != len(m.findShown) {
		countStr = fmt.Sprintf("  %d of %d", len(m.findShown), m.findTotal)
	}
	m.findFilter.SetWidth(layout.Clamp(rowW-len(countStr)-4, 12, 60))
	sb.WriteString(" " + layout.FitANSIWidth(m.findFilter.View()+m.theme.modalHint(countStr), rowW-1))
	sb.WriteByte('\n')
	sb.WriteByte('\n')
	m.modalListRow = 5 // title + blank + facet bar + filter + blank

	addrW := m.file.AddrHexWidth()
	blank := layout.PadRight("", rowW)
	if len(m.findShown) == 0 {
		// "No occurrences" only once the active facet's own scan has finished — while
		// its source is still running (the disasm decode, typically) show "searching".
		msg := "no occurrences found"
		if m.facetStillScanning() {
			msg = "searching …"
		}
		for i := 0; i < visible; i++ {
			if i == visible/2 {
				sb.WriteString(centeredModalLine(m.theme.modalHint(msg), rowW) + "\n")
			} else {
				sb.WriteString(blank + "\n")
			}
		}
	} else {
		top := layout.VisualTop(m.findResSel, m.findResTop, len(m.findShown), visible, func(int) int { return 1 })
		m.findResTop = top
		const badgeW = 8
		locW := 2 + addrW
		ctxW := max(6, rowW-1-badgeW-2-locW-2-18)
		for row := 0; row < visible; row++ {
			r := top + row
			if r >= len(m.findShown) {
				sb.WriteString(blank + "\n")
				continue
			}
			h := m.findHits[m.findShown[r]]
			badge := m.findFacetStyle(h.facet).Render(layout.PadVisual(h.facet.String(), badgeW))
			loc := layout.PadVisual("", locW)
			switch {
			case h.hasAddr:
				loc = m.theme.addrStyle.Render(fmt.Sprintf("0x%0*x", addrW, h.addr))
			case h.off != 0 || h.facet == ffData:
				loc = m.theme.srcShadowStyle.Render(fmt.Sprintf("@0x%0*x", addrW-1, h.off))
			}
			ctx := layout.TruncateMiddle(h.text, ctxW)
			sym := ""
			if h.sym != "" {
				sym = "  " + m.theme.srcShadowStyle.Render(layout.TruncateMiddle(h.sym, 16))
			}
			line := layout.PadRight(fmt.Sprintf(" %s  %s  %s%s", badge, loc, ctx, sym), rowW)
			if r == m.findResSel {
				line = m.theme.tableSelStyle.Render(ansi.Strip(line))
			}
			sb.WriteString(line + "\n")
		}
	}

	sb.WriteByte('\n')
	hint := "↑/↓ select · ↵ jump · ⇥ view · / filter · Esc cancel"
	if m.findFiltering {
		hint = "type to filter · ↵ jump · Tab done · Esc clear"
	}
	sb.WriteString(" " + m.theme.modalHint(hint))
	return m.theme.modalStyle.Render(sb.String())
}

// findFacetBar renders the view facets as a segmented control with per-facet
// counts, the active one highlighted.
func (m *Model) findFacetBar() string {
	counts := m.findFacetCounts()
	var b strings.Builder
	for f := findFacet(0); f < ffCount; f++ {
		if f > 0 {
			b.WriteString(m.theme.srcShadowStyle.Render(" "))
		}
		label := f.String()
		if f == ffAll {
			label = fmt.Sprintf("all %d", len(m.findHits))
		} else if counts[f] > 0 {
			label = fmt.Sprintf("%s %d", f.String(), counts[f])
		}
		seg := " " + label + " "
		if f == m.findFacet {
			b.WriteString(m.theme.tableSelStyle.Render(seg))
		} else {
			b.WriteString(m.theme.srcShadowStyle.Render(seg))
		}
	}
	return b.String()
}
