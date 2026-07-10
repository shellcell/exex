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
	"bytes"
	"fmt"
	"sort"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/bytesearch"
	"github.com/rabarbra/exex/internal/ui/layout"
	"github.com/rabarbra/exex/internal/ui/modal"
	findtomodal "github.com/rabarbra/exex/internal/ui/modals/findto"
	"github.com/rabarbra/exex/internal/ui/scope"
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
	label         string // e.g. "_main", "0x1000" — for the modal title
	addr          uint64
	hasAddr       bool
	text          string
	caseSensitive bool // text matching honours case (default off for the l search)
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

// openFindQuery opens the free-text global-search prompt (the `l` key): type any
// value — a symbol name, a string, or a hex/decimal address — and it runs the
// same content scan `f` does, seeded by the typed query instead of the caret.
func (m *Model) openFindQuery() {
	if m.findQueryInput.Prompt == "" {
		m.findQueryInput = newPromptInput("symbol · string · 0xaddr", "search ")
	}
	m.findQueryInput.SetValue("")
	m.findQueryActive = true
	m.findQueryInput.Focus()
}

// updateFindQuery drives the free-text prompt: Enter runs the search, ^i toggles
// case sensitivity, Esc closes.
func (m *Model) updateFindQuery(msg tea.KeyMsg, key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc":
		m.findQueryActive = false
		m.findQueryInput.Blur()
		return m, nil
	case "ctrl+i":
		m.findQueryCase = !m.findQueryCase
		return m, nil
	case "enter":
		q := m.queryForText(strings.TrimSpace(m.findQueryInput.Value()))
		m.findQueryActive = false
		m.findQueryInput.Blur()
		if !q.hasAddr && q.text == "" {
			m.setStatus("type something to search for", true)
			return m, nil
		}
		return m, m.startFindSearchQuery(q)
	}
	var cmd tea.Cmd
	m.findQueryInput, cmd = m.findQueryInput.Update(msg)
	return m, cmd
}

// queryForText interprets a free-text query: a 0x-prefixed literal is an address
// (searched as an address across disasm/data/relocs + the string at it); anything
// else is a literal text/byte search across disasm text, string content, and the
// raw file bytes. Text is not resolved to a symbol — an address is only ever a
// 0x… value, so plain words search content, not the symbol table.
func (m *Model) queryForText(s string) findQuery {
	if s == "" {
		return findQuery{}
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		if a, err := parseAddr(s); err == nil {
			return findQuery{label: s, addr: a, hasAddr: true}
		}
	}
	return findQuery{label: s, text: s, caseSensitive: m.findQueryCase}
}

// startFindSearchQuery runs the global search for an already-built query (the
// free-text path); startFindSearch builds one from a seed first.
func (m *Model) startFindSearchQuery(q findQuery) tea.Cmd {
	return m.launchFindSearch(q)
}

// queryForSeed resolves a chosen seed into a search query. Seed searches are
// case-sensitive: a seed is an exact value taken from the binary (a symbol name,
// a string), so its case is meaningful.
func (m *Model) queryForSeed(s findtomodal.Seed) findQuery {
	q := findQuery{label: s.Preview, caseSensitive: true}
	switch s.Scope {
	case scope.Addr:
		if a, err := parseAddr(s.Value); err == nil {
			q.addr, q.hasAddr = a, true
		}
		q.label = s.Value
	default:
		// Symbol / String / Section / Library seeds carry text, and an address when
		// the seed named a located thing.
		q.text = s.Value
		q.addr, q.hasAddr = s.Addr, s.HasAddr
	}
	return q
}

// StartSearch opens the results modal and launches the per-source scans for the
// selected seed. Each applicable source runs as its own command, so tea.Batch
// executes them concurrently and their hits stream into the list as each
// finishes — the fast data/strings/relocs scans appear almost immediately while
// the disasm decode (the slow one) fills in when it completes.
//
// It satisfies findto.Host. Closing the seed picker first is what keeps the
// picker and the results overlay from both being open (see modalOrder).
func (m *Model) StartSearch(s findtomodal.Seed) tea.Cmd {
	m.find.Close()
	q := m.queryForSeed(s)
	if !q.hasAddr && q.text == "" {
		m.setStatus("nothing searchable in that seed", true)
		return nil
	}
	return m.launchFindSearch(q)
}

// launchFindSearch opens the results modal and launches the concurrent per-source
// scans for a resolved query — the shared core of the caret-seeded (`f`) and
// free-text (`l`) searches.
func (m *Model) launchFindSearch(q findQuery) tea.Cmd {
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

	// disasm/data/relocs each match by address (operand refs / pointer words /
	// target) and by text (instruction text / raw bytes / bound symbol); strings by
	// text content plus the string at an address. So every source runs whenever the
	// query carries either an address or text.
	any := q.hasAddr || q.text != ""
	m.findFacetPending = [5]bool{}
	var cmds []tea.Cmd
	if any {
		cmds = append(cmds,
			m.findDisasmCmd(q, seq, done),
			m.findDataCmd(q, seq, done),
			m.findStringsCmd(q, seq, done),
			m.findRelocsCmd(q, seq, done),
		)
		m.findFacetPending[ffDisasm] = true
		m.findFacetPending[ffData] = true
		m.findFacetPending[ffStrings] = true
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

// textMatcher returns a predicate testing whether a string contains the query's
// text, honouring its case-sensitivity flag (case-insensitive folds against a
// pre-lowered needle with no per-call allocation). Empty text never matches.
func textMatcher(q findQuery) func(string) bool {
	if q.text == "" {
		return func(string) bool { return false }
	}
	if q.caseSensitive {
		needle := q.text
		return func(s string) bool { return strings.Contains(s, needle) }
	}
	lower := strings.ToLower(q.text)
	return func(s string) bool { return layout.ContainsFold(s, lower) }
}

// bytesMatcher is textMatcher over raw bytes, for the string table (whose entries
// are byte slices into the mapped image, so testing them never allocates a
// string). Both branches are chosen once, up front: the scan used to run the
// case-insensitive fold over every string in the binary and then discard the
// result whenever the query was case-sensitive — which seed searches always are.
func bytesMatcher(q findQuery) func([]byte) bool {
	if q.text == "" {
		return func([]byte) bool { return false }
	}
	if q.caseSensitive {
		needle := []byte(q.text)
		return func(b []byte) bool { return bytes.Contains(b, needle) }
	}
	lower := strings.ToLower(q.text)
	return func(b []byte) bool { return layout.ContainsFoldBytes(b, lower) }
}

// findDisasmCmd scans the executable image for instructions matching the query:
// operand references to the address (an address query) and/or instruction text
// containing the search text (a free-text query). The slowest source.
func (m *Model) findDisasmCmd(q findQuery, seq int, done <-chan struct{}) tea.Cmd {
	svc := m.disasmService()
	textMatch := textMatcher(q)
	return func() tea.Msg {
		match := func(text string) bool {
			if q.hasAddr && instReferences(text, q.addr) {
				return true
			}
			return textMatch(text)
		}
		matches := svc.ScanMatching(match, findMaxPerFacet, done)
		hits := make([]findHit, 0, len(matches))
		for _, h := range matches {
			hits = append(hits, findHit{facet: ffDisasm, addr: h.Addr, hasAddr: true, text: h.Text, sym: h.Sym})
		}
		return findPartialMsg{seq: seq, facet: ffDisasm, hits: hits}
	}
}

// findDataCmd finds byte occurrences in the file image: the address as a
// pointer-width little-endian word (an address query) and/or the search text as
// raw ASCII bytes (a free-text query) — the hex/raw facet.
func (m *Model) findDataCmd(q findQuery, seq int, done <-chan struct{}) tea.Cmd {
	file := m.file
	ptrBytes := m.file.PointerBytes()
	sectionAt := m.sectionAtOffset
	addrForOff := m.addrForOffset
	return func() tea.Msg {
		raw := file.Raw()
		var hits []findHit
		// Each pattern to look for, with the note shown for a hit and whether it
		// folds ASCII case. fold is a field rather than being re-derived from note:
		// it used to be `p.note == "bytes"`, which keyed matching semantics off a
		// display string, so renaming the note in the UI would silently change how
		// the search matched.
		type pat struct {
			bytes []byte
			note  string
			fold  bool
		}
		var pats []pat
		if q.hasAddr {
			pb := make([]byte, ptrBytes)
			v := q.addr
			for i := range pb {
				pb[i] = byte(v)
				v >>= 8
			}
			// The pointer word is a binary value: folding it would match byte values
			// that merely differ by 0x20.
			pats = append(pats, pat{bytes: pb, note: "pointer word", fold: false})
		}
		if q.text != "" {
			pats = append(pats, pat{bytes: []byte(q.text), note: "bytes", fold: !q.caseSensitive})
		}
		// findMaxPerFacet caps the facet, not each pattern: an address+text query
		// used to run the counter per pattern and could return 2× the documented cap.
		for _, p := range pats {
			if len(p.bytes) == 0 {
				continue
			}
			for pos := 0; len(hits) < findMaxPerFacet; {
				if scanCancelled(done) {
					break
				}
				idx := bytesearch.FindBytesFold(raw, p.bytes, pos, true, p.fold)
				if idx < 0 {
					break
				}
				off := uint64(idx)
				h := findHit{facet: ffData, off: off, text: p.note}
				if a, ok := addrForOff(off); ok {
					h.addr, h.hasAddr = a, true
				}
				if sec := sectionAt(off); sec != nil {
					h.sym = sec.Name
				}
				hits = append(hits, h)
				pos = idx + 1
			}
		}
		return findPartialMsg{seq: seq, facet: ffData, hits: hits}
	}
}

// findStringsCmd finds strings whose bytes contain the seed text, plus — for an
// address query — the string that lives at the target address (so searching an
// address surfaces the string it is, when it is one).
func (m *Model) findStringsCmd(q findQuery, seq int, done <-chan struct{}) tea.Cmd {
	file := m.file
	return func() tea.Msg {
		var hits []findHit
		mk := func(e binfile.StringEntry, sym string) findHit {
			return findHit{facet: ffStrings, addr: e.Addr, off: e.Offset, hasAddr: e.HasAddr, text: strs.Sanitize(file.StringText(e)), sym: sym}
		}
		if q.hasAddr {
			for _, e := range file.Strings() {
				if e.HasAddr && q.addr >= e.Addr && q.addr < e.Addr+uint64(e.Len) {
					hits = append(hits, mk(e, "at target"))
					break
				}
			}
		}
		if q.text != "" {
			matches := bytesMatcher(q)
			for _, e := range file.Strings() {
				if len(hits) >= findMaxPerFacet || scanCancelled(done) {
					break
				}
				if !matches(file.StringBytes(e)) {
					continue
				}
				hits = append(hits, mk(e, e.Section))
			}
		}
		return findPartialMsg{seq: seq, facet: ffStrings, hits: hits}
	}
}

// findRelocsCmd finds relocations patching the address or binding the symbol.
//
// The symbol test is a substring match honouring the query's case sensitivity,
// like every other facet. It used to be an exact `==` that ignored the flag, so
// searching "malloc" found it in disasm, data and strings but never in the
// relocation that binds `malloc@GLIBC_2.2.5` — the one place the name is most
// likely to be decorated.
func (m *Model) findRelocsCmd(q findQuery, seq int, done <-chan struct{}) tea.Cmd {
	file := m.file
	symMatch := textMatcher(q)
	return func() tea.Msg {
		var hits []findHit
		for _, r := range file.Relocations() {
			if len(hits) >= findMaxPerFacet || scanCancelled(done) {
				break
			}
			if !((q.hasAddr && r.Offset == q.addr) || symMatch(r.Sym)) {
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

// renderFindQueryModal draws the free-text search prompt.
func (m *Model) renderFindQueryModal() string {
	rowW := modalListWidth(m.width)
	var sb strings.Builder
	sb.WriteString(m.theme.modalTitle("Search the binary"))
	sb.WriteByte('\n')
	sb.WriteByte('\n')
	sb.WriteString(" " + m.findQueryInput.View())
	sb.WriteByte('\n')
	sb.WriteByte('\n')
	caseTag := m.theme.modalHint("case-insensitive")
	if m.findQueryCase {
		caseTag = m.theme.warnStyle.Render("case-sensitive")
	}
	sb.WriteString(" " + caseTag + m.theme.modalHint("  (^i)") + "\n")
	sb.WriteByte('\n')
	sb.WriteString(" " + m.theme.modalHint("↵ search disasm · data · strings · relocs   ·   Esc cancel"))
	return m.theme.modalStyle.Render(layout.PadRight(sb.String(), rowW))
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
				sb.WriteString(modal.CenterLine(m.theme.modalHint(msg), rowW) + "\n")
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
