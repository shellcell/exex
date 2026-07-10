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
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/bytesearch"
	"github.com/rabarbra/exex/internal/ui/layout"
	findresultsmodal "github.com/rabarbra/exex/internal/ui/modals/findresults"
	findtomodal "github.com/rabarbra/exex/internal/ui/modals/findto"
	"github.com/rabarbra/exex/internal/ui/scope"
	"github.com/rabarbra/exex/internal/ui/views/strs"
)

// findMaxPerFacet caps hits collected per source, so a value that appears
// everywhere (0, a common byte) can't blow up memory or the list.
const findMaxPerFacet = 500

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

// StartTextSearch runs the global search for a typed query. It satisfies
// findquery.Host: the prompt hands over raw text, and the shell decides what it
// means (a 0x… literal is an address; anything else is content).
func (m *Model) StartTextSearch(text string, caseSensitive bool) tea.Cmd {
	m.findQueryCase = caseSensitive
	q := m.queryForText(text)
	if !q.hasAddr && q.text == "" {
		m.setStatus("type something to search for", true)
		return nil
	}
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

// launchFindSearch opens the results overlay and launches the concurrent
// per-source scans for a resolved query — the shared core of the caret-seeded
// (`f`) and free-text (`l`) searches.
//
// disasm/data/relocs each match by address (operand refs / pointer words /
// target) and by text (instruction text / raw bytes / bound symbol); strings by
// text content plus the string at an address. So every source runs whenever the
// query carries either an address or text, which its callers have checked.
func (m *Model) launchFindSearch(q findQuery) tea.Cmd {
	m.stopFindSearch()
	m.findSeq++
	seq := m.findSeq
	done := make(chan struct{})
	m.findCancel = done

	cmds := []tea.Cmd{
		m.findDisasmCmd(q, seq, done),
		m.findDataCmd(q, seq, done),
		m.findStringsCmd(q, seq, done),
		m.findRelocsCmd(q, seq, done),
	}
	m.findResults.Open(q.label, len(cmds))
	m.setStatus("searching for "+q.label+" …", false)
	return tea.Batch(cmds...)
}

// findPartialMsg delivers one source's hits as it finishes, tagged with the facet
// so the modal can mark that view's scan complete (an empty facet whose scan is
// still running shows "searching…", not "no occurrences").
type findPartialMsg struct {
	seq   int
	facet findresultsmodal.Facet
	hits  []findresultsmodal.Hit
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
		hits := make([]findresultsmodal.Hit, 0, len(matches))
		for _, h := range matches {
			hits = append(hits, findresultsmodal.Hit{Facet: findresultsmodal.FacetDisasm, Addr: h.Addr, HasAddr: true, Text: h.Text, Sym: h.Sym})
		}
		return findPartialMsg{seq: seq, facet: findresultsmodal.FacetDisasm, hits: hits}
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
		var hits []findresultsmodal.Hit
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
				h := findresultsmodal.Hit{Facet: findresultsmodal.FacetData, Off: off, Text: p.note}
				if a, ok := addrForOff(off); ok {
					h.Addr, h.HasAddr = a, true
				}
				if sec := sectionAt(off); sec != nil {
					h.Sym = sec.Name
				}
				hits = append(hits, h)
				pos = idx + 1
			}
		}
		return findPartialMsg{seq: seq, facet: findresultsmodal.FacetData, hits: hits}
	}
}

// findStringsCmd finds strings whose bytes contain the seed text, plus — for an
// address query — the string that lives at the target address (so searching an
// address surfaces the string it is, when it is one).
func (m *Model) findStringsCmd(q findQuery, seq int, done <-chan struct{}) tea.Cmd {
	file := m.file
	return func() tea.Msg {
		var hits []findresultsmodal.Hit
		mk := func(e binfile.StringEntry, sym string) findresultsmodal.Hit {
			return findresultsmodal.Hit{Facet: findresultsmodal.FacetStrings, Addr: e.Addr, Off: e.Offset, HasAddr: e.HasAddr, Text: strs.Sanitize(file.StringText(e)), Sym: sym}
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
		return findPartialMsg{seq: seq, facet: findresultsmodal.FacetStrings, hits: hits}
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
		var hits []findresultsmodal.Hit
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
			hits = append(hits, findresultsmodal.Hit{Facet: findresultsmodal.FacetRelocs, Addr: r.Offset, HasAddr: r.Offset != 0, Text: ctx, Sym: r.Section})
		}
		return findPartialMsg{seq: seq, facet: findresultsmodal.FacetRelocs, hits: hits}
	}
}

// handleFindPartial appends one source's hits as it finishes, keeping the list
// live during the search. When the last source reports, the scan is done.
func (m *Model) handleFindPartial(msg findPartialMsg) (tea.Model, tea.Cmd) {
	if msg.seq != m.findSeq || !m.findResults.Running() {
		return m, nil // superseded or cancelled
	}
	if finished := m.findResults.AddHits(msg.facet, msg.hits); finished {
		m.findCancel = nil
		label := m.findResults.Label()
		if n := len(m.findResults.Hits()); n == 0 {
			m.setStatus("no occurrences of "+label, false)
		} else {
			m.setStatus(fmt.Sprintf("%d occurrences of %s", n, label), false)
		}
	}
	return m, nil
}

func (m *Model) stopFindSearch() {
	if m.findCancel != nil {
		close(m.findCancel)
		m.findCancel = nil
	}
}

// CancelSearch abandons any source scans still in flight. It satisfies
// findresults.Host: the overlay closes itself, and the shell stops the work.
func (m *Model) CancelSearch() {
	m.findSeq++
	m.findResults.StopScan()
	m.stopFindSearch()
}

// OpenHit navigates to a hit in the view its facet belongs to. It satisfies
// findresults.Host.
func (m *Model) OpenHit(h findresultsmodal.Hit) {
	switch h.Facet {
	case findresultsmodal.FacetDisasm:
		m.jumpDisasmAtAddr(h.Addr)
	case findresultsmodal.FacetData:
		if h.HasAddr {
			m.openHexAt(h.Addr)
		} else {
			m.openRawAt(h.Off)
		}
	case findresultsmodal.FacetStrings:
		if h.HasAddr {
			m.jumpStringsAtAddr(h.Addr)
		} else {
			m.jumpStringsAtOffset(h.Off)
		}
	case findresultsmodal.FacetRelocs:
		m.jumpRelocsAtAddr(h.Addr)
	default:
		if h.HasAddr {
			m.gotoAddr(h.Addr)
		} else {
			m.openRawAt(h.Off)
		}
	}
}
