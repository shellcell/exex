package ui

// The asynchronous, windowed disassembly search engine: a bounded result cache
// with coverage tracking, a symbol-name fast path, and a streaming step command
// that scans the executable image chunk by chunk (cancelable, with progress).
// The generic search prompt + dispatch that drives this lives in search.go.

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	tea "charm.land/bubbletea/v2"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/disasm"
	"github.com/rabarbra/exex/internal/explorer"
	"github.com/rabarbra/exex/internal/ui/layout"
)

type disasmSearchHit struct {
	win   binfile.Window
	insts []disasm.Inst
	idx   int
	addr  uint64
	text  string
}

type disasmSearchStep struct {
	file          *binfile.File
	seq           int
	label         string
	query         string
	caseSensitive bool
	forward       bool
	inclusive     bool
	logical       int
	total         int
	chunk         int
	base          int
	cancel        <-chan struct{}
}

type disasmSearchProgressMsg struct {
	file      *binfile.File
	seq       int
	forward   bool
	next      disasmSearchStep
	hit       *disasmSearchHit
	found     []disasmSearchHit
	scannedLo int
	scannedHi int
	done      bool
	status    string
}

// searchCursorMode values mirror explorer.CursorMode; the shell tracks where the
// search cursor sits so the cache can answer "the next hit" after running off an
// end.
const (
	searchCursorAtMatch     = explorer.CursorAtMatch
	searchCursorAfterEnd    = explorer.CursorAfterEnd
	searchCursorBeforeStart = explorer.CursorBeforeStart
)

// resetDisasmSearchCache / ensureDisasmSearchCache keep the cache aligned with
// the live query; the cache itself lives in internal/explorer.
func (m *Model) resetDisasmSearchCache(query string) {
	m.searchResults.Reset(query)
	m.searchCursorMode = searchCursorAtMatch
	m.searchCursorAddr = 0
}

func (m *Model) ensureDisasmSearchCache() {
	if m.searchResults.EnsureQuery(m.searchQuery) {
		m.searchCursorMode = searchCursorAtMatch
		m.searchCursorAddr = 0
	}
}

// cacheDisasmSearchHits stores the addresses and text of fresh hits. The decoded
// windows that found them are deliberately dropped (see explorer.SearchHit).
func (m *Model) cacheDisasmSearchHits(hits []disasmSearchHit, forward bool) {
	if len(hits) == 0 {
		return
	}
	m.ensureDisasmSearchCache()
	cached := make([]explorer.SearchHit, len(hits))
	for i, h := range hits {
		cached[i] = explorer.SearchHit{Addr: h.addr, Text: h.text}
	}
	m.searchResults.Add(cached, forward)
}

func (m *Model) noteDisasmSearchCoverage(lo, hi int) {
	m.ensureDisasmSearchCache()
	m.searchResults.NoteCoverage(lo, hi)
}

func (m *Model) disasmSearchCacheComplete() bool {
	return m.searchResults.Complete(m.file.ExecImage().Len())
}

// cachedDisasmSearchHit answers a repeat search from the cache when it can.
func (m *Model) cachedDisasmSearchHit(forward, inclusive bool) (explorer.SearchHit, bool) {
	m.ensureDisasmSearchCache()
	if len(m.dasm.Inst) == 0 {
		return explorer.SearchHit{}, false
	}
	cur := m.dasm.Inst[m.dasm.Cur].Addr
	if m.searchCursorAddr != 0 {
		cur = m.searchCursorAddr
	}
	return m.searchResults.Next(cur, m.searchCursorMode, forward, inclusive)
}

func (m *Model) cachedDisasmSearchBoundary(forward bool) (uint64, bool) {
	m.ensureDisasmSearchCache()
	return m.searchResults.Boundary(forward)
}

func (m *Model) startDisasmSearch(forward, inclusive, fromCursor bool) tea.Cmd {
	if len(m.dasm.Inst) == 0 {
		m.setStatus("no disassembly loaded", true)
		return nil
	}
	m.ensureDisasmSearchCache()
	if fromCursor {
		if hit, ok := m.cachedDisasmSearchHit(forward, inclusive); ok {
			m.loadDisasmAt(hit.Addr)
			m.searchCursorMode = searchCursorAtMatch
			m.searchCursorAddr = hit.Addr
			m.setStatus("match: "+strings.TrimSpace(hit.Text), false)
			return m.prefetchDisasmAroundCmd(hit.Addr)
		}
	}
	if fromCursor && m.searchResults.Exhausted(forward) {
		m.setStatus("not found: "+m.searchQuery, true)
		return nil
	}
	if fromCursor && m.disasmSearchCacheComplete() {
		m.setStatus("not found: "+m.searchQuery, true)
		return nil
	}
	if hit, ok := m.searchDisasmSymbolFastPath(forward, inclusive, fromCursor); ok {
		m.cacheDisasmSearchHits([]disasmSearchHit{hit}, forward)
		m.loadDisasmAt(hit.addr)
		m.searchCursorMode = searchCursorAtMatch
		m.searchCursorAddr = hit.addr
		m.setStatus("match: "+strings.TrimSpace(hit.text), false)
		return m.prefetchDisasmAroundCmd(hit.addr)
	}
	img := m.file.ExecImage()
	cur := m.dasm.Inst[m.dasm.Cur]
	pos, ok := img.PosForAddr(cur.Addr)
	if !ok {
		m.setStatus("current disasm address is not in executable image", true)
		return nil
	}
	m.searchSeq++
	m.stopDisasmSearch()
	m.searchRunning = true
	m.searchCancelable = true
	done := make(chan struct{})
	m.searchCancel = done
	step := disasmSearchStep{
		file:          m.file,
		seq:           m.searchSeq,
		label:         m.searchQuery,
		query:         canonicalSearchQuery(m.searchQuery),
		caseSensitive: m.search.CaseSensitive(),
		forward:       forward,
		inclusive:     inclusive,
		total:         img.Len(),
		chunk:         m.disasmSearchChunkBytes(),
		base:          pos,
		cancel:        done,
	}
	if !fromCursor {
		if forward {
			step.logical = 0
		} else {
			step.logical = img.Len()
		}
	} else if forward {
		step.logical = pos
		if !inclusive {
			step.logical += len(cur.Bytes)
		}
	} else {
		step.logical = pos + 1
		if !inclusive {
			step.logical = pos
		}
	}
	if fromCursor {
		if bound, ok := m.cachedDisasmSearchBoundary(forward); ok {
			if p, mapped := img.PosForAddr(bound); mapped {
				if forward {
					step.logical = max(step.logical, p+1)
				} else {
					step.logical = min(step.logical, p)
				}
			}
		}
	}
	m.setStatus(m.disasmSearchStatus(step), false)
	return m.searchDisasmStepCmd(step)
}

// nameMatches compares a search query to a symbol name, honouring case
// sensitivity (the fast path is an exact-name match).
func nameMatches(q, name string, caseSensitive bool) bool {
	if caseSensitive {
		return q == name
	}
	return strings.EqualFold(q, name)
}

func (m *Model) searchDisasmSymbolFastPath(forward, inclusive, fromCursor bool) (disasmSearchHit, bool) {
	q := strings.TrimSpace(m.searchQuery)
	if q == "" || len(m.dasm.Inst) == 0 {
		return disasmSearchHit{}, false
	}
	cur := m.dasm.Inst[m.dasm.Cur].Addr
	if !fromCursor {
		if forward {
			cur = 0
		} else {
			cur = ^uint64(0)
		}
	}
	img := m.file.ExecImage()
	best := uint64(0)
	found := false
	for _, sym := range m.file.Symbols {
		if sym.Addr == 0 {
			continue
		}
		// Cheap, allocation-free name match first (Display is Demangled-or-Name,
		// so checking both covers it); only then the binary-search membership test.
		// Honour case sensitivity so a sensitive search doesn't fast-path to a
		// wrong-case symbol.
		if !nameMatches(q, sym.Name, m.search.CaseSensitive()) &&
			!(sym.Demangled != "" && nameMatches(q, sym.Demangled, m.search.CaseSensitive())) {
			continue
		}
		if _, ok := img.PosForAddr(sym.Addr); !ok {
			continue
		}
		if forward {
			if (!inclusive && sym.Addr <= cur) || (inclusive && sym.Addr < cur) {
				continue
			}
			if !found || sym.Addr < best {
				best = sym.Addr
				found = true
			}
			continue
		}
		if (!inclusive && sym.Addr >= cur) || (inclusive && sym.Addr > cur) {
			continue
		}
		if !found || sym.Addr > best {
			best = sym.Addr
			found = true
		}
	}
	if !found {
		return disasmSearchHit{}, false
	}
	return disasmSearchHit{addr: best, text: m.searchQuery}, true
}

func (m *Model) disasmSearchStatus(step disasmSearchStep) string {
	progress := 0
	if step.total > 0 {
		if step.forward {
			progress = 100 * min(step.logical, step.total) / step.total
		} else {
			progress = 100 * (step.total - max(0, step.logical)) / step.total
		}
	}
	return fmt.Sprintf("searching disasm for %q (%d%%, Esc cancels)", step.label, progress)
}

// canonicalSearchQuery lowercases a disasm query and, when it is a hex literal
// ("0x…" or AT&T "$0x…"), reduces it to "0x" + value with no leading zeros — so
// "0x000106b6", "$0x106b6" and "0x106B6" all match the decoder's canonical
// "0x106b6" in the instruction text. Bare words (including all-hex mnemonics like
// "add") are left as a literal substring.
func canonicalSearchQuery(q string) string {
	q = strings.ToLower(strings.TrimSpace(q))
	s := strings.TrimPrefix(q, "$") // AT&T immediate marker
	if hex, ok := strings.CutPrefix(s, "0x"); ok && hex != "" && len(hex) <= 16 && isAllHexDigits(hex) {
		if v, err := strconv.ParseUint(hex, 16, 64); err == nil {
			return "0x" + strconv.FormatUint(v, 16)
		}
	}
	return q
}

// isAllHexDigits reports whether s is non-empty and entirely ASCII hex digits.
func isAllHexDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return len(s) > 0
}

func (m *Model) searchDisasmStepCmd(step disasmSearchStep) tea.Cmd {
	img := m.file.ExecImage()
	file := m.file
	svc := m.disasmService()
	query := step.query
	queryASCII := true
	for i := 0; i < len(query); i++ {
		if query[i] >= 0x80 {
			queryASCII = false
			break
		}
	}
	matchText := func(s string) bool {
		if step.caseSensitive {
			return strings.Contains(s, step.label) // exact, case-sensitive
		}
		if queryASCII {
			return layout.ContainsFold(s, query)
		}
		return strings.Contains(strings.ToLower(s), query)
	}
	match := func(instText string, addr uint64) bool {
		if matchText(instText) {
			return true
		}
		if sym, ok := file.SymbolAt(addr); ok && sym.Addr == addr && matchText(sym.Display()) {
			return true
		}
		return false
	}
	type chunkResult struct {
		order int
		win   binfile.Window
		insts []disasm.Inst
		hits  []disasmSearchHit
	}
	return func() tea.Msg {
		if scanCancelled(step.cancel) {
			return disasmSearchProgressMsg{file: step.file, seq: step.seq, forward: step.forward, done: true}
		}
		batch := svc.SearchBatchChunks()
		if batch < 1 {
			batch = 1
		}
		if step.forward {
			if step.logical >= img.Len() {
				return disasmSearchProgressMsg{file: step.file, seq: step.seq, forward: step.forward, next: step, scannedLo: step.logical, scannedHi: step.logical, done: true}
			}
			var wins []binfile.Window
			logical := step.logical
			for i := 0; i < batch && logical < img.Len(); i++ {
				win := img.Window(logical, step.chunk)
				wins = append(wins, win)
				logical = win.End
			}
			results := make([]chunkResult, len(wins))
			limit := svc.SearchWorkersFor(len(wins))
			sem := make(chan struct{}, limit)
			var wg sync.WaitGroup
			for i, win := range wins {
				if scanCancelled(step.cancel) {
					break
				}
				wg.Add(1)
				sem <- struct{}{}
				go func(i int, win binfile.Window) {
					defer wg.Done()
					defer func() { <-sem }()
					if scanCancelled(step.cancel) {
						return
					}
					insts := svc.DecodeWindow(win)
					results[i] = chunkResult{order: i, win: win, insts: insts}
					startPos := step.logical
					if i > 0 {
						startPos = win.Start
					}
					for j, inst := range insts {
						if scanCancelled(step.cancel) {
							return
						}
						instPos, ok := img.PosForAddr(inst.Addr)
						if !ok || instPos < startPos {
							continue
						}
						if match(inst.Text, inst.Addr) {
							results[i].hits = append(results[i].hits, disasmSearchHit{win: win, insts: insts, idx: j, addr: inst.Addr, text: inst.Text})
						}
					}
				}(i, win)
			}
			wg.Wait()
			var found []disasmSearchHit
			for _, res := range results {
				if len(res.hits) > 0 {
					found = append(found, res.hits...)
				}
			}
			if len(found) > 0 {
				return disasmSearchProgressMsg{file: step.file, seq: step.seq, forward: step.forward, hit: &found[0], found: found, scannedLo: step.logical, scannedHi: logical, done: true}
			}
			next := step
			next.logical = logical
			return disasmSearchProgressMsg{file: step.file, seq: step.seq, forward: step.forward, next: next, scannedLo: step.logical, scannedHi: logical, status: fmt.Sprintf("searching disasm for %q (%d%%, Esc cancels)", step.label, 100*min(next.logical, next.total)/max(1, next.total))}
		}
		if step.logical <= 0 {
			return disasmSearchProgressMsg{file: step.file, seq: step.seq, forward: step.forward, next: step, scannedLo: step.logical, scannedHi: step.logical, done: true}
		}
		var wins []binfile.Window
		logical := step.logical
		for i := 0; i < batch && logical > 0; i++ {
			start := max(0, logical-step.chunk)
			win := img.Window(start, logical-start)
			wins = append(wins, win)
			logical = win.Start
		}
		results := make([]chunkResult, len(wins))
		limit := svc.SearchWorkersFor(len(wins))
		sem := make(chan struct{}, limit)
		var wg sync.WaitGroup
		for i, win := range wins {
			if scanCancelled(step.cancel) {
				break
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(i int, win binfile.Window) {
				defer wg.Done()
				defer func() { <-sem }()
				if scanCancelled(step.cancel) {
					return
				}
				insts := svc.DecodeWindow(win)
				results[i] = chunkResult{order: i, win: win, insts: insts}
				endPos := step.logical
				if i > 0 {
					endPos = win.End
				}
				for j := len(insts) - 1; j >= 0; j-- {
					if scanCancelled(step.cancel) {
						return
					}
					inst := insts[j]
					instPos, ok := img.PosForAddr(inst.Addr)
					if !ok || instPos >= endPos {
						continue
					}
					if match(inst.Text, inst.Addr) {
						results[i].hits = append(results[i].hits, disasmSearchHit{win: win, insts: insts, idx: j, addr: inst.Addr, text: inst.Text})
					}
				}
			}(i, win)
		}
		wg.Wait()
		var found []disasmSearchHit
		for _, res := range results {
			if len(res.hits) > 0 {
				found = append(found, res.hits...)
			}
		}
		if len(found) > 0 {
			return disasmSearchProgressMsg{file: step.file, seq: step.seq, forward: step.forward, hit: &found[0], found: found, scannedLo: logical, scannedHi: step.logical, done: true}
		}
		next := step
		next.logical = logical
		progress := 100 * (step.total - max(0, next.logical)) / max(1, step.total)
		return disasmSearchProgressMsg{file: step.file, seq: step.seq, forward: step.forward, next: next, scannedLo: logical, scannedHi: step.logical, status: fmt.Sprintf("searching disasm for %q (%d%%, Esc cancels)", step.label, progress)}
	}
}
