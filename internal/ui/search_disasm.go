package ui

// The asynchronous, windowed disassembly search engine: a bounded result cache
// with coverage tracking, a symbol-name fast path, and a streaming step command
// that scans the executable image chunk by chunk (cancelable, with progress).
// The generic search prompt + dispatch that drives this lives in search.go.

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	tea "charm.land/bubbletea/v2"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/disasm"
)

type disasmSearchHit struct {
	win   binfile.Window
	insts []disasm.Inst
	idx   int
	addr  uint64
	text  string
}

type disasmSearchStep struct {
	file      *binfile.File
	seq       int
	label     string
	query     string
	forward   bool
	inclusive bool
	logical   int
	total     int
	chunk     int
	base      int
	cancel    <-chan struct{}
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

type disasmSearchCache struct {
	query             string
	hits              []disasmSearchHit
	forwardExhausted  bool
	backwardExhausted bool
	scannedLo         int
	scannedHi         int
	overflow          bool
}

const disasmSearchCacheCap = 100

const (
	searchCursorAtMatch = iota
	searchCursorAfterEnd
	searchCursorBeforeStart
)

func (m *Model) resetDisasmSearchCache(query string) {
	m.searchResults = disasmSearchCache{query: query, scannedLo: -1}
	m.searchCursorMode = searchCursorAtMatch
	m.searchCursorAddr = 0
}

func (m *Model) ensureDisasmSearchCache() {
	if m.searchResults.query != m.searchQuery {
		m.resetDisasmSearchCache(m.searchQuery)
	}
}

func (m *Model) cacheDisasmSearchHits(hits []disasmSearchHit, forward bool) {
	if len(hits) == 0 {
		return
	}
	m.ensureDisasmSearchCache()
	sort.Slice(hits, func(i, j int) bool { return hits[i].addr < hits[j].addr })
	for _, hit := range hits {
		i := sort.Search(len(m.searchResults.hits), func(i int) bool { return m.searchResults.hits[i].addr >= hit.addr })
		if i < len(m.searchResults.hits) && m.searchResults.hits[i].addr == hit.addr {
			continue
		}
		if len(m.searchResults.hits) >= disasmSearchCacheCap {
			m.searchResults.overflow = true
		}
		m.searchResults.hits = append(m.searchResults.hits, disasmSearchHit{})
		copy(m.searchResults.hits[i+1:], m.searchResults.hits[i:])
		m.searchResults.hits[i] = disasmSearchHit{addr: hit.addr, text: hit.text}
	}
	if len(m.searchResults.hits) > disasmSearchCacheCap {
		if forward {
			m.searchResults.hits = m.searchResults.hits[len(m.searchResults.hits)-disasmSearchCacheCap:]
		} else {
			m.searchResults.hits = m.searchResults.hits[:disasmSearchCacheCap]
		}
	}
}

func (m *Model) noteDisasmSearchCoverage(lo, hi int) {
	m.ensureDisasmSearchCache()
	if lo < 0 {
		lo = 0
	}
	if hi < lo {
		hi = lo
	}
	if m.searchResults.scannedLo < 0 || lo < m.searchResults.scannedLo {
		m.searchResults.scannedLo = lo
	}
	if hi > m.searchResults.scannedHi {
		m.searchResults.scannedHi = hi
	}
}

func (m *Model) disasmSearchCacheComplete() bool {
	img := m.file.ExecImage()
	return !m.searchResults.overflow && m.searchResults.scannedLo == 0 && m.searchResults.scannedHi >= img.Len()
}

func (m *Model) cachedDisasmSearchHit(forward, inclusive bool) (disasmSearchHit, bool) {
	m.ensureDisasmSearchCache()
	if len(m.searchResults.hits) == 0 || len(m.disasmInst) == 0 {
		return disasmSearchHit{}, false
	}
	if !forward && m.searchCursorMode == searchCursorAfterEnd {
		return m.searchResults.hits[len(m.searchResults.hits)-1], true
	}
	if forward && m.searchCursorMode == searchCursorBeforeStart {
		return m.searchResults.hits[0], true
	}
	cur := m.disasmInst[m.disasmCur].Addr
	if m.searchCursorAddr != 0 {
		cur = m.searchCursorAddr
	}
	if forward {
		for _, hit := range m.searchResults.hits {
			if (!inclusive && hit.addr <= cur) || (inclusive && hit.addr < cur) {
				continue
			}
			return hit, true
		}
		return disasmSearchHit{}, false
	}
	for i := len(m.searchResults.hits) - 1; i >= 0; i-- {
		hit := m.searchResults.hits[i]
		if (!inclusive && hit.addr >= cur) || (inclusive && hit.addr > cur) {
			continue
		}
		return hit, true
	}
	return disasmSearchHit{}, false
}

func (m *Model) cachedDisasmSearchBoundary(forward bool) (uint64, bool) {
	m.ensureDisasmSearchCache()
	if len(m.searchResults.hits) == 0 {
		return 0, false
	}
	if forward {
		return m.searchResults.hits[len(m.searchResults.hits)-1].addr, true
	}
	return m.searchResults.hits[0].addr, true
}

func (m *Model) startDisasmSearch(forward, inclusive, fromCursor bool) tea.Cmd {
	if len(m.disasmInst) == 0 {
		m.setStatus("no disassembly loaded", true)
		return nil
	}
	m.ensureDisasmSearchCache()
	if fromCursor {
		if hit, ok := m.cachedDisasmSearchHit(forward, inclusive); ok {
			m.loadDisasmAt(hit.addr)
			m.searchCursorMode = searchCursorAtMatch
			m.searchCursorAddr = hit.addr
			m.setStatus("match: "+strings.TrimSpace(hit.text), false)
			return m.prefetchDisasmAroundCmd(hit.addr)
		}
	}
	if fromCursor && forward && m.searchResults.forwardExhausted {
		m.setStatus("not found: "+m.searchQuery, true)
		return nil
	}
	if fromCursor && !forward && m.searchResults.backwardExhausted {
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
	cur := m.disasmInst[m.disasmCur]
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
		file:      m.file,
		seq:       m.searchSeq,
		label:     m.searchQuery,
		query:     canonicalSearchQuery(m.searchQuery),
		forward:   forward,
		inclusive: inclusive,
		total:     img.Len(),
		chunk:     m.disasmSearchChunkBytes(),
		base:      pos,
		cancel:    done,
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

func (m *Model) searchDisasmSymbolFastPath(forward, inclusive, fromCursor bool) (disasmSearchHit, bool) {
	q := strings.TrimSpace(m.searchQuery)
	if q == "" || len(m.disasmInst) == 0 {
		return disasmSearchHit{}, false
	}
	cur := m.disasmInst[m.disasmCur].Addr
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
		if !strings.EqualFold(q, sym.Name) && !(sym.Demangled != "" && strings.EqualFold(q, sym.Demangled)) {
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
		if queryASCII {
			return containsFold(s, query)
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
