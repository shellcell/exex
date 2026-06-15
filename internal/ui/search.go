package ui

// In-view search: the hex and raw views match byte/text patterns, the disasm
// view matches instruction text and symbol names. The query is remembered so
// n / N can repeat forward / backward.

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	tea "github.com/charmbracelet/bubbletea"
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
	seq       int
	label     string
	query     string
	forward   bool
	inclusive bool
	logical   int
	total     int
	chunk     int
	base      int
}

type disasmSearchProgressMsg struct {
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

const (
	searchModeAuto = iota
	searchModeText
	searchModeHex
)

func searchModeName(mode int) string {
	switch mode {
	case searchModeText:
		return "text"
	case searchModeHex:
		return "hex"
	default:
		return "auto"
	}
}

func (m *Model) cycleSearchMode() {
	m.searchMode = (m.searchMode + 1) % 3
}

// searchSwitch is one clickable toggle in the search popup.
type searchSwitch struct {
	label  string
	toggle func()
}

// searchSwitchSep separates the switch segments; searchSwitchLine is the
// 0-based content row the switch strip occupies inside the modal (hint, blank,
// input, blank, switches, help).
const (
	searchSwitchSep  = "   "
	searchSwitchLine = 4
)

// searchSwitches returns the mode / direction / origin toggles. The render and
// the mouse hit-test both build from this, so they can't drift.
func (m *Model) searchSwitches() []searchSwitch {
	dir := "forward"
	if !m.searchForward {
		dir = "backward"
	}
	origin := "from cursor"
	if !m.searchFromCursor {
		if m.searchForward {
			origin = "from start"
		} else {
			origin = "from end"
		}
	}
	return []searchSwitch{
		{"[ mode: " + searchModeName(m.searchMode) + " ]", m.cycleSearchMode},
		{"[ dir: " + dir + " ]", func() { m.searchForward = !m.searchForward }},
		{"[ origin: " + origin + " ]", func() { m.searchFromCursor = !m.searchFromCursor }},
	}
}

// openSearch opens the search prompt. Repeat search still uses searchQuery via
// n/N, but each new prompt starts empty so stale input is not accidentally reused.
func (m *Model) openSearch() {
	m.searchActive = true
	m.searchInput.SetValue("")
	m.searchInput.Focus()
}

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

// runSearch finds the next/previous match for the current query in the active
// view and moves the cursor onto it. inclusive includes the current position
// (used for the initial Enter); n / N pass inclusive=false to step past it.
func (m *Model) runSearch(forward, inclusive bool) tea.Cmd {
	return m.runSearchWithOrigin(forward, inclusive, true)
}

func (m *Model) runSearchFromPrompt() tea.Cmd {
	inclusive := true
	if !m.searchFromCursor {
		inclusive = false
	}
	return m.runSearchWithOrigin(m.searchForward, inclusive, m.searchFromCursor)
}

func (m *Model) runSearchWithOrigin(forward, inclusive bool, fromCursor bool) tea.Cmd {
	if m.searchQuery == "" {
		m.setStatus("no search query", true)
		return nil
	}
	switch m.mode {
	case modeDisasm:
		if m.sourceFirst && m.srcFile != "" {
			m.searchInSourceFile(forward, inclusive)
			return nil
		}
		return m.startDisasmSearch(forward, inclusive, fromCursor)
	case modeHex:
		m.ensureHex()
		start := m.hexCur
		if !fromCursor {
			if forward {
				start = -1
			} else {
				start = len(m.hexImg.Data) - 1
			}
		}
		m.hexCur = m.searchBytesAt(m.hexImg.Data, start, forward, inclusive)
	case modeRaw:
		m.ensureRaw()
		start := m.rawCur
		if !fromCursor {
			if forward {
				start = -1
			} else {
				start = len(m.rawData) - 1
			}
		}
		m.rawCur = m.searchBytesAt(m.rawData, start, forward, inclusive)
	case modeStrings:
		m.ensureStrings()
		start := m.stringsCur
		if !fromCursor {
			if forward {
				start = 0
			} else {
				start = len(m.stringsList) - 1
			}
		} else if !inclusive {
			if forward {
				start++
			} else {
				start--
			}
		}
		if i := m.searchStrings(start, forward); i >= 0 {
			m.stringsCur = i
			m.setStatus("match: "+truncate(m.stringsList[i].Text, 40), false)
		} else {
			m.setStatus("not found: "+m.searchQuery, true)
		}
	case modeSources:
		if m.srcSearchAll {
			m.searchAllSources(forward, inclusive)
		} else {
			m.searchInSourceFile(forward, inclusive)
		}
	default:
		m.setStatus("search isn't available in this view", true)
	}
	return nil
}

func (m *Model) cancelSearch(status string) {
	m.searchSeq++
	m.searchRunning = false
	m.searchCancelable = false
	m.setStatus(status, false)
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
	m.searchRunning = true
	m.searchCancelable = true
	step := disasmSearchStep{
		seq:       m.searchSeq,
		label:     m.searchQuery,
		query:     strings.ToLower(m.searchQuery),
		forward:   forward,
		inclusive: inclusive,
		total:     img.Len(),
		chunk:     m.disasmSearchChunkBytes(),
		base:      pos,
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
	q := strings.ToLower(strings.TrimSpace(m.searchQuery))
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
	best := uint64(0)
	found := false
	for _, sym := range m.file.Symbols {
		if sym.Addr == 0 {
			continue
		}
		if _, ok := m.file.ExecImage().PosForAddr(sym.Addr); !ok {
			continue
		}
		name := strings.ToLower(sym.Name)
		dem := strings.ToLower(sym.Demangled)
		disp := strings.ToLower(sym.Display())
		if q != name && q != dem && q != disp {
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

func (m *Model) searchBytesAt(data []byte, cur int, forward, inclusive bool) int {
	pat := searchPattern(m.searchQuery, m.searchMode)
	if len(pat) == 0 {
		m.setStatus("empty search pattern", true)
		return cur
	}
	start := cur
	if !inclusive {
		if forward {
			start++
		} else {
			start--
		}
	}
	if i := findBytes(data, pat, start, forward); i >= 0 {
		m.setStatus(fmt.Sprintf("match at offset +0x%x", i), false)
		return i
	}
	m.setStatus("not found: "+m.searchQuery, true)
	return cur
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

func (m *Model) searchDisasmStepCmd(step disasmSearchStep) tea.Cmd {
	img := m.file.ExecImage()
	file := m.file
	query := step.query
	match := func(instText string, addr uint64) bool {
		if strings.Contains(strings.ToLower(instText), query) {
			return true
		}
		if sym, ok := file.SymbolAt(addr); ok && sym.Addr == addr &&
			strings.Contains(strings.ToLower(sym.Display()), query) {
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
		batch := m.disasmSearchBatchChunks()
		if batch < 1 {
			batch = 1
		}
		if step.forward {
			if step.logical >= img.Len() {
				return disasmSearchProgressMsg{seq: step.seq, forward: step.forward, next: step, scannedLo: step.logical, scannedHi: step.logical, done: true}
			}
			var wins []binfile.Window
			logical := step.logical
			for i := 0; i < batch && logical < img.Len(); i++ {
				win := img.Window(logical, step.chunk)
				wins = append(wins, win)
				logical = win.End
			}
			results := make([]chunkResult, len(wins))
			limit := m.disasmSearchWorkersFor(len(wins))
			sem := make(chan struct{}, limit)
			var wg sync.WaitGroup
			for i, win := range wins {
				wg.Add(1)
				sem <- struct{}{}
				go func(i int, win binfile.Window) {
					defer wg.Done()
					defer func() { <-sem }()
					insts := m.disasmDecodeWindow(win)
					results[i] = chunkResult{order: i, win: win, insts: insts}
					startPos := step.logical
					if i > 0 {
						startPos = win.Start
					}
					for j, inst := range insts {
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
				return disasmSearchProgressMsg{seq: step.seq, forward: step.forward, hit: &found[0], found: found, scannedLo: step.logical, scannedHi: logical, done: true}
			}
			next := step
			next.logical = logical
			return disasmSearchProgressMsg{seq: step.seq, forward: step.forward, next: next, scannedLo: step.logical, scannedHi: logical, status: fmt.Sprintf("searching disasm for %q (%d%%, Esc cancels)", step.label, 100*min(next.logical, next.total)/max(1, next.total))}
		}
		if step.logical <= 0 {
			return disasmSearchProgressMsg{seq: step.seq, forward: step.forward, next: step, scannedLo: step.logical, scannedHi: step.logical, done: true}
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
		limit := m.disasmSearchWorkersFor(len(wins))
		sem := make(chan struct{}, limit)
		var wg sync.WaitGroup
		for i, win := range wins {
			wg.Add(1)
			sem <- struct{}{}
			go func(i int, win binfile.Window) {
				defer wg.Done()
				defer func() { <-sem }()
				insts := m.disasmDecodeWindow(win)
				results[i] = chunkResult{order: i, win: win, insts: insts}
				endPos := step.logical
				if i > 0 {
					endPos = win.End
				}
				for j := len(insts) - 1; j >= 0; j-- {
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
			return disasmSearchProgressMsg{seq: step.seq, forward: step.forward, hit: &found[0], found: found, scannedLo: logical, scannedHi: step.logical, done: true}
		}
		next := step
		next.logical = logical
		progress := 100 * (step.total - max(0, next.logical)) / max(1, step.total)
		return disasmSearchProgressMsg{seq: step.seq, forward: step.forward, next: next, scannedLo: logical, scannedHi: step.logical, status: fmt.Sprintf("searching disasm for %q (%d%%, Esc cancels)", step.label, progress)}
	}
}

// findBytes returns the index of pat in data at or after (forward) / at or
// before (backward) start, or -1.
func findBytes(data, pat []byte, start int, forward bool) int {
	if len(pat) == 0 || len(pat) > len(data) {
		return -1
	}
	if forward {
		if start < 0 {
			start = 0
		}
		if start > len(data)-len(pat) {
			return -1
		}
		if j := bytes.Index(data[start:], pat); j >= 0 {
			return start + j
		}
		return -1
	}
	end := start + len(pat)
	if end > len(data) {
		end = len(data)
	}
	if end < len(pat) {
		return -1
	}
	return bytes.LastIndex(data[:end], pat)
}

// searchPattern interprets a query as bytes or text:
//   - "quoted text"   → literal bytes of the text
//   - hex digits / 0x → byte pattern (spaces allowed: "de ad be ef")
//   - anything else   → literal text bytes
func searchPattern(q string, mode int) []byte {
	trimmed := strings.TrimSpace(q)
	if mode == searchModeText {
		if len(trimmed) >= 2 && trimmed[0] == '"' && trimmed[len(trimmed)-1] == '"' {
			return []byte(trimmed[1 : len(trimmed)-1])
		}
		return []byte(q)
	}
	if mode == searchModeHex {
		compact := strings.TrimPrefix(strings.ReplaceAll(trimmed, " ", ""), "0x")
		if len(compact)%2 != 0 || !isHexStr(compact) {
			return nil
		}
		b := make([]byte, len(compact)/2)
		for i := range b {
			v, _ := strconv.ParseUint(compact[2*i:2*i+2], 16, 8)
			b[i] = byte(v)
		}
		return b
	}
	if len(trimmed) >= 2 && trimmed[0] == '"' && trimmed[len(trimmed)-1] == '"' {
		return []byte(trimmed[1 : len(trimmed)-1])
	}
	compact := strings.TrimPrefix(strings.ReplaceAll(trimmed, " ", ""), "0x")
	if q == trimmed && len(compact) >= 2 && len(compact)%2 == 0 && isHexStr(compact) {
		b := make([]byte, len(compact)/2)
		for i := range b {
			v, _ := strconv.ParseUint(compact[2*i:2*i+2], 16, 8)
			b[i] = byte(v)
		}
		return b
	}
	return []byte(q)
}

func isHexStr(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
