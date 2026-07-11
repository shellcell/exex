// Package syntax highlights source files for display in the TUI source pane.
//
// A curated Chroma tokeniser is compiled in only for the default build. The
// `lite` build tag swaps in a small built-in highlighter (highlight_lite.go),
// dropping Chroma while keeping basic source colours.
package syntax

import (
	"container/list"
	"sync"
	"unsafe"

	"github.com/rabarbra/exex/internal/theme"
)

// defaultTheme is the style used when the caller names none.
const defaultTheme = theme.DefaultName

// Highlighter tokenises source files and caches recent per-line ANSI output.
type Highlighter struct {
	theme      string
	mu         sync.Mutex
	cache      map[string]*list.Element
	lru        list.List
	cacheBytes int
	budget     int
	maxEntries int
}

type highlightCacheEntry struct {
	filename string
	lines    []string
	weight   int
}

const (
	defaultHighlightCacheBudget  = 64 << 20
	defaultHighlightCacheEntries = 32
)

// NewHighlighter creates a cached source highlighter. An empty theme selects the
// project default.
func NewHighlighter(theme string) *Highlighter {
	if theme == "" {
		theme = defaultTheme
	}
	return &Highlighter{
		theme:      theme,
		cache:      map[string]*list.Element{},
		budget:     defaultHighlightCacheBudget,
		maxEntries: defaultHighlightCacheEntries,
	}
}

// Highlight returns ANSI-styled source lines for filename, using a per-filename
// cache. A nil receiver falls back to one-shot highlighting with the default
// theme.
func (h *Highlighter) Highlight(filename string, src []string) []string {
	if h == nil {
		return HighlightLines(filename, src, defaultTheme)
	}
	h.mu.Lock()
	if h.cache == nil {
		h.cache = map[string]*list.Element{}
	}
	if h.budget <= 0 {
		h.budget = defaultHighlightCacheBudget
	}
	if h.maxEntries <= 0 {
		h.maxEntries = defaultHighlightCacheEntries
	}
	if elem := h.cache[filename]; elem != nil {
		h.lru.MoveToFront(elem)
		lines := elem.Value.(*highlightCacheEntry).lines
		h.mu.Unlock()
		return lines
	}
	h.mu.Unlock()
	hl := HighlightLines(filename, src, h.theme)
	weight := cap(hl) * int(unsafe.Sizeof(""))
	for _, line := range hl {
		weight += len(line)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if elem := h.cache[filename]; elem != nil {
		h.lru.MoveToFront(elem)
		return elem.Value.(*highlightCacheEntry).lines
	}
	entry := &highlightCacheEntry{filename: filename, lines: hl, weight: weight}
	h.cache[filename] = h.lru.PushFront(entry)
	h.cacheBytes += weight
	for h.lru.Len() > 1 && (h.cacheBytes > h.budget || h.lru.Len() > h.maxEntries) {
		oldest := h.lru.Back()
		old := oldest.Value.(*highlightCacheEntry)
		delete(h.cache, old.filename)
		h.lru.Remove(oldest)
		h.cacheBytes -= old.weight
	}
	return hl
}
