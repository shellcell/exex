// Package syntax highlights source files for display in the TUI source pane.
//
// A curated Chroma tokeniser is compiled in only for the default build. The
// `lite` build tag swaps in a small built-in highlighter (highlight_lite.go),
// dropping Chroma while keeping basic source colours.
package syntax

import "sync"

const defaultTheme = "nord"

// Highlighter tokenises source files once and caches their per-line ANSI output.
type Highlighter struct {
	theme string
	mu    sync.RWMutex
	cache map[string][]string
}

// NewHighlighter creates a cached source highlighter. An empty theme selects the
// project default.
func NewHighlighter(theme string) *Highlighter {
	if theme == "" {
		theme = defaultTheme
	}
	return &Highlighter{theme: theme, cache: map[string][]string{}}
}

// Highlight returns ANSI-styled source lines for filename, using a per-filename
// cache. A nil receiver falls back to one-shot highlighting with the default
// theme.
func (h *Highlighter) Highlight(filename string, src []string) []string {
	if h == nil {
		return HighlightLines(filename, src, defaultTheme)
	}
	h.mu.RLock()
	v, ok := h.cache[filename]
	h.mu.RUnlock()
	if ok {
		return v
	}
	hl := HighlightLines(filename, src, h.theme)
	h.mu.Lock()
	h.cache[filename] = hl
	h.mu.Unlock()
	return hl
}
