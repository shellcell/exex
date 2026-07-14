package ui

import "github.com/shellcell/exex/internal/syntax"

// highlightedSource returns file's source highlighted line-by-line, or nil when
// no lexer matches (the caller then renders the plain text). Results are cached.
func (m *Model) highlightedSource(file string, src []string) []string {
	if m.srcHighlighter == nil {
		m.srcHighlighter = syntax.NewHighlighter(sourceSyntaxTheme(m.cfg))
	}
	return m.srcHighlighter.Highlight(file, src)
}
