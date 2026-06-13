package ui

// Source syntax highlighting for the disasm view's side pane. Each source file
// is tokenised once by chroma (language picked from the filename, falling back
// to content analysis) and rendered to per-line ANSI strings, cached so the
// pane can redraw every frame without re-tokenising.

import (
	"strings"

	"github.com/alecthomas/chroma/v2"
	"github.com/alecthomas/chroma/v2/lexers"
	"github.com/alecthomas/chroma/v2/styles"
	"github.com/charmbracelet/lipgloss"
)

// syntaxTheme is the chroma style used for highlighting. ApplyColors overrides
// it from config (colors.syntax_theme); an unknown name falls back gracefully.
var syntaxTheme = "catppuccin-mocha"

// highlightedSource returns file's source highlighted line-by-line, or nil when
// no lexer matches (the caller then renders the plain text). Results are cached.
func (m *Model) highlightedSource(file string, src []string) []string {
	if m.srcHL == nil {
		m.srcHL = map[string][]string{}
	}
	if v, ok := m.srcHL[file]; ok {
		return v
	}
	hl := highlightLines(file, src)
	m.srcHL[file] = hl
	return hl
}

func highlightLines(filename string, src []string) []string {
	lexer := lexers.Match(filename)
	if lexer == nil {
		lexer = lexers.Analyse(strings.Join(src, "\n"))
	}
	if lexer == nil {
		return nil
	}
	lexer = chroma.Coalesce(lexer)

	st := styles.Get(syntaxTheme)
	if st == nil {
		st = styles.Fallback
	}

	it, err := lexer.Tokenise(nil, strings.Join(src, "\n"))
	if err != nil {
		return nil
	}

	// Memoise the lipgloss style per token type — a source file has thousands
	// of tokens but only a handful of distinct types.
	styleFor := map[chroma.TokenType]lipgloss.Style{}
	lines := make([]string, 0, len(src))
	var cur strings.Builder
	for _, tok := range it.Tokens() {
		ls, ok := styleFor[tok.Type]
		if !ok {
			ls = chromaToLipgloss(st.Get(tok.Type))
			styleFor[tok.Type] = ls
		}
		// A token's value may span newlines; flush a line at each break.
		parts := strings.Split(tok.Value, "\n")
		for i, p := range parts {
			if i > 0 {
				lines = append(lines, cur.String())
				cur.Reset()
			}
			if p != "" {
				cur.WriteString(ls.Render(p))
			}
		}
	}
	lines = append(lines, cur.String())
	return lines
}

func chromaToLipgloss(e chroma.StyleEntry) lipgloss.Style {
	s := lipgloss.NewStyle()
	if e.Colour.IsSet() {
		s = s.Foreground(lipgloss.Color(e.Colour.String()))
	}
	if e.Bold == chroma.Yes {
		s = s.Bold(true)
	}
	if e.Italic == chroma.Yes {
		s = s.Italic(true)
	}
	if e.Underline == chroma.Yes {
		s = s.Underline(true)
	}
	return s
}
