//go:build !lite

package syntax

import (
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/alecthomas/chroma/v2"

	"github.com/rabarbra/exex/internal/chromalexers"
	"github.com/rabarbra/exex/internal/chromastyles"
	"github.com/rabarbra/exex/internal/theme"
)

// HighlightLines returns ANSI-styled source lines without using a cache. It uses
// the minimal highlighter when Chroma cannot identify or tokenise the file.
func HighlightLines(filename string, src []string, themeName string) []string {
	if strings.TrimSpace(themeName) == "" {
		themeName = defaultTheme
	}
	lexer := lexerFor(filename, src)
	if lexer == nil {
		// Unknown file type: fall back to the tiny built-in highlighter rather
		// than rendering plain text.
		return minimalHighlight(filename, src, themeName)
	}
	lexer = chroma.Coalesce(lexer)

	st, ok := chromastyles.Lookup(themeName)
	if !ok || st == nil {
		return minimalHighlight(filename, src, themeName)
	}
	fallbackFG := chromaFallbackForeground(themeName)

	it, err := lexer.Tokenise(nil, strings.Join(src, "\n"))
	if err != nil {
		return minimalHighlight(filename, src, themeName)
	}

	// Memoise the lipgloss style per token type: a source file has thousands of
	// tokens but only a handful of distinct types.
	styleFor := map[chroma.TokenType]lipgloss.Style{}
	lines := make([]string, 0, len(src))
	var cur strings.Builder
	for _, tok := range it.Tokens() {
		ls, ok := styleFor[tok.Type]
		if !ok {
			ls = chromaToLipgloss(st.Get(tok.Type), fallbackFG)
			styleFor[tok.Type] = ls
		}
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

// lexerFor picks the Chroma lexer for a file. Assembly sources (.s/.S) are
// special-cased to GAS because ArmAsm and GAS both register that extension, and
// GAS (GNU assembler) is the usual format for those files. Everything else uses
// the normal curated filename match, then content analysis.
func lexerFor(filename string, src []string) chroma.Lexer {
	if lowerExt(filename) == ".s" {
		if l := chromalexers.Get("gas"); l != nil {
			return l
		}
	}
	if l := chromalexers.Match(filename); l != nil {
		return l
	}
	return chromalexers.Analyse(strings.Join(src, "\n"))
}

// chromaToLipgloss converts the subset of Chroma style attributes used here.
func chromaToLipgloss(e chroma.StyleEntry, fallbackFG string) lipgloss.Style {
	s := lipgloss.NewStyle()
	if e.Colour.IsSet() {
		s = s.Foreground(lipgloss.Color(e.Colour.String()))
	} else if fallbackFG != "" {
		s = s.Foreground(lipgloss.Color(fallbackFG))
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

func chromaFallbackForeground(name string) string {
	if p, ok := theme.PaletteFor(strings.TrimSpace(name)); ok {
		return p.Foreground
	}
	if p, ok := theme.PaletteFor(defaultTheme); ok {
		return p.Foreground
	}
	return ""
}
