//go:build !lite

package asmhl

// Default build: Chroma-based assembly syntax highlighting from the curated
// lexer/style set. The `lite` build (asmhl_lite.go) swaps in a small
// theme-driven token highlighter and drops Chroma entirely.

import (
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/alecthomas/chroma/v2"

	"github.com/shellcell/exex/internal/arch"
	"github.com/shellcell/exex/internal/chromalexers"
	"github.com/shellcell/exex/internal/chromastyles"
	"github.com/shellcell/exex/internal/disasm"
	"github.com/shellcell/exex/internal/syntax"
)

// lexers caches the Chroma asm lexer per architecture. Keying by arch (rather
// than a single global) means opening a different-arch binary in the same process
// — e.g. a library via the Libs view's "open as primary" — gets the right lexer
// instead of reusing the first file's.
var lexers = map[arch.Arch]chroma.Lexer{}

// lexerFor returns the asm lexer for a, building and caching it (even when nil)
// on first use.
func lexerFor(a arch.Arch) chroma.Lexer {
	if l, ok := lexers[a]; ok {
		return l
	}
	l := newLexer(a)
	lexers[a] = l
	return l
}

func newLexer(a arch.Arch) chroma.Lexer {
	names := []string{"ArmAsm", "GAS", "asm", "NASM"}
	switch a {
	case disasm.ArchX86, disasm.ArchAMD64, disasm.ArchRISCV64:
		names = append([]string{"GAS"}, names...)
	case disasm.ArchARM64:
		names = append([]string{"ArmAsm"}, names...)
	}
	for _, name := range names {
		if lexer := chromalexers.Get(name); lexer != nil {
			return chroma.Coalesce(lexer)
		}
	}
	return nil
}

type chromaHighlighter struct {
	st Styles

	// styled is false when the theme has no bundled Chroma style, or the
	// architecture has no asm lexer: every line then falls back to renderByClass.
	styled bool
	lexer  chroma.Lexer
	style  *chroma.Style

	// tokenStyles memoises Chroma token-type → lipgloss style. A screenful of
	// instructions has thousands of tokens but a handful of distinct types.
	tokenStyles map[chroma.TokenType]lipgloss.Style
	fallbackFG  string
}

// newHighlighter resolves the theme's Chroma style and the architecture's asm
// lexer once. A highlighter is rebuilt (not mutated) when the theme changes, so
// its caches can never be stale.
func newHighlighter(themeName, fallbackFG string, a arch.Arch, st Styles) Highlighter {
	h := &chromaHighlighter{st: st, fallbackFG: fallbackFG, tokenStyles: map[chroma.TokenType]lipgloss.Style{}}
	style, ok := chromastyles.Lookup(themeName)
	if !ok || style == nil {
		return h // no bundled style: class colours only
	}
	lexer := lexerFor(a)
	if lexer == nil {
		return h // no asm lexer for this architecture
	}
	h.style, h.lexer, h.styled = style, lexer, true
	return h
}

func (h *chromaHighlighter) Render(text string, class disasm.InstClass, spans []Span) string {
	if !h.styled {
		return renderByClass(text, class, spans, h.st)
	}
	tokens, err := chroma.Tokenise(h.lexer, nil, text)
	if err != nil {
		return renderByClass(text, class, spans, h.st)
	}
	pos := 0
	var b strings.Builder
	for _, tok := range tokens {
		if tok == chroma.EOF {
			break
		}
		b.WriteString(h.renderToken(tok, pos, spans))
		pos += len(tok.Value)
	}
	return b.String()
}

// renderToken draws one Chroma token, splitting it wherever a link span overlaps
// so the address literal keeps its link colour.
func (h *chromaHighlighter) renderToken(tok chroma.Token, pos int, spans []Span) string {
	st := h.tokenStyle(tok.Type)
	from := 0
	var b strings.Builder
	for _, span := range spans {
		lo := max(span.Start, pos)
		hi := min(span.End, pos+len(tok.Value))
		if hi <= lo {
			continue
		}
		if rel := lo - pos; rel > from {
			b.WriteString(st.Render(tok.Value[from:rel]))
		}
		b.WriteString(span.Style.Render(tok.Value[lo-pos : hi-pos]))
		from = hi - pos
	}
	if from < len(tok.Value) {
		b.WriteString(st.Render(tok.Value[from:]))
	}
	return b.String()
}

func (h *chromaHighlighter) tokenStyle(tt chroma.TokenType) lipgloss.Style {
	if st, ok := h.tokenStyles[tt]; ok {
		return st
	}
	st := syntax.StyleEntryToLipgloss(h.style.Get(tt), h.fallbackFG)
	h.tokenStyles[tt] = st
	return st
}
