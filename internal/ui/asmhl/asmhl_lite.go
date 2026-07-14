//go:build lite

package asmhl

// Lite build: a small, theme-driven assembly highlighter that replaces Chroma.
// It colours the mnemonic by instruction class, followable mapped addresses by
// their link colour, and operand registers / immediates by the theme's
// (configurable) asm token colours — so it still follows the active preset and
// any `colors:` overrides, without Chroma's embedded lexer data.

import (
	"strings"

	"github.com/shellcell/exex/internal/arch"
	"github.com/shellcell/exex/internal/disasm"
)

// operandKeywords are operand-position size/scope specifiers that read better
// left uncoloured than tinted as registers.
var operandKeywords = map[string]bool{
	"ptr": true, "byte": true, "word": true, "dword": true, "qword": true,
	"tword": true, "oword": true, "xmmword": true, "ymmword": true, "zmmword": true,
	"near": true, "far": true, "short": true,
}

type liteHighlighter struct{ st Styles }

// newHighlighter ignores the theme name, fallback colour and architecture: the
// lite build has no Chroma style or lexer to select.
func newHighlighter(_, _ string, _ arch.Arch, st Styles) Highlighter {
	return liteHighlighter{st: st}
}

func (h liteHighlighter) Render(text string, class disasm.InstClass, spans []Span) string {
	st := h.st
	var b strings.Builder
	n := len(text)

	// Mnemonic: the leading non-space run, coloured by instruction class.
	i := 0
	for i < n && (text[i] == ' ' || text[i] == '\t') {
		b.WriteByte(text[i])
		i++
	}
	mnStart := i
	for i < n && text[i] != ' ' && text[i] != '\t' {
		i++
	}
	if mnStart < i {
		b.WriteString(st.Class(class).Render(text[mnStart:i]))
	}

	for i < n {
		if sp, ok := spanAt(spans, i); ok {
			b.WriteString(sp.Style.Render(text[i:sp.End]))
			i = sp.End
			continue
		}
		c := text[i]
		switch {
		case c == ' ' || c == '\t':
			j := i + 1
			for j < n && (text[j] == ' ' || text[j] == '\t') {
				j++
			}
			b.WriteString(st.Plain.Render(text[i:j]))
			i = j
		case c == '%': // AT&T register (%rax, %xmm0)
			j := i + 1
			for j < n && isIdentChar(text[j]) {
				j++
			}
			b.WriteString(st.Register.Render(text[i:j]))
			i = j
		case c == '$' || c == '#': // immediate prefix (AT&T $, ARM #)
			j := i + 1
			for j < n && isNumChar(text[j]) {
				j++
			}
			b.WriteString(st.Number.Render(text[i:j]))
			i = j
		case c >= '0' && c <= '9':
			j := i + 1
			for j < n && isNumChar(text[j]) {
				j++
			}
			b.WriteString(st.Number.Render(text[i:j]))
			i = j
		case isIdentStart(c):
			j := i + 1
			for j < n && isIdentChar(text[j]) {
				j++
			}
			tok := text[i:j]
			if operandKeywords[strings.ToLower(tok)] {
				b.WriteString(st.Plain.Render(tok))
			} else {
				b.WriteString(st.Register.Render(tok))
			}
			i = j
		default: // punctuation: [], (), commas, +, -, *, : …
			b.WriteString(st.Plain.Render(text[i : i+1]))
			i++
		}
	}
	return b.String()
}

func isIdentStart(c byte) bool { return c == '_' || (c|0x20 >= 'a' && c|0x20 <= 'z') }
func isIdentChar(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9') || c == '.'
}
func isNumChar(c byte) bool {
	return (c >= '0' && c <= '9') || c == 'x' || c == 'X' || c == '.' || c == '_' ||
		(c|0x20 >= 'a' && c|0x20 <= 'f')
}
