//go:build !lite

package ui

// Default build: Chroma-based assembly syntax highlighting from the curated
// lexer/style set. The `lite` build (disasm_syntax_lite.go) swaps in a small
// theme-driven token highlighter and drops Chroma entirely.

import (
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/alecthomas/chroma/v2"

	"github.com/rabarbra/exex/internal/arch"
	"github.com/rabarbra/exex/internal/chromalexers"
	"github.com/rabarbra/exex/internal/chromastyles"
	"github.com/rabarbra/exex/internal/disasm"
	"github.com/rabarbra/exex/internal/syntax"
)

// disasmAsmLexers caches the Chroma asm lexer per architecture. Keying by arch
// (rather than a single global) means opening a different-arch binary in the same
// process — e.g. a library via the Libs view's "open as primary" — gets the right
// lexer instead of reusing the first file's.
var disasmAsmLexers = map[arch.Arch]chroma.Lexer{}

// disasmAsmLexerFor returns the asm lexer for a, building and caching it (even
// when nil) on first use.
func disasmAsmLexerFor(a arch.Arch) chroma.Lexer {
	if l, ok := disasmAsmLexers[a]; ok {
		return l
	}
	l := newDisasmAsmLexer(a)
	disasmAsmLexers[a] = l
	return l
}

func newDisasmAsmLexer(arch arch.Arch) chroma.Lexer {
	lexer_names := []string{"ArmAsm", "GAS", "asm", "NASM"}
	switch arch {
	case disasm.ArchX86, disasm.ArchAMD64, disasm.ArchRISCV64:
		lexer_names = append([]string{"GAS"}, lexer_names...)
	case disasm.ArchARM64:
		lexer_names = append([]string{"ArmAsm"}, lexer_names...)
	}
	for _, name := range lexer_names {
		if lexer := chromalexers.Get(name); lexer != nil {
			return chroma.Coalesce(lexer)
		}
	}
	return nil
}

// renderInstTextStyled uses Chroma for assembly syntax, overlaying semantic link
// styles on followable address literals.
func (m *Model) renderInstTextStyled(text string, class disasm.InstClass, instAddr uint64) string {
	if m.disasmStyledMode == 0 {
		if _, ok := chromastyles.Lookup(sourceSyntaxTheme(m.cfg)); ok {
			m.disasmStyledMode = 1
		} else {
			m.disasmStyledMode = -1
		}
	}
	if m.disasmStyledMode < 0 {
		return m.renderInstTextFallback(text, class, instAddr)
	}
	lexer := disasmAsmLexerFor(m.file.Arch())
	if lexer == nil {
		return m.renderInstTextFallback(text, class, instAddr)
	}
	tokens, err := chroma.Tokenise(lexer, nil, text)
	if err != nil {
		return m.renderInstTextFallback(text, class, instAddr)
	}
	spans := m.disasmAddrSpans(text, instAddr)
	pos := 0
	var b strings.Builder
	for _, tok := range tokens {
		if tok == chroma.EOF {
			break
		}
		b.WriteString(m.renderDisasmToken(tok, pos, spans))
		pos += len(tok.Value)
	}
	return b.String()
}

// renderInstTextFallback colours an instruction by its class and link addresses
// only (no per-token highlighting) — the fallback when no asm lexer matches or
// tokenising fails.
func (m *Model) renderInstTextFallback(text string, class disasm.InstClass, instAddr uint64) string {
	classSt := m.theme.styleForClass(class)
	from := 0
	var b strings.Builder
	spans := m.disasmAddrSpans(text, instAddr)
	si := 0
	for from < len(text) {
		if si < len(spans) && spans[si].start == from {
			b.WriteString(spans[si].style.Render(text[from:spans[si].end]))
			from = spans[si].end
			si++
			continue
		}
		next := len(text)
		if si < len(spans) {
			next = spans[si].start
		}
		b.WriteString(classSt.Render(text[from:next]))
		from = next
	}
	return b.String()
}

func (m *Model) renderDisasmToken(tok chroma.Token, pos int, spans []disasmAddrSpan) string {
	st := m.disasmTokenStyle(tok.Type)
	from := 0
	var b strings.Builder
	for _, span := range spans {
		lo := max(span.start, pos)
		hi := min(span.end, pos+len(tok.Value))
		if hi <= lo {
			continue
		}
		if rel := lo - pos; rel > from {
			b.WriteString(st.Render(tok.Value[from:rel]))
		}
		b.WriteString(span.style.Render(tok.Value[lo-pos : hi-pos]))
		from = hi - pos
	}
	if from < len(tok.Value) {
		b.WriteString(st.Render(tok.Value[from:]))
	}
	return b.String()
}

func (m *Model) disasmTokenStyle(tt chroma.TokenType) lipgloss.Style {
	if m.disasmTokenStyles == nil {
		m.disasmTokenStyles = make(map[int]lipgloss.Style)
	}
	if st, ok := m.disasmTokenStyles[int(tt)]; ok {
		return st
	}
	themeName := sourceSyntaxTheme(m.cfg)
	chromaStyle, ok := chromastyles.Lookup(themeName)
	if !ok || chromaStyle == nil {
		chromaStyle = chromastyles.Fallback()
	}
	st := syntax.StyleEntryToLipgloss(chromaStyle.Get(tt), sourceSyntaxForeground(m.cfg))
	m.disasmTokenStyles[int(tt)] = st
	return st
}
