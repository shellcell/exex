// Package asmhl highlights a single line of disassembled instruction text.
//
// It exists to keep the `lite` build tag out of internal/ui. The default build
// tokenises with Chroma's assembly lexers; the lite build uses a small
// theme-driven scanner and drops Chroma entirely. Both satisfy Highlighter, so
// the shell holds one interface value and never mentions a build tag.
//
// Whichever it is, followable address literals are drawn in their link colour
// rather than the operand-token colours. The caller finds those spans (it needs
// the binary to know which addresses are mapped) and passes them in.
package asmhl

import (
	"strings"

	"charm.land/lipgloss/v2"

	"github.com/shellcell/exex/internal/arch"
	"github.com/shellcell/exex/internal/disasm"
)

// Span marks a run of instruction text — a followable mapped address — that
// should be drawn in a link colour. Offsets are byte indices into the text.
type Span struct {
	Start int
	End   int
	Style lipgloss.Style
}

// Styles is the theme vocabulary a highlighter draws with. Class colours the
// mnemonic by instruction class; the rest colour operand tokens (used by the
// lite highlighter, and by the Chroma one's fallback path).
type Styles struct {
	Class    func(disasm.InstClass) lipgloss.Style
	Plain    lipgloss.Style // whitespace, punctuation, size specifiers
	Register lipgloss.Style
	Number   lipgloss.Style
}

// Highlighter renders one instruction's text.
type Highlighter interface {
	// Render styles text, overlaying spans on top of the token colours. spans must
	// be ordered by Start and must not overlap.
	Render(text string, class disasm.InstClass, spans []Span) string
}

// New builds the highlighter for the current build, theme and architecture.
//
//   - themeName / fallbackFG select the Chroma style (default build only).
//   - a selects the assembly lexer (default build only).
//
// The lite build ignores both and colours from st alone. Callers rebuild the
// highlighter when the theme changes rather than mutating it, so its caches are
// never stale.
func New(themeName, fallbackFG string, a arch.Arch, st Styles) Highlighter {
	return newHighlighter(themeName, fallbackFG, a, st)
}

// spanAt returns the span covering byte index i, if any.
func spanAt(spans []Span, i int) (Span, bool) {
	for _, s := range spans {
		if i >= s.Start && i < s.End {
			return s, true
		}
	}
	return Span{}, false
}

// renderByClass colours text by its instruction class, with the link spans drawn
// in their own style. No per-token highlighting: it is the Chroma build's
// fallback when the theme has no bundled style, no asm lexer matches, or
// tokenising fails.
func renderByClass(text string, class disasm.InstClass, spans []Span, st Styles) string {
	classSt := st.Class(class)
	var b strings.Builder
	from, si := 0, 0
	for from < len(text) {
		if si < len(spans) && spans[si].Start == from {
			b.WriteString(spans[si].Style.Render(text[from:spans[si].End]))
			from = spans[si].End
			si++
			continue
		}
		next := len(text)
		if si < len(spans) {
			next = spans[si].Start
		}
		b.WriteString(classSt.Render(text[from:next]))
		from = next
	}
	return b.String()
}
