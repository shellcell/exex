// Package theme provides colour palettes extracted from Chroma's styles as plain
// data, so both the full and lite builds can theme the whole UI (and the
// built-in highlighter) from any Chroma style name without importing Chroma.
//
// The palette table in palettes_gen.go is produced by `go generate ./internal/theme`
// (see gen/main.go), which reads Chroma's style registry at generation time. The
// generated file holds only colour strings — no Chroma dependency — so it links
// into the lite build too.
package theme

//go:generate go run gen/main.go

import (
	"sort"
	"strings"
)

// DefaultName is the theme used when none is configured, and the palette every
// other lookup falls back to. Both the UI (internal/ui) and the source
// highlighter (internal/syntax) resolve against it, so it lives here rather than
// as a constant duplicated in each.
const DefaultName = "nord"

// Palette is the small set of semantic colours we pull from a Chroma style and
// map onto the UI and the built-in syntax highlighter. Every field is a #RRGGBB
// hex string; empty means the style didn't define it (callers fall back to
// Foreground).
type Palette struct {
	Background string // editor background
	Foreground string // default text
	Comment    string // comments, dim/secondary text
	Keyword    string // keywords, instruction mnemonics
	Type       string // type keywords
	Function   string // function/definition names
	Name       string // identifiers, registers
	String     string // string literals
	Number     string // numeric literals, immediates
	Operator   string // operators / punctuation
	Error      string // errors / "bad" highlights
}

// or returns the field value, or Foreground (then a caller default) when unset.
func (p Palette) or(v, fallback string) string {
	if v != "" {
		return v
	}
	if p.Foreground != "" {
		return p.Foreground
	}
	return fallback
}

// resolved returns p with every empty field filled from Foreground/Background so
// callers never have to handle "".
func (p Palette) resolved() Palette {
	fg, bg := p.Foreground, p.Background
	if fg == "" {
		fg = "#cccccc"
	}
	if bg == "" {
		bg = "#000000"
	}
	return Palette{
		Background: bg,
		Foreground: fg,
		Comment:    p.or(p.Comment, fg),
		Keyword:    p.or(p.Keyword, fg),
		Type:       p.or(p.Type, p.or(p.Keyword, fg)),
		Function:   p.or(p.Function, p.or(p.Name, fg)),
		Name:       p.or(p.Name, fg),
		String:     p.or(p.String, fg),
		Number:     p.or(p.Number, fg),
		Operator:   p.or(p.Operator, fg),
		Error:      p.or(p.Error, fg),
	}
}

// PaletteFor returns the fully-resolved palette for a Chroma style name,
// reporting whether the name is known. The lookup is case-sensitive; Chroma
// style names are lowercase (e.g. "dracula", "github-dark").
func PaletteFor(name string) (Palette, bool) {
	if p, ok := palettes[name]; ok {
		return p.resolved(), true
	}
	return Palette{}, false
}

// ForegroundFor returns the default text colour of a style, falling back to
// DefaultName's and then to "". Callers use it to colour tokens a style leaves
// unstyled.
func ForegroundFor(name string) string {
	if p, ok := PaletteFor(strings.TrimSpace(name)); ok {
		return p.Foreground
	}
	if p, ok := PaletteFor(DefaultName); ok {
		return p.Foreground
	}
	return ""
}

// Names returns the sorted list of known palette (Chroma style) names.
func Names() []string {
	out := make([]string, 0, len(palettes))
	for n := range palettes {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
