package syntax

// A tiny, dependency-free highlighter used by the `lite` build (in place of
// Chroma) and as a fallback in the full build when Chroma can't identify a file.
// It colours comments, string/char literals, numbers, broad keyword categories,
// and likely function names — not language-accurate, but far more readable than
// plain text, in ~zero bytes.

import (
	"strings"

	"charm.land/lipgloss/v2"

	"github.com/rabarbra/exex/internal/theme"
)

var (
	mhComment = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	mhString  = lipgloss.NewStyle().Foreground(lipgloss.Color("114"))
	mhNumber  = lipgloss.NewStyle().Foreground(lipgloss.Color("215"))

	mhControl      = lipgloss.NewStyle().Foreground(lipgloss.Color("117")).Bold(true)
	mhDeclaration  = lipgloss.NewStyle().Foreground(lipgloss.Color("213"))
	mhFunction     = lipgloss.NewStyle().Foreground(lipgloss.Color("80")).Bold(true)
	mhFunctionName = lipgloss.NewStyle().Foreground(lipgloss.Color("39"))
	mhType         = lipgloss.NewStyle().Foreground(lipgloss.Color("176"))
	mhLiteral      = lipgloss.NewStyle().Foreground(lipgloss.Color("215"))
	mhOperator     = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	mhPreproc      = lipgloss.NewStyle().Foreground(lipgloss.Color("173"))
)

type minimalPalette struct {
	text         lipgloss.Style
	comment      lipgloss.Style
	stringLit    lipgloss.Style
	number       lipgloss.Style
	control      lipgloss.Style
	declaration  lipgloss.Style
	function     lipgloss.Style
	functionName lipgloss.Style
	typ          lipgloss.Style
	literal      lipgloss.Style
	operator     lipgloss.Style // operators / punctuation
	preproc      lipgloss.Style // C preprocessor directives (#include, #define, …)
}

var defaultMinimalPalette = minimalPalette{
	text:         lipgloss.NewStyle().Foreground(lipgloss.Color("252")),
	comment:      mhComment,
	stringLit:    mhString,
	number:       mhNumber,
	control:      mhControl,
	declaration:  mhDeclaration,
	function:     mhFunction,
	functionName: mhFunctionName,
	typ:          mhType,
	literal:      mhLiteral,
	operator:     mhOperator,
	preproc:      mhPreproc,
}

var (
	nordMinimalPalette = minimalPalette{
		text:         lipgloss.NewStyle().Foreground(lipgloss.Color("#d8dee9")),
		comment:      lipgloss.NewStyle().Foreground(lipgloss.Color("#4c566a")),
		stringLit:    lipgloss.NewStyle().Foreground(lipgloss.Color("#a3be8c")),
		number:       lipgloss.NewStyle().Foreground(lipgloss.Color("#d08770")),
		control:      lipgloss.NewStyle().Foreground(lipgloss.Color("#b48ead")).Bold(true),
		declaration:  lipgloss.NewStyle().Foreground(lipgloss.Color("#81a1c1")),
		function:     lipgloss.NewStyle().Foreground(lipgloss.Color("#88c0d0")).Bold(true),
		functionName: lipgloss.NewStyle().Foreground(lipgloss.Color("#8fbcbb")),
		typ:          lipgloss.NewStyle().Foreground(lipgloss.Color("#ebcb8b")),
		literal:      lipgloss.NewStyle().Foreground(lipgloss.Color("#d08770")),
		operator:     lipgloss.NewStyle().Foreground(lipgloss.Color("#81a1c1")),
		preproc:      lipgloss.NewStyle().Foreground(lipgloss.Color("#5e81ac")),
	}
	solarizedDarkMinimalPalette  = solarizedMinimalPalette("#93a1a1", "#586e75")
	solarizedLightMinimalPalette = solarizedMinimalPalette("#586e75", "#93a1a1")
)

func minimalPaletteForTheme(name string) minimalPalette {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "dark":
		return defaultMinimalPalette
	case "nord":
		return nordMinimalPalette
	case "solarized-dark":
		return solarizedDarkMinimalPalette
	case "solarized-light":
		return solarizedLightMinimalPalette
	}
	// Any other name: derive from the matching Chroma palette so lite source
	// highlighting follows the chosen theme too.
	if p, ok := theme.PaletteFor(strings.TrimSpace(name)); ok {
		return minimalPaletteFromChroma(p)
	}
	return defaultMinimalPalette
}

// minimalPaletteFromChroma maps a Chroma palette onto the highlighter's category
// styles.
func minimalPaletteFromChroma(p theme.Palette) minimalPalette {
	fg := func(hex string) lipgloss.Style { return lipgloss.NewStyle().Foreground(lipgloss.Color(hex)) }
	or := func(a, b string) string {
		if a != "" {
			return a
		}
		return b
	}
	return minimalPalette{
		text:         fg(p.Foreground),
		comment:      fg(p.Comment),
		stringLit:    fg(p.String),
		number:       fg(p.Number),
		control:      fg(p.Keyword).Bold(true),
		declaration:  fg(p.Keyword),
		function:     fg(p.Function).Bold(true),
		functionName: fg(p.Function),
		typ:          fg(p.Type),
		literal:      fg(p.Number),
		operator:     fg(or(p.Operator, p.Foreground)),
		preproc:      fg(or(p.Comment, p.Keyword)),
	}
}

func solarizedMinimalPalette(text, comment string) minimalPalette {
	return minimalPalette{
		text:         lipgloss.NewStyle().Foreground(lipgloss.Color(text)),
		comment:      lipgloss.NewStyle().Foreground(lipgloss.Color(comment)),
		stringLit:    lipgloss.NewStyle().Foreground(lipgloss.Color("#859900")),
		number:       lipgloss.NewStyle().Foreground(lipgloss.Color("#cb4b16")),
		control:      lipgloss.NewStyle().Foreground(lipgloss.Color("#d33682")).Bold(true),
		declaration:  lipgloss.NewStyle().Foreground(lipgloss.Color("#268bd2")),
		function:     lipgloss.NewStyle().Foreground(lipgloss.Color("#2aa198")).Bold(true),
		functionName: lipgloss.NewStyle().Foreground(lipgloss.Color("#268bd2")),
		typ:          lipgloss.NewStyle().Foreground(lipgloss.Color("#6c71c5")),
		literal:      lipgloss.NewStyle().Foreground(lipgloss.Color("#cb4b16")),
		operator:     lipgloss.NewStyle().Foreground(lipgloss.Color(comment)),
		preproc:      lipgloss.NewStyle().Foreground(lipgloss.Color("#cb4b16")),
	}
}

type mhKeywordCategory uint8

const (
	mhCatControl mhKeywordCategory = iota + 1
	mhCatDeclaration
	mhCatFunction
	mhCatType
	mhCatLiteral
)

// mhKeywordCategories is a language-agnostic union of common keywords grouped by
// broad role. Some entries are only keywords in some languages; the occasional
// false positive is an acceptable trade for covering C/C++/Go/Rust/Python/JS.
var mhKeywordCategories = map[string]mhKeywordCategory{
	"if": mhCatControl, "else": mhCatControl, "elif": mhCatControl, "for": mhCatControl, "while": mhCatControl, "do": mhCatControl,
	"switch": mhCatControl, "case": mhCatControl, "default": mhCatControl, "break": mhCatControl, "continue": mhCatControl,
	"return": mhCatControl, "goto": mhCatControl, "yield": mhCatControl, "defer": mhCatControl, "go": mhCatControl,
	"range": mhCatControl, "select": mhCatControl, "match": mhCatControl, "try": mhCatControl, "catch": mhCatControl,
	"finally": mhCatControl, "throw": mhCatControl, "throws": mhCatControl, "except": mhCatControl, "raise": mhCatControl,
	"with": mhCatControl, "pass": mhCatControl, "and": mhCatControl, "or": mhCatControl, "not": mhCatControl,
	"in": mhCatControl, "is": mhCatControl, "async": mhCatControl, "await": mhCatControl,

	"func": mhCatFunction, "fn": mhCatFunction, "def": mhCatFunction, "fun": mhCatFunction, "function": mhCatFunction, "lambda": mhCatFunction,
	"new": mhCatFunction, "delete": mhCatFunction,

	"var": mhCatDeclaration, "let": mhCatDeclaration, "const": mhCatDeclaration, "static": mhCatDeclaration, "final": mhCatDeclaration,
	"mut": mhCatDeclaration, "import": mhCatDeclaration, "include": mhCatDeclaration, "package": mhCatDeclaration, "use": mhCatDeclaration,
	"using": mhCatDeclaration, "from": mhCatDeclaration, "as": mhCatDeclaration, "public": mhCatDeclaration, "private": mhCatDeclaration,
	"protected": mhCatDeclaration, "pub": mhCatDeclaration, "extern": mhCatDeclaration, "inline": mhCatDeclaration,
	"volatile": mhCatDeclaration, "register": mhCatDeclaration, "export": mhCatDeclaration, "noreturn": mhCatDeclaration,
	"namespace": mhCatDeclaration, "where": mhCatDeclaration,

	"struct": mhCatType, "class": mhCatType, "enum": mhCatType, "interface": mhCatType, "trait": mhCatType,
	"impl": mhCatType, "type": mhCatType, "typedef": mhCatType, "union": mhCatType, "chan": mhCatType, "map": mhCatType,
	"int": mhCatType, "long": mhCatType, "short": mhCatType, "char": mhCatType, "bool": mhCatType, "void": mhCatType,
	"float": mhCatType, "double": mhCatType, "string": mhCatType, "unsigned": mhCatType, "signed": mhCatType,
	"byte": mhCatType, "rune": mhCatType, "any": mhCatType, "u8": mhCatType, "u16": mhCatType, "u32": mhCatType, "u64": mhCatType,
	"i8": mhCatType, "i16": mhCatType, "i32": mhCatType, "i64": mhCatType, "usize": mhCatType, "isize": mhCatType,

	"nil": mhCatLiteral, "null": mhCatLiteral, "none": mhCatLiteral, "nullptr": mhCatLiteral,
	"true": mhCatLiteral, "false": mhCatLiteral, "self": mhCatLiteral, "this": mhCatLiteral, "super": mhCatLiteral,
}

var mhFunctionDeclKeywords = map[string]bool{
	"func": true, "fn": true, "def": true, "fun": true, "function": true,
}

type commentSyntax struct {
	line  string // line-comment marker ("//" or "#"); "" if none
	block bool   // /* … */ block comments supported
}

// commentFor picks comment markers by file type. Hash-comment languages use "#"
// only (so Python's "//" operator isn't mistaken for a comment); everything else
// gets C-style "//" and "/* */".
func commentFor(filename string) commentSyntax {
	switch lowerExt(filename) {
	case ".py", ".rb", ".sh", ".bash", ".zsh", ".pl", ".yaml", ".yml", ".toml",
		".cfg", ".conf", ".ini", ".mk", ".r", ".jl", ".tcl", ".cmake", ".nim",
		".ps1", ".dockerfile":
		return commentSyntax{line: "#"}
	}
	switch baseName(filename) {
	case "Makefile", "makefile", "Dockerfile", "CMakeLists.txt":
		return commentSyntax{line: "#"}
	}
	return commentSyntax{line: "//", block: true}
}

// minimalHighlight returns ANSI-styled source lines using the tiny tokeniser.
func minimalHighlight(filename string, src []string, theme string) []string {
	cs := commentFor(filename)
	pal := minimalPaletteForTheme(theme)
	out := make([]string, len(src))
	inBlock := false
	for i, line := range src {
		out[i], inBlock = mhLine(line, cs, inBlock, pal)
	}
	return out
}

func mhLine(line string, cs commentSyntax, inBlock bool, pal minimalPalette) (string, bool) {
	var b strings.Builder
	n := len(line)
	wantFuncName := false
	i := 0
	// Preprocessor directive: a line whose first non-blank character is '#' in a
	// C-style (block-comment) language — #include, #define, #pragma, #ifdef, … —
	// colours the whole "#directive" token. Hash-comment languages handle '#' as a
	// comment instead (see commentFor), so this only fires for C-family sources.
	if !inBlock && cs.block {
		ws := i
		for ws < n && (line[ws] == ' ' || line[ws] == '\t') {
			ws++
		}
		if ws < n && line[ws] == '#' {
			j := ws + 1
			for j < n && (line[j] == ' ' || line[j] == '\t') {
				j++
			}
			for j < n && isIdentChar(line[j]) {
				j++
			}
			b.WriteString(line[i:ws]) // leading whitespace, unstyled
			b.WriteString(pal.preproc.Render(line[ws:j]))
			i = j
		}
	}
	for i < n {
		if inBlock {
			if j := strings.Index(line[i:], "*/"); j >= 0 {
				b.WriteString(pal.comment.Render(line[i : i+j+2]))
				i += j + 2
				inBlock = false
				continue
			}
			b.WriteString(pal.comment.Render(line[i:]))
			return b.String(), true
		}
		c := line[i]
		switch {
		case cs.block && c == '/' && i+1 < n && line[i+1] == '*':
			if j := strings.Index(line[i+2:], "*/"); j >= 0 {
				end := i + 2 + j + 2
				b.WriteString(pal.comment.Render(line[i:end]))
				i = end
				continue
			}
			b.WriteString(pal.comment.Render(line[i:]))
			return b.String(), true
		case cs.line != "" && strings.HasPrefix(line[i:], cs.line):
			b.WriteString(pal.comment.Render(line[i:]))
			return b.String(), false
		case c == '"' || c == '\'' || c == '`':
			end := mhStringEnd(line, i)
			b.WriteString(pal.stringLit.Render(line[i:end]))
			i = end
		case isDigit(c):
			j := i + 1
			for j < n && isNumChar(line[j]) {
				j++
			}
			b.WriteString(pal.number.Render(line[i:j]))
			i = j
		case isIdentStart(c):
			j := i + 1
			for j < n && isIdentChar(line[j]) {
				j++
			}
			word := line[i:j]
			if cat, ok := mhKeywordCategories[word]; ok {
				b.WriteString(mhStyleForCategory(cat, pal).Render(word))
				wantFuncName = mhFunctionDeclKeywords[word]
			} else if wantFuncName || mhLooksFunctionCall(line, j) {
				b.WriteString(pal.functionName.Render(word))
				wantFuncName = false
			} else {
				b.WriteString(pal.text.Render(word))
				wantFuncName = false
			}
			i = j
		case isOperatorByte(c):
			j := i + 1
			for j < n && isOperatorByte(line[j]) {
				j++
			}
			b.WriteString(pal.operator.Render(line[i:j]))
			i = j
		default:
			b.WriteString(pal.text.Render(line[i : i+1]))
			i++
		}
	}
	return b.String(), inBlock
}

// isOperatorByte reports whether c is an operator or punctuation byte. Runs of
// these share the operator colour, so multi-byte operators (==, &&, ::) read as
// one unit. '/' reaches here only when the comment cases above did not consume it.
func isOperatorByte(c byte) bool {
	switch c {
	case '+', '-', '*', '/', '%', '=', '<', '>', '!', '&', '|', '^', '~',
		'?', ':', ';', ',', '.', '(', ')', '[', ']', '{', '}', '@':
		return true
	}
	return false
}

func mhStyleForCategory(cat mhKeywordCategory, pal minimalPalette) lipgloss.Style {
	switch cat {
	case mhCatControl:
		return pal.control
	case mhCatDeclaration:
		return pal.declaration
	case mhCatFunction:
		return pal.function
	case mhCatType:
		return pal.typ
	case mhCatLiteral:
		return pal.literal
	}
	return lipgloss.NewStyle()
}

func mhLooksFunctionCall(line string, pos int) bool {
	for pos < len(line) && (line[pos] == ' ' || line[pos] == '\t') {
		pos++
	}
	return pos < len(line) && line[pos] == '('
}

// mhStringEnd returns the index just past the closing quote, or end-of-line when
// the literal is unterminated.
func mhStringEnd(line string, start int) int {
	q := line[start]
	for i := start + 1; i < len(line); i++ {
		switch line[i] {
		case '\\':
			i++ // skip the escaped byte
		case q:
			return i + 1
		}
	}
	return len(line)
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isNumChar(c byte) bool {
	return isDigit(c) || c == '.' || c == '_' || c == 'x' || (c|0x20 >= 'a' && c|0x20 <= 'f')
}
func isIdentStart(c byte) bool {
	return c == '_' || c >= 0x80 || (c|0x20 >= 'a' && c|0x20 <= 'z')
}
func isIdentChar(c byte) bool { return isIdentStart(c) || isDigit(c) }

func lowerExt(filename string) string {
	if i := strings.LastIndexByte(filename, '.'); i >= 0 {
		return strings.ToLower(filename[i:])
	}
	return ""
}

func baseName(filename string) string {
	if i := strings.LastIndexAny(filename, "/\\"); i >= 0 {
		return filename[i+1:]
	}
	return filename
}
