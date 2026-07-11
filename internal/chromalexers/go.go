package chromalexers

import (
	"strings"

	"github.com/alecthomas/chroma/v2"
)

// registerGo keeps Chroma's hand-written Go lexer in the curated registry
// without importing github.com/alecthomas/chroma/v2/lexers, which embeds the full
// upstream lexer set.
func registerGo(reg *chroma.LexerRegistry) {
	reg.Register(chroma.MustNewLexer(
		&chroma.Config{
			Name:      "Go",
			Aliases:   []string{"go", "golang"},
			Filenames: []string{"*.go"},
			MimeTypes: []string{"text/x-gosrc"},
		},
		goRules,
	).SetAnalyser(func(text string) float32 {
		if strings.Contains(text, "fmt.") && strings.Contains(text, "package ") {
			return 0.5
		}
		if strings.Contains(text, "package ") {
			return 0.1
		}
		return 0
	}))
}

// rule builds a keyed chroma.Rule (the upstream lexer uses positional literals,
// which go vet rejects for out-of-package struct types).
func rule(pattern string, emitter chroma.Emitter) chroma.Rule {
	return chroma.Rule{Pattern: pattern, Type: emitter}
}

func goRules() chroma.Rules {
	return chroma.Rules{
		"root": {
			rule(`\n`, chroma.TextWhitespace),
			rule(`\s+`, chroma.TextWhitespace),
			rule(`//[^\s\n\r][^\n\r]*`, chroma.CommentPreproc),
			rule(`//[^\n\r]*`, chroma.CommentSingle),
			rule(`/(\\\n)?[*](.|\n)*?[*](\\\n)?/`, chroma.CommentMultiline),
			rule(`(import|package)\b`, chroma.KeywordNamespace),
			rule(`(var|func|struct|map|chan|type|interface|const)\b`, chroma.KeywordDeclaration),
			rule(chroma.Words(``, `\b`, `break`, `default`, `select`, `case`, `defer`, `go`, `else`, `goto`, `switch`, `fallthrough`, `if`, `range`, `continue`, `for`, `return`), chroma.Keyword),
			rule(`(true|false|iota|nil)\b`, chroma.KeywordConstant),
			rule(chroma.Words(``, `\b(\()`, `uint`, `uint8`, `uint16`, `uint32`, `uint64`, `int`, `int8`, `int16`, `int32`, `int64`, `float`, `float32`, `float64`, `complex64`, `complex128`, `byte`, `rune`, `string`, `bool`, `error`, `uintptr`, `print`, `println`, `panic`, `recover`, `close`, `complex`, `real`, `imag`, `len`, `cap`, `append`, `copy`, `delete`, `new`, `make`, `clear`, `min`, `max`), chroma.ByGroups(chroma.NameBuiltin, chroma.Punctuation)),
			rule(chroma.Words(``, `\b`, `uint`, `uint8`, `uint16`, `uint32`, `uint64`, `int`, `int8`, `int16`, `int32`, `int64`, `float`, `float32`, `float64`, `complex64`, `complex128`, `byte`, `rune`, `string`, `bool`, `error`, `uintptr`, `any`), chroma.KeywordType),
			rule(`\d+i`, chroma.LiteralNumber),
			rule(`\d+\.\d*([Ee][-+]\d+)?i`, chroma.LiteralNumber),
			rule(`\.\d+([Ee][-+]\d+)?i`, chroma.LiteralNumber),
			rule(`\d+[Ee][-+]\d+i`, chroma.LiteralNumber),
			rule(`\d+(\.\d+[eE][+\-]?\d+|\.\d*|[eE][+\-]?\d+)`, chroma.LiteralNumberFloat),
			rule(`\.\d+([eE][+\-]?\d+)?`, chroma.LiteralNumberFloat),
			rule(`0[0-7]+`, chroma.LiteralNumberOct),
			rule(`0[xX][0-9a-fA-F_]+`, chroma.LiteralNumberHex),
			rule(`0b[01_]+`, chroma.LiteralNumberBin),
			rule(`(0|[1-9][0-9_]*)`, chroma.LiteralNumberInteger),
			rule(`'(\\['"\\abfnrtv]|\\x[0-9a-fA-F]{2}|\\[0-7]{1,3}|\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}|[^\\])'`, chroma.LiteralStringChar),
			rule("`[^`]*`", chroma.LiteralStringBacktick),
			rule(`"(\\\\|\\"|[^"])*"`, chroma.LiteralString),
			rule(`(<<=|>>=|<<|>>|<=|>=|&\^=|&\^|\+=|-=|\*=|/=|%=|&=|\|=|&&|\|\||<-|\+\+|--|==|!=|:=|\.\.\.|[+\-*/%&])`, chroma.Operator),
			rule(`([a-zA-Z_]\w*)(\s*)(\()`, chroma.ByGroups(chroma.NameFunction, chroma.UsingSelf("root"), chroma.Punctuation)),
			rule(`[|^<>=!()\[\]{}.,;:~]`, chroma.Punctuation),
			rule(`[^\W\d]\w*`, chroma.NameOther),
		},
	}
}
