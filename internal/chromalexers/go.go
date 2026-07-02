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

func goRules() chroma.Rules {
	return chroma.Rules{
		"root": {
			{`\n`, chroma.TextWhitespace, nil},
			{`\s+`, chroma.TextWhitespace, nil},
			{`//[^\s\n\r][^\n\r]*`, chroma.CommentPreproc, nil},
			{`//[^\n\r]*`, chroma.CommentSingle, nil},
			{`/(\\\n)?[*](.|\n)*?[*](\\\n)?/`, chroma.CommentMultiline, nil},
			{`(import|package)\b`, chroma.KeywordNamespace, nil},
			{`(var|func|struct|map|chan|type|interface|const)\b`, chroma.KeywordDeclaration, nil},
			{chroma.Words(``, `\b`, `break`, `default`, `select`, `case`, `defer`, `go`, `else`, `goto`, `switch`, `fallthrough`, `if`, `range`, `continue`, `for`, `return`), chroma.Keyword, nil},
			{`(true|false|iota|nil)\b`, chroma.KeywordConstant, nil},
			{chroma.Words(``, `\b(\()`, `uint`, `uint8`, `uint16`, `uint32`, `uint64`, `int`, `int8`, `int16`, `int32`, `int64`, `float`, `float32`, `float64`, `complex64`, `complex128`, `byte`, `rune`, `string`, `bool`, `error`, `uintptr`, `print`, `println`, `panic`, `recover`, `close`, `complex`, `real`, `imag`, `len`, `cap`, `append`, `copy`, `delete`, `new`, `make`, `clear`, `min`, `max`), chroma.ByGroups(chroma.NameBuiltin, chroma.Punctuation), nil},
			{chroma.Words(``, `\b`, `uint`, `uint8`, `uint16`, `uint32`, `uint64`, `int`, `int8`, `int16`, `int32`, `int64`, `float`, `float32`, `float64`, `complex64`, `complex128`, `byte`, `rune`, `string`, `bool`, `error`, `uintptr`, `any`), chroma.KeywordType, nil},
			{`\d+i`, chroma.LiteralNumber, nil},
			{`\d+\.\d*([Ee][-+]\d+)?i`, chroma.LiteralNumber, nil},
			{`\.\d+([Ee][-+]\d+)?i`, chroma.LiteralNumber, nil},
			{`\d+[Ee][-+]\d+i`, chroma.LiteralNumber, nil},
			{`\d+(\.\d+[eE][+\-]?\d+|\.\d*|[eE][+\-]?\d+)`, chroma.LiteralNumberFloat, nil},
			{`\.\d+([eE][+\-]?\d+)?`, chroma.LiteralNumberFloat, nil},
			{`0[0-7]+`, chroma.LiteralNumberOct, nil},
			{`0[xX][0-9a-fA-F_]+`, chroma.LiteralNumberHex, nil},
			{`0b[01_]+`, chroma.LiteralNumberBin, nil},
			{`(0|[1-9][0-9_]*)`, chroma.LiteralNumberInteger, nil},
			{`'(\\['"\\abfnrtv]|\\x[0-9a-fA-F]{2}|\\[0-7]{1,3}|\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}|[^\\])'`, chroma.LiteralStringChar, nil},
			{"`[^`]*`", chroma.LiteralStringBacktick, nil},
			{`"(\\\\|\\"|[^"])*"`, chroma.LiteralString, nil},
			{`(<<=|>>=|<<|>>|<=|>=|&\^=|&\^|\+=|-=|\*=|/=|%=|&=|\|=|&&|\|\||<-|\+\+|--|==|!=|:=|\.\.\.|[+\-*/%&])`, chroma.Operator, nil},
			{`([a-zA-Z_]\w*)(\s*)(\()`, chroma.ByGroups(chroma.NameFunction, chroma.UsingSelf("root"), chroma.Punctuation), nil},
			{`[|^<>=!()\[\]{}.,;:~]`, chroma.Punctuation, nil},
			{`[^\W\d]\w*`, chroma.NameOther, nil},
		},
	}
}
