// Package chromalexers provides the curated Chroma lexer registry bundled by
// exex's default build.
package chromalexers

import (
	"embed"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/alecthomas/chroma/v2"
)

//go:embed embedded/*.xml
var embedded embed.FS

// Registry is the curated lexer registry used at runtime.
var Registry = func() *chroma.LexerRegistry {
	reg := chroma.NewLexerRegistry()
	paths, err := fs.Glob(embedded, "embedded/*.xml")
	if err != nil {
		panic(err)
	}
	for _, path := range paths {
		reg.Register(chroma.MustNewXMLLexer(embedded, path))
	}
	registerGo(reg)
	return reg
}()

// Names returns the curated lexer names, optionally including aliases.
func Names(withAliases bool) []string {
	return Registry.Names(withAliases)
}

// Get returns a curated lexer by name, alias, extension, or filename.
func Get(name string) chroma.Lexer {
	return Registry.Get(name)
}

// Match returns the first curated lexer matching filename.
func Match(filename string) chroma.Lexer {
	base := filepath.Base(filename)
	if base == "v.mod" {
		if l := Get("v"); l != nil {
			return l
		}
	}
	if strings.HasSuffix(base, ".s") || strings.HasSuffix(base, ".S") {
		if l := Get("gas"); l != nil {
			return l
		}
	}
	return Registry.Match(filename)
}

// Analyse chooses the best curated lexer for text content.
func Analyse(text string) chroma.Lexer {
	return Registry.Analyse(text)
}
