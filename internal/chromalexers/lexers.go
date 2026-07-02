// Package chromalexers provides the curated Chroma lexer registry bundled by
// exex's default build.
package chromalexers

import (
	"embed"
	"io/fs"
	"path/filepath"
	"strings"
	"sync"

	"github.com/alecthomas/chroma/v2"
)

//go:embed embedded/*.xml
var embedded embed.FS

// registry builds the curated lexer registry on first use. Lazy so that runs
// that never highlight (most `-o` dumps) skip parsing the embedded XML configs
// and compiling their analyser regexes at startup.
var registry = sync.OnceValue(func() *chroma.LexerRegistry {
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
})

// Names returns the curated lexer names, optionally including aliases.
func Names(withAliases bool) []string {
	return registry().Names(withAliases)
}

// Get returns a curated lexer by name, alias, extension, or filename.
func Get(name string) chroma.Lexer {
	return registry().Get(name)
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
	// OpenCL C is a C superset. Chroma has no OpenCL lexer, and .cl otherwise
	// matches Common Lisp — which never shows up in ELF/Mach-O DWARF — so route
	// OpenCL kernels (.cl) to the C lexer for correct-enough highlighting.
	if strings.HasSuffix(base, ".cl") {
		if l := Get("c"); l != nil {
			return l
		}
	}
	// Objective-C++ (.mm) has no dedicated Chroma lexer; the Objective-C lexer is
	// the closest fit (Objective-C++ is Objective-C plus C++).
	if strings.HasSuffix(base, ".mm") {
		if l := Get("objective-c"); l != nil {
			return l
		}
	}
	return registry().Match(filename)
}

// Analyse chooses the best curated lexer for text content.
func Analyse(text string) chroma.Lexer {
	return registry().Analyse(text)
}
