// Package chromastyles provides the curated Chroma style registry bundled by
// exex's default build.
package chromastyles

import (
	"embed"
	"io/fs"
	"strings"
	"sync"

	"github.com/alecthomas/chroma/v2"
)

//go:embed embedded/*.xml
var embedded embed.FS

// registry parses the curated styles on first use. Lazy so that runs that never
// highlight (most `-o` dumps) skip parsing the embedded XML at startup.
var registry = sync.OnceValue(func() map[string]*chroma.Style {
	reg := map[string]*chroma.Style{}
	files, err := fs.ReadDir(embedded, "embedded")
	if err != nil {
		panic(err)
	}
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		r, err := embedded.Open("embedded/" + file.Name())
		if err != nil {
			panic(err)
		}
		style, err := chroma.NewXMLStyle(r)
		_ = r.Close()
		if err != nil {
			panic(err)
		}
		reg[strings.ToLower(style.Name)] = style
	}
	return reg
})

// Fallback returns the curated fallback style.
func Fallback() *chroma.Style {
	return registry()["swapoff"]
}

// Lookup returns the named curated style and whether it is bundled. Callers
// decide what an absent style means; there is deliberately no Get-with-fallback
// helper, because silently substituting a different style is what let the
// settings picker offer themes it could not actually render.
func Lookup(name string) (*chroma.Style, bool) {
	style, ok := registry()[strings.ToLower(strings.TrimSpace(name))]
	return style, ok
}
