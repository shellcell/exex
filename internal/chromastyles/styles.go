// Package chromastyles provides the curated Chroma style registry bundled by
// exex's default build.
package chromastyles

import (
	"embed"
	"io/fs"
	"sort"
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

// Names returns the sorted list of curated style names.
func Names() []string {
	reg := registry()
	out := make([]string, 0, len(reg))
	for name := range reg {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Lookup returns the named curated style and whether it is bundled.
func Lookup(name string) (*chroma.Style, bool) {
	style, ok := registry()[strings.ToLower(strings.TrimSpace(name))]
	return style, ok
}

// Get returns the named curated style or Fallback when the name is not bundled.
func Get(name string) *chroma.Style {
	if style, ok := Lookup(name); ok {
		return style
	}
	return Fallback()
}
