// Package chromastyles provides the curated Chroma style registry bundled by
// exex's default build.
package chromastyles

import (
	"embed"
	"io/fs"
	"sort"
	"strings"

	"github.com/alecthomas/chroma/v2"
)

//go:embed embedded/*.xml
var embedded embed.FS

// Registry is the curated style registry used at runtime.
var Registry = func() map[string]*chroma.Style {
	registry := map[string]*chroma.Style{}
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
		registry[strings.ToLower(style.Name)] = style
	}
	return registry
}()

// Fallback is the curated fallback style.
var Fallback = Registry["swapoff"]

// Names returns the sorted list of curated style names.
func Names() []string {
	out := make([]string, 0, len(Registry))
	for name := range Registry {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Lookup returns the named curated style and whether it is bundled.
func Lookup(name string) (*chroma.Style, bool) {
	style, ok := Registry[strings.ToLower(strings.TrimSpace(name))]
	return style, ok
}

// Get returns the named curated style or Fallback when the name is not bundled.
func Get(name string) *chroma.Style {
	if style, ok := Lookup(name); ok {
		return style
	}
	return Fallback
}
