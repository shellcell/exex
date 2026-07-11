package chromalexers

import (
	"io/fs"
	"regexp"
	"testing"
)

// usingRef matches a static cross-lexer delegation, e.g. <using lexer="CSS"/>.
var usingRef = regexp.MustCompile(`using\s+lexer="([^"]+)"`)

// TestUsingGraphIsClosed guards the curated lexer set against dangling
// delegations. A lexer XML can hand a sub-region to another lexer by name
// (<using lexer="X"/>); Chroma resolves X against the same registry at tokenise
// time and *panics* if it is absent. So dropping a lexer from lexers.txt that
// another still references (as removing CSS would have broken HTML) turns into a
// crash on one file type — this test turns that into a build-time failure.
func TestUsingGraphIsClosed(t *testing.T) {
	paths, err := fs.Glob(embedded, "embedded/*.xml")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		data, err := fs.ReadFile(embedded, path)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range usingRef.FindAllStringSubmatch(string(data), -1) {
			ref := m[1]
			if Get(ref) == nil {
				t.Errorf("%s delegates to lexer %q, which is not in the curated set "+
					"(add %q to internal/chromasubset/lexers.txt, or it will panic at runtime)", path, ref, ref)
			}
		}
	}
}
