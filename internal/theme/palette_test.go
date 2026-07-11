package theme

import (
	"testing"

	"github.com/rabarbra/exex/internal/chromasubset"
)

// TestNamesMatchManifest pins palettes_gen.go to the curated manifest. This
// package is Chroma-free (it links into the lite build), so it cannot check the
// style XMLs directly — but both sides are generated from styles.txt, and this
// catches a stale palettes_gen.go after the manifest changes.
func TestNamesMatchManifest(t *testing.T) {
	want, err := chromasubset.StyleNames()
	if err != nil {
		t.Fatalf("StyleNames: %v", err)
	}
	if got := len(Names()); got != len(want) {
		t.Errorf("palettes_gen.go has %d palettes, manifest lists %d; run go generate ./internal/theme", got, len(want))
	}
	for _, name := range want {
		if _, ok := PaletteFor(name); !ok {
			t.Errorf("no palette for curated style %q; run go generate ./internal/theme", name)
		}
	}
}

func TestPaletteForResolvesEmptyFields(t *testing.T) {
	p, ok := PaletteFor("nord")
	if !ok {
		t.Fatal("nord palette missing")
	}
	if p.Foreground == "" || p.Background == "" || p.Comment == "" || p.Keyword == "" {
		t.Errorf("resolved palette left fields empty: %+v", p)
	}
	if _, ok := PaletteFor("definitely-not-a-style"); ok {
		t.Error("unknown style unexpectedly has a palette")
	}
}
