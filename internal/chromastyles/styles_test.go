package chromastyles

import (
	"testing"

	"github.com/rabarbra/exex/internal/chromasubset"
)

func TestCuratedStyles(t *testing.T) {
	for _, name := range []string{"swapoff", "nord", "catppuccin-mocha", "dracula", "solarized-dark", "solarized-light"} {
		if st, ok := Lookup(name); !ok || st == nil {
			t.Errorf("Lookup(%q) returned no style", name)
		}
	}
}

func TestCuratedStyleFallback(t *testing.T) {
	if Fallback() == nil {
		t.Fatal("Fallback is nil")
	}
	if _, ok := Lookup("definitely-not-a-style"); ok {
		t.Fatal("unknown style unexpectedly bundled")
	}
}

// TestBundledMatchesManifest keeps the embedded assets and the manifest in step.
// internal/theme's palette table is generated from the same manifest, so drift
// here is drift between the settings picker and the styles it can render.
func TestBundledMatchesManifest(t *testing.T) {
	names, err := chromasubset.StyleNames()
	if err != nil {
		t.Fatalf("StyleNames: %v", err)
	}
	for _, name := range names {
		if _, ok := Lookup(name); !ok {
			t.Errorf("styles.txt lists %q but it is not embedded; run go generate ./internal/chromasubset", name)
		}
	}
	if got := len(registry()); got != len(names) {
		t.Errorf("embedded %d styles, manifest lists %d", got, len(names))
	}
}
