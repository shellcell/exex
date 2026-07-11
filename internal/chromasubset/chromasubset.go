// Package chromasubset owns the curated Chroma XML manifests bundled by exex.
//
// The manifests are the single source of truth for the curated set. Two
// generators read them:
//
//   - gen/main.go copies the named XML assets into internal/chromalexers and
//     internal/chromastyles, which embed them.
//   - internal/theme/gen/main.go emits a palette entry for each curated style,
//     so internal/theme never describes a theme whose highlighter is absent.
//
// Keeping both generators on one list is what stops the settings picker from
// offering themes that silently fall back to the minimal highlighter.
package chromasubset

import (
	"bufio"
	_ "embed"
	"fmt"
	"path"
	"strings"
)

//go:generate go run gen/main.go

//go:embed styles.txt
var stylesManifest string

//go:embed lexers.txt
var lexersManifest string

// StyleAssets returns the curated style XML filenames in manifest order.
func StyleAssets() ([]string, error) { return parseManifest("styles.txt", stylesManifest) }

// LexerAssets returns the curated lexer XML filenames in manifest order.
func LexerAssets() ([]string, error) { return parseManifest("lexers.txt", lexersManifest) }

// StyleNames returns the curated Chroma style names — the asset filenames minus
// their ".xml" suffix. Chroma's own style names match their filenames; the
// theme generator verifies that rather than trusting it.
func StyleNames() ([]string, error) {
	assets, err := StyleAssets()
	if err != nil {
		return nil, err
	}
	names := make([]string, len(assets))
	for i, a := range assets {
		names[i] = strings.TrimSuffix(a, ".xml")
	}
	return names, nil
}

// parseManifest reads one asset name per line, ignoring blanks and # comments,
// and rejects duplicates and anything that isn't a bare .xml filename.
func parseManifest(name, body string) ([]string, error) {
	seen := map[string]bool{}
	var assets []string
	s := bufio.NewScanner(strings.NewReader(body))
	for line := 1; s.Scan(); line++ {
		asset := strings.TrimSpace(s.Text())
		if asset == "" || strings.HasPrefix(asset, "#") {
			continue
		}
		if path.Base(asset) != asset || !strings.HasSuffix(asset, ".xml") {
			return nil, fmt.Errorf("%s:%d: invalid asset name %q", name, line, asset)
		}
		if seen[asset] {
			return nil, fmt.Errorf("%s:%d: duplicate asset %q", name, line, asset)
		}
		seen[asset] = true
		assets = append(assets, asset)
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	if len(assets) == 0 {
		return nil, fmt.Errorf("%s has no assets", name)
	}
	return assets, nil
}
