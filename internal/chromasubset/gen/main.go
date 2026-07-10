//go:build ignore

// Command gen copies the curated Chroma lexer/style XML manifests into the
// internal runtime registries.
package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/rabarbra/exex/internal/chromasubset"
)

func main() {
	chromaDir, err := chromaModuleDir()
	if err != nil {
		fatal(err)
	}
	lexers, err := chromasubset.LexerAssets()
	if err != nil {
		fatal(err)
	}
	styles, err := chromasubset.StyleAssets()
	if err != nil {
		fatal(err)
	}
	if err := copyAssets("lexers.txt", lexers, filepath.Join(chromaDir, "lexers", "embedded"), filepath.Join("..", "chromalexers", "embedded")); err != nil {
		fatal(err)
	}
	if err := copyAssets("styles.txt", styles, filepath.Join(chromaDir, "styles"), filepath.Join("..", "chromastyles", "embedded")); err != nil {
		fatal(err)
	}
}

func chromaModuleDir() (string, error) {
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/alecthomas/chroma/v2")
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("go list chroma module: %w: %s", err, strings.TrimSpace(string(ee.Stderr)))
		}
		return "", fmt.Errorf("go list chroma module: %w", err)
	}
	dir := strings.TrimSpace(string(out))
	if dir == "" {
		return "", fmt.Errorf("go list returned an empty Chroma module directory")
	}
	return dir, nil
}

// copyAssets replaces dstDir with exactly the named assets, so a name dropped
// from the manifest is dropped from the embedded set too.
func copyAssets(manifest string, names []string, srcDir, dstDir string) error {
	if err := os.RemoveAll(dstDir); err != nil {
		return fmt.Errorf("clear %s: %w", dstDir, err)
	}
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dstDir, err)
	}
	for _, name := range names {
		if err := copyFile(filepath.Join(srcDir, name), filepath.Join(dstDir, name)); err != nil {
			return err
		}
	}
	fmt.Printf("copied %d assets from %s into %s\n", len(names), manifest, dstDir)
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return fmt.Errorf("copy %s to %s: %w", src, dst, copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close %s: %w", dst, closeErr)
	}
	return nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
