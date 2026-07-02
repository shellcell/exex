//go:build ignore

// Command gen copies the curated Chroma lexer/style XML manifests into the
// internal runtime registries.
package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	chromaDir, err := chromaModuleDir()
	if err != nil {
		fatal(err)
	}
	if err := copyManifest("lexers.txt", filepath.Join(chromaDir, "lexers", "embedded"), filepath.Join("..", "chromalexers", "embedded")); err != nil {
		fatal(err)
	}
	if err := copyManifest("styles.txt", filepath.Join(chromaDir, "styles"), filepath.Join("..", "chromastyles", "embedded")); err != nil {
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

func copyManifest(manifest, srcDir, dstDir string) error {
	names, err := readManifest(manifest)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(dstDir); err != nil {
		return fmt.Errorf("clear %s: %w", dstDir, err)
	}
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dstDir, err)
	}
	for _, name := range names {
		if filepath.Base(name) != name || !strings.HasSuffix(name, ".xml") {
			return fmt.Errorf("%s: invalid asset name %q", manifest, name)
		}
		if err := copyFile(filepath.Join(srcDir, name), filepath.Join(dstDir, name)); err != nil {
			return err
		}
	}
	fmt.Printf("copied %d assets from %s into %s\n", len(names), manifest, dstDir)
	return nil
}

func readManifest(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	seen := map[string]bool{}
	var names []string
	s := bufio.NewScanner(f)
	for line := 1; s.Scan(); line++ {
		name := strings.TrimSpace(s.Text())
		if name == "" || strings.HasPrefix(name, "#") {
			continue
		}
		if seen[name] {
			return nil, fmt.Errorf("%s:%d: duplicate asset %q", path, line, name)
		}
		seen[name] = true
		names = append(names, name)
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("%s has no assets", path)
	}
	return names, nil
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
