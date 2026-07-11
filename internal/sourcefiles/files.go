// Package sourcefiles ranks and searches source files referenced by debug info.
package sourcefiles

import (
	"path/filepath"
	"sort"
	"strings"
)

// Match is one source-line search hit.
type Match struct {
	File string
	Line int
}

// SortForProject sorts source files so project-local paths appear before
// generated/absolute paths, and system/vendor paths are last.
func SortForProject(files []string, binPath, workDir string) {
	root := filepath.Dir(binPath)
	if workDir != "" {
		root = workDir
	}
	sort.SliceStable(files, func(i, j int) bool {
		ri, rj := Rank(files[i], root), Rank(files[j], root)
		if ri != rj {
			return ri < rj
		}
		return files[i] < files[j]
	})
}

// Rank assigns a stable priority bucket: project-local files first, generated or
// ambiguous files next, and system/vendor files last.
func Rank(file, root string) int {
	if root != "" {
		if rel, err := filepath.Rel(root, file); err == nil && rel != "." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".." {
			return 0
		}
	}
	base := filepath.Base(file)
	if strings.HasPrefix(file, "/usr/") || strings.HasPrefix(file, "/System/") || strings.HasPrefix(file, "/Library/") || strings.Contains(file, "/.cargo/registry/") || strings.Contains(file, "/go/pkg/mod/") {
		return 2
	}
	if !filepath.IsAbs(file) || !strings.Contains(base, ".") {
		return 0
	}
	return 1
}

// FindInLines returns the 1-based line number of the next/previous line that
// contains query, or 0 when no match exists. start is also 1-based.
func FindInLines(lines []string, query string, start int, forward bool) int {
	q := strings.ToLower(query)
	if q == "" {
		return 0
	}
	hit := func(i int) bool {
		return i >= 1 && i <= len(lines) && strings.Contains(strings.ToLower(lines[i-1]), q)
	}
	if forward {
		for i := start; i <= len(lines); i++ {
			if hit(i) {
				return i
			}
		}
		return 0
	}
	for i := start; i >= 1; i-- {
		if hit(i) {
			return i
		}
	}
	return 0
}

// Grep scans source files for query and returns at most limit matches. linesFor
// supplies file contents as individual lines.
func Grep(files []string, linesFor func(string) []string, query string, limit int) []Match {
	q := strings.ToLower(query)
	if q == "" || limit <= 0 {
		return nil
	}
	var out []Match
	for _, f := range files {
		for i, line := range linesFor(f) {
			if strings.Contains(strings.ToLower(line), q) {
				out = append(out, Match{File: f, Line: i + 1})
				if len(out) >= limit {
					return out
				}
			}
		}
	}
	return out
}

// GrepStream is Grep for a streaming line source. scan calls yield in line
// order and stops when yield returns false, so callers need not retain every
// source file merely to search it.
func GrepStream(files []string, scan func(string, func(string) bool), query string, limit int) []Match {
	q := strings.ToLower(query)
	if q == "" || limit <= 0 {
		return nil
	}
	var out []Match
	for _, file := range files {
		lineNo := 0
		scan(file, func(line string) bool {
			lineNo++
			if strings.Contains(strings.ToLower(line), q) {
				out = append(out, Match{File: file, Line: lineNo})
			}
			return len(out) < limit
		})
		if len(out) >= limit {
			return out
		}
	}
	return out
}
