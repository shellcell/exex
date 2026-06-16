package sourcefiles

import (
	"path/filepath"
	"testing"
)

func TestSortForProjectRanksProjectFilesFirst(t *testing.T) {
	dir := t.TempDir()
	project := filepath.Join(dir, "cmd", "main.go")
	files := []string{"/usr/include/stdio.h", "/tmp/generated.c", project, "relative.c"}

	SortForProject(files, filepath.Join(dir, "app"), dir)

	if !containsSame(files[:2], []string{project, "relative.c"}) {
		t.Fatalf("project sources not first: %v", files)
	}
	if files[len(files)-1] != "/usr/include/stdio.h" {
		t.Fatalf("external system source should sort last: %v", files)
	}
}

func TestFindInLines(t *testing.T) {
	lines := []string{"alpha", "Beta", "gamma beta"}
	if got := FindInLines(lines, "beta", 1, true); got != 2 {
		t.Fatalf("forward = %d, want 2", got)
	}
	if got := FindInLines(lines, "beta", 3, false); got != 3 {
		t.Fatalf("backward inclusive = %d, want 3", got)
	}
	if got := FindInLines(lines, "missing", 1, true); got != 0 {
		t.Fatalf("missing = %d, want 0", got)
	}
}

func TestGrep(t *testing.T) {
	files := []string{"a.go", "b.go"}
	contents := map[string][]string{
		"a.go": {"one", "needle"},
		"b.go": {"Needle again", "needle third"},
	}
	matches := Grep(files, func(file string) []string { return contents[file] }, "needle", 2)
	if len(matches) != 2 {
		t.Fatalf("matches = %d, want cap 2", len(matches))
	}
	if matches[0] != (Match{File: "a.go", Line: 2}) || matches[1] != (Match{File: "b.go", Line: 1}) {
		t.Fatalf("matches = %#v", matches)
	}
}

func containsSame(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := map[string]int{}
	for _, s := range got {
		seen[s]++
	}
	for _, s := range want {
		if seen[s] == 0 {
			return false
		}
		seen[s]--
	}
	return true
}
