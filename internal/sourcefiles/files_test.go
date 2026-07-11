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

func TestRankBucketsSources(t *testing.T) {
	root := filepath.Join(t.TempDir(), "project")
	tests := []struct {
		file string
		want int
	}{
		{file: filepath.Join(root, "main.go"), want: 0},
		{file: "relative.c", want: 0},
		{file: filepath.Join(t.TempDir(), "generated.c"), want: 1},
		{file: "/usr/include/stdio.h", want: 2},
		{file: filepath.Join(string(filepath.Separator), "home", "me", "go", "pkg", "mod", "x.go"), want: 2},
	}
	for _, tt := range tests {
		if got := Rank(tt.file, root); got != tt.want {
			t.Fatalf("Rank(%q) = %d, want %d", tt.file, got, tt.want)
		}
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
	if got := FindInLines(lines, "alpha", -10, true); got != 1 {
		t.Fatalf("negative forward start = %d, want 1", got)
	}
	if got := FindInLines(lines, "beta", 100, false); got != 3 {
		t.Fatalf("oversized backward start = %d, want 3", got)
	}
	if got := FindInLines(lines, "", 1, true); got != 0 {
		t.Fatalf("empty query = %d, want 0", got)
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
	if matches := Grep(files, func(file string) []string { return contents[file] }, "needle", 0); matches != nil {
		t.Fatalf("zero limit matches = %#v, want nil", matches)
	}
	if matches := Grep(files, func(file string) []string { return contents[file] }, "", 2); matches != nil {
		t.Fatalf("empty query matches = %#v, want nil", matches)
	}
}

func TestGrepStream(t *testing.T) {
	files := []string{"a.go", "b.go"}
	contents := map[string][]string{
		"a.go": {"one", "needle"},
		"b.go": {"Needle again", "needle third"},
	}
	matches := GrepStream(files, func(file string, yield func(string) bool) {
		for _, line := range contents[file] {
			if !yield(line) {
				return
			}
		}
	}, "needle", 2)
	if len(matches) != 2 || matches[0] != (Match{File: "a.go", Line: 2}) || matches[1] != (Match{File: "b.go", Line: 1}) {
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
