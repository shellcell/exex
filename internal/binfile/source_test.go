package binfile

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSourceFilesAndLineToAddr(t *testing.T) {
	f := &File{
		lineFiles: []string{"a.c", "b.c"},
		lines: []lineEntry{
			{Addr: 0x1000, File: 0, Line: 10, Col: 5},
			{Addr: 0x1010, File: 0, Line: 11, Col: 2},
			{Addr: 0x1020, File: 1, Line: 5},
			{Addr: 0x1030, File: 0, Line: 11, Col: 9},
			{Addr: 0x1040, File: 0, Line: 12},
		},
	}

	files := f.SourceFiles()
	if len(files) != 2 || files[0] != "a.c" || files[1] != "b.c" {
		t.Fatalf("SourceFiles() = %v, want [a.c b.c]", files)
	}

	cases := []struct {
		file string
		line int
		want uint64
		ok   bool
	}{
		{"a.c", 11, 0x1010, true},
		{"b.c", 5, 0x1020, true},
		{"a.c", 9, 0x1000, true}, // nearest line >= 9 is line 10
		{"nope.c", 1, 0, false},
	}
	for _, c := range cases {
		got, ok := f.LineToAddr(c.file, c.line)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("LineToAddr(%q, %d) = 0x%x, %v; want 0x%x, %v", c.file, c.line, got, ok, c.want, c.ok)
		}
	}

	file, line, col := f.LookupAddrCol(0x1035)
	if file != "a.c" || line != 11 || col != 9 {
		t.Fatalf("LookupAddrCol = %q:%d:%d, want a.c:11:9", file, line, col)
	}
	mapped := f.MappedLines("a.c")
	if !mapped[10] || !mapped[11] || !mapped[12] || mapped[5] {
		t.Fatalf("MappedLines(a.c) = %#v", mapped)
	}
	mapped[10] = false
	if f.MappedLines("a.c")[10] != true {
		t.Fatal("MappedLines returned map was not a defensive copy")
	}
	cols := f.LineColumns("a.c", 11)
	if len(cols) != 2 || cols[0] != 2 || cols[1] != 9 {
		t.Fatalf("LineColumns = %#v, want [2 9]", cols)
	}
}

func TestSourceCacheEvictsLeastRecentlyUsed(t *testing.T) {
	dir := t.TempDir()
	paths := make([]string, 3)
	for i, name := range []string{"a.c", "b.c", "c.c"} {
		paths[i] = filepath.Join(dir, name)
		if err := os.WriteFile(paths[i], []byte(name+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	f := &File{sourceCacheBudget: 1 << 20, sourceCacheMaxEntries: 2}
	f.SourceLines(paths[0])
	f.SourceLines(paths[1])
	f.SourceLines(paths[0]) // refresh a.c
	f.SourceLines(paths[2])
	if f.sourceCache[paths[0]] == nil || f.sourceCache[paths[2]] == nil {
		t.Fatal("recent source files were evicted")
	}
	if f.sourceCache[paths[1]] != nil {
		t.Fatal("least recently used source file remained cached")
	}
}

func TestScanSourceLinesDoesNotPopulateDisplayCache(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source.c")
	if err := os.WriteFile(path, []byte("one\ntwo\nthree"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := &File{}
	var got []string
	if !f.ScanSourceLines(path, func(line string) bool {
		got = append(got, line)
		return true
	}) {
		t.Fatal("source file was not scanned")
	}
	if !reflect.DeepEqual(got, []string{"one", "two", "three"}) {
		t.Fatalf("lines = %#v", got)
	}
	if len(f.sourceCache) != 0 {
		t.Fatal("streaming scan populated the display cache")
	}
}

func TestDetailedSourceIndexesReleaseDWARFData(t *testing.T) {
	path, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	f, err := Open(path)
	if err != nil {
		t.Skip(err)
	}
	defer f.Close()
	files := f.SourceFiles()
	if len(files) == 0 || f.dwarf == nil {
		t.Skip("test binary has no readable DWARF line table")
	}
	f.MappedLines(files[0])
	if f.dwarf != nil {
		t.Fatal("parsed DWARF data remained retained after compact line indexes were built")
	}
}
