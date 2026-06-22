package binfile

import "testing"

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
