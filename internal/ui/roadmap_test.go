package ui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/lipgloss"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/disasm"
)

func TestSourceSortRanksProjectFilesFirst(t *testing.T) {
	dir := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	defer func() { _ = os.Chdir(old) }()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd after Chdir: %v", err)
	}
	project := filepath.Join(wd, "cmd", "main.go")
	files := []string{"/usr/include/stdio.h", "/tmp/generated.c", project, "relative.c"}
	sortSourcesForProject(files, filepath.Join(dir, "app"))

	if !containsSame(files[:2], []string{project, "relative.c"}) {
		t.Fatalf("project sources not first: %v", files)
	}
	if files[len(files)-1] != "/usr/include/stdio.h" {
		t.Fatalf("external system source should sort last: %v", files)
	}
}

func TestSymbolTypeFilterCyclesAndFilters(t *testing.T) {
	m := &Model{file: &binfile.File{Symbols: []binfile.Symbol{
		{Name: "data", Kind: binfile.SymObject},
		{Name: "fn", Kind: binfile.SymFunc},
		{Name: "sec", Kind: binfile.SymSection},
	}}}
	m.symbolsFilter = textinput.New()
	m.recomputeSymbols()
	if got := len(m.symbolsFiltered); got != 3 {
		t.Fatalf("initial filtered count = %d, want 3", got)
	}
	m.cycleSymbolKindFilter()
	m.recomputeSymbols()
	if got := len(m.symbolsFiltered); got != 1 {
		t.Fatalf("func filtered count = %d, want 1", got)
	}
	if sym := m.file.Symbols[m.symbolsFiltered[0]]; sym.Kind != binfile.SymFunc {
		t.Fatalf("filtered symbol kind = %v, want func", sym.Kind)
	}
}

func TestOpenSearchClearsInputButKeepsRepeatQuery(t *testing.T) {
	m := &Model{searchQuery: "old"}
	m.searchInput = textinput.New()
	m.searchInput.SetValue("stale")
	m.openSearch()
	if got := m.searchInput.Value(); got != "" {
		t.Fatalf("search input = %q, want empty", got)
	}
	if got := m.searchQuery; got != "old" {
		t.Fatalf("repeat query = %q, want old", got)
	}
}

func TestGotoUnmappedAddressOpensRaw(t *testing.T) {
	path := firstExisting("/bin/ls", "/usr/bin/true", "/bin/cat")
	if path == "" {
		t.Skip("no system binary available")
	}
	f, err := binfile.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	m, err := New(f)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	addr := uint64(len(f.Raw()) + 1)
	if f.Info != nil && f.Info.MappedHi >= addr {
		addr = f.Info.MappedHi + 0x100000
	}
	m.gotoAddr(addr)
	if m.mode != modeRaw {
		t.Fatalf("mode = %v, want raw", m.mode)
	}
	if m.rawCur != 0 {
		t.Fatalf("raw cursor = %d, want clamped 0", m.rawCur)
	}
}

func TestTruncateMiddleKeepsEnds(t *testing.T) {
	got := truncateMiddle("/very/long/source/path/main.go", 16)
	if got == "/very/long/source/path/main.go" || lipgloss.Width(got) > 16 {
		t.Fatalf("truncateMiddle returned %q", got)
	}
	if got[:1] != "/" || got[len(got)-5:] != "in.go" {
		t.Fatalf("truncateMiddle did not keep useful ends: %q", got)
	}
}

func TestRenderLineRowsActuallyWraps(t *testing.T) {
	line := "0123456789 abcdefghij klmnopqrst"
	rows := renderLineRows(line, 12, true)
	if len(rows) < 3 {
		t.Fatalf("wrapped rows = %d, want at least 3: %q", len(rows), rows)
	}
	for _, row := range rows {
		if w := lipgloss.Width(stripANSI(row)); w > 12 {
			t.Fatalf("row width = %d, want <= 12: %q", w, row)
		}
	}
	if got := renderLineRows(line, 12, false); len(got) != 1 {
		t.Fatalf("non-wrapped rows = %d, want 1", len(got))
	}
}

func TestRenderLineRowsIndentedContinuation(t *testing.T) {
	rows := renderLineRowsIndented("addr type very-long-content-that-wraps", 18, true, 6)
	if len(rows) < 2 {
		t.Fatalf("rows = %q, want wrapped continuation", rows)
	}
	for i, row := range rows[1:] {
		plain := stripANSI(row)
		if len(plain) < 6 || plain[:6] != "      " {
			t.Fatalf("continuation row %d not indented: %q", i+1, plain)
		}
		if w := lipgloss.Width(plain); w > 18 {
			t.Fatalf("continuation row width = %d, want <= 18: %q", w, plain)
		}
	}
}

func TestSearchPopupClickTogglesSwitches(t *testing.T) {
	m := &Model{width: 100, height: 30, searchActive: true, searchForward: true, searchFromCursor: true}
	m.searchInput = textinput.New()
	modal := m.renderSearchModal()
	left := (m.width - lipgloss.Width(modal)) / 2
	top := (m.height - lipgloss.Height(modal)) / 2
	m.handleSearchPopupClick(left+4, top+4)
	if m.searchMode != searchModeText {
		t.Fatalf("mode click set mode = %s, want text", searchModeName(m.searchMode))
	}
	m.handleSearchPopupClick(left+lipgloss.Width(modal)/2, top+4)
	if m.searchForward {
		t.Fatal("direction click did not toggle searchForward")
	}
	m.handleSearchPopupClick(left+lipgloss.Width(modal)-4, top+4)
	if m.searchFromCursor {
		t.Fatal("origin click did not toggle searchFromCursor")
	}
}

func TestWrappedSymbolsKeepAddressGrayOnContinuation(t *testing.T) {
	m := &Model{width: 42, wrapLong: map[mode]bool{modeSymbols: true}, file: &binfile.File{Symbols: []binfile.Symbol{{
		Name: strings.Repeat("very_long_symbol_name_", 5), Addr: 0x1000, Kind: binfile.SymFunc,
	}}}}
	m.symbolsFiltered = []int{0}
	rows := m.symbolRows(0, 8, false)
	if len(rows) < 2 {
		t.Fatalf("symbol did not wrap: %q", rows)
	}
	if strings.Contains(rows[1], "0x00001000") {
		t.Fatalf("continuation row repeated address: %q", rows[1])
	}
	if strings.Contains(rows[0], "\x1b[38;5;84m0x") {
		t.Fatalf("address inherited symbol function color: %q", rows[0])
	}
}

func TestWrappedSymbolsMouseSelectionUsesVisualRows(t *testing.T) {
	m := &Model{
		mode:     modeSymbols,
		width:    42,
		height:   120,
		wrapLong: map[mode]bool{modeSymbols: true},
		file: &binfile.File{Symbols: []binfile.Symbol{
			{Name: strings.Repeat("very_long_symbol_name_", 5), Addr: 0x1000, Kind: binfile.SymFunc},
			{Name: "second", Addr: 0x2000, Kind: binfile.SymObject},
		}},
	}
	m.symbolsFiltered = []int{0, 1}
	firstRows := m.symbolRowHeight(0)
	if firstRows < 2 {
		t.Fatalf("first symbol did not wrap")
	}
	m.handleClick(1, 1+2+firstRows-1)
	if m.symbolsCur != 0 {
		t.Fatalf("click on first continuation selected %d, want 0", m.symbolsCur)
	}
	m.handleClick(1, 1+2+firstRows)
	if m.symbolsCur != 1 {
		t.Fatalf("click after wrapped first selected %d, want 1", m.symbolsCur)
	}
}

func TestVisualItemAtRowUsesWrappedHeights(t *testing.T) {
	heights := func(i int) int {
		if i == 0 {
			return 3
		}
		return 1
	}
	if got, ok := visualItemAtRow(0, 3, 2, heights); !ok || got != 0 {
		t.Fatalf("row 2 maps to %d,%v; want first wrapped item", got, ok)
	}
	if got, ok := visualItemAtRow(0, 3, 3, heights); !ok || got != 1 {
		t.Fatalf("row 3 maps to %d,%v; want second item", got, ok)
	}
}

func TestRawClickSkipsSectionSplitRows(t *testing.T) {
	m := &Model{width: 100, file: &binfile.File{Sections: []binfile.Section{{Name: ".text", Offset: 0, FileSize: 32}}}}
	data := make([]byte, 64)
	cur := m.clickByte(modeRaw, data, 0, 7, hexBodyStart(16), 1, func(pos int) uint64 { return uint64(pos) })
	if cur != 7 {
		t.Fatalf("click on split row changed cursor to %d", cur)
	}
	cur = m.clickByte(modeRaw, data, 0, 7, hexBodyStart(16), 2, func(pos int) uint64 { return uint64(pos) })
	if cur != 0 {
		t.Fatalf("click on first data row selected %d, want 0", cur)
	}
}

func TestDisasmAnnotationWrapsWithGrayStyleEachRow(t *testing.T) {
	m := &Model{width: 64, wrapLong: map[mode]bool{modeDisasm: true}, file: &binfile.File{Sections: []binfile.Section{{
		Name: strings.Repeat("very_long_section_name_", 5), Addr: 0x2000, Size: 8, Alloc: true,
	}}}}
	inst := disasm.Inst{Addr: 0x1000, Text: "call 0x2000", Class: disasm.ClassCall, Bytes: []byte{0xe8}}
	rows := m.disasmInstRows(inst, 64, false, nil)
	if len(rows) < 2 {
		t.Fatalf("annotation did not wrap: %q", rows)
	}
	for _, row := range rows {
		if strings.Contains(stripANSI(row), "very_long_section_name_") && !strings.Contains(row, "\x1b[") {
			t.Fatalf("annotation row lost ANSI styling: %q", row)
		}
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
