package ui

import (
	searchutil "github.com/rabarbra/exex/internal/bytesearch"
	searchmodal "github.com/rabarbra/exex/internal/ui/modals/search"
	"os"
	"strings"
	"testing"
	"time"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/disasm"
	"github.com/rabarbra/exex/internal/ui/layout"
	"github.com/rabarbra/exex/internal/ui/views/hexraw"
)

const testBytesPerHexRow = 16

func testHexBodyStart(addrW int) int { return 1 + 2 + addrW + 2 }

func renderHexTest(m *Model) string { return m.byteViews.Render(m.viewContextPtr(), hexraw.Hex) }
func renderRawTest(m *Model) string { return m.byteViews.Render(m.viewContextPtr(), hexraw.Raw) }

func TestSymbolTypeFilterCyclesAndFilters(t *testing.T) {
	m := &Model{
		theme: DefaultTheme(),
		file: &binfile.File{Symbols: []binfile.Symbol{
			{Name: "data", Kind: binfile.SymObject},
			{Name: "fn", Kind: binfile.SymFunc},
			{Name: "sec", Kind: binfile.SymSection},
		}},
	}
	m.symbols.Filter = textinput.New()
	m.symbols.Recompute(m.viewContext())
	if got := len(m.symbols.Filtered); got != 3 {
		t.Fatalf("initial filtered count = %d, want 3", got)
	}
	m.symbols.Update(m.viewContext(), m, "ctrl+t")
	m.symbols.Recompute(m.viewContext())
	if got := len(m.symbols.Filtered); got != 1 {
		t.Fatalf("func filtered count = %d, want 1", got)
	}
	if sym := m.file.Symbols[m.symbols.Filtered[0]]; sym.Kind != binfile.SymFunc {
		t.Fatalf("filtered symbol kind = %v, want func", sym.Kind)
	}
}

func TestOpenSearchClearsInputButKeepsRepeatQuery(t *testing.T) {
	m := &Model{searchState: searchState{searchQuery: "old"}}
	m.search.Init(textinput.New())
	m.search.Open()
	m.search.HandleInput(tea.PasteMsg{Content: "stale"})
	m.search.Open()
	if got := m.search.Value(); got != "" {
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
	if m.byteViews.RawCur != 0 {
		t.Fatalf("raw cursor = %d, want clamped 0", m.byteViews.RawCur)
	}
}

func TestParseAddr(t *testing.T) {
	tests := []struct {
		in   string
		want uint64
	}{
		{in: "123", want: 123},
		{in: "0x10", want: 16},
		{in: "0X20", want: 32},
		{in: "deadbeef", want: 0xdeadbeef},
		{in: " 42 ", want: 42},
	}
	for _, tt := range tests {
		got, err := parseAddr(tt.in)
		if err != nil || got != tt.want {
			t.Fatalf("parseAddr(%q) = 0x%x, %v; want 0x%x", tt.in, got, err, tt.want)
		}
	}
	if _, err := parseAddr("not an address"); err == nil {
		t.Fatal("parseAddr invalid input succeeded, want error")
	}
}

func TestDefaultViewAndNavHelpers(t *testing.T) {
	if got := parseDefaultView(" DISASM "); got != modeDisasm {
		t.Fatalf("parseDefaultView(DISASM) = %v, want disasm", got)
	}
	if got := parseDefaultView("unknown"); got != modeInfo {
		t.Fatalf("parseDefaultView(unknown) = %v, want info", got)
	}
	m := &Model{}
	if got := m.normalizeNavKey("ctrl+a"); got != "home" {
		t.Fatalf("normalize ctrl+a = %q, want home", got)
	}
	if got := m.normalizeNavKey("alt+down"); got != "pgdown" {
		t.Fatalf("normalize alt+down = %q, want pgdown", got)
	}
	if !keyReattachesViewport("pgdown") || keyReattachesViewport("enter") {
		t.Fatal("keyReattachesViewport returned unexpected values")
	}
}

func TestHexColumnToByteBounds(t *testing.T) {
	addrW := 8
	bpr := testBytesPerHexRow
	start := testHexBodyStart(addrW)
	if got := hexraw.ColumnToByte(addrW, bpr, start-10); got != 0 {
		t.Fatalf("column before hex body = %d, want 0", got)
	}
	if got := hexraw.ColumnToByte(addrW, bpr, start); got != 0 {
		t.Fatalf("first byte column = %d, want 0", got)
	}
	if got := hexraw.ColumnToByte(addrW, bpr, start+3*8+1); got != 8 {
		t.Fatalf("column after midpoint gap = %d, want 8", got)
	}
	if got := hexraw.ColumnToByte(addrW, bpr, start+1000); got != testBytesPerHexRow-1 {
		t.Fatalf("column after row = %d, want last byte", got)
	}
}

func TestHexVisibleTopPreservesUnalignedSectionStart(t *testing.T) {
	// Two regions: an aligned one [0x00,0x65) and an unaligned section B that
	// starts at data position 0x65 / address 0x2003 (lead 3).
	const sectionStart = 0x65
	m := &Model{
		theme:       DefaultTheme(),
		file:        &binfile.File{},
		layoutState: layoutState{width: 120, height: 13},
		byteViews: hexraw.State{HexImg: binfile.NewImage(make([]byte, 0x200), []binfile.Region{
			{Addr: 0x1000, Size: sectionStart, Off: 0, Name: "A"},
			{Addr: 0x2003, Size: 0x200 - sectionStart, Off: sectionStart, Name: "B"},
		})},
	}

	m.byteViews.HexCur = sectionStart
	m.byteViews.HexTop = sectionStart
	renderHexTest(m)
	if got := m.byteViews.HexTop; got != sectionStart {
		t.Fatalf("hexVisibleTop at section start = 0x%x, want 0x%x", got, sectionStart)
	}
	// The row ending the previous section is address-aligned at 0x60.
	m.byteViews.HexCur = sectionStart - 1
	m.byteViews.HexTop = sectionStart
	renderHexTest(m)
	if got := m.byteViews.HexTop; got != 0x60 {
		t.Fatalf("hexVisibleTop before section start = 0x%x, want 0x60", got)
	}
	m.byteViews.HexTop = sectionStart
	m.byteViews.Scroll(m.viewContextPtr(), hexraw.Hex, -1)
	if got := m.byteViews.HexTop; got != 0x60 {
		t.Fatalf("scrollByteViewportTop up = 0x%x, want 0x60", got)
	}
	// Section B's first row spans the 13 bytes up to the next aligned address.
	m.byteViews.HexTop = sectionStart
	m.byteViews.Scroll(m.viewContextPtr(), hexraw.Hex, 1)
	if got := m.byteViews.HexTop; got != sectionStart+13 {
		t.Fatalf("scrollByteViewportTop down = 0x%x, want 0x%x", got, sectionStart+13)
	}
}

// TestHexMiddleRowsNeverGap guards the rule that only a section's first and last
// rows may be partial: when scrolled into the middle of an unaligned section,
// every visible row must be full (no leading gap on the top row).
func TestHexMiddleRowsNeverGap(t *testing.T) {
	data := make([]byte, 0x200)
	for i := range data {
		data[i] = byte(i + 1) // non-zero so a blank slot is unambiguous
	}
	m := &Model{
		mode:        modeHex,
		theme:       DefaultTheme(),
		file:        &binfile.File{},
		layoutState: layoutState{width: 120, height: 12},
		byteViews:   hexraw.State{HexImg: binfile.NewImage(data, []binfile.Region{{Addr: 0x1029052b8, Size: uint64(len(data)), Off: 0, Name: "__objc_data"}})},
	}
	for range 40 { // scroll well past the section start
		m.byteViews.Update(m.viewContextPtr(), m, hexraw.Hex, "down")
	}
	lines := strings.Split(ansi.Strip(renderHexTest(m)), "\n")
	var body []string
	for _, ln := range lines {
		if strings.Contains(ln, "0x0000000") {
			body = append(body, ln)
		}
	}
	if len(body) < 3 {
		t.Fatalf("expected several body rows, got %d", len(body))
	}
	for i, ln := range body {
		// Hex column begins after " 0x"+addr digits+"  "; check its first slot.
		addrW := m.file.AddrHexWidth()
		first := ln[testHexBodyStart(addrW) : testHexBodyStart(addrW)+2]
		if first == "  " {
			t.Fatalf("row %d has a leading gap (mid-section row must be full):\n%s", i, ln)
		}
	}
}

func TestHexAndRawRowsSplitAtUnalignedSectionStart(t *testing.T) {
	raw := make([]byte, 0x40)
	copy(raw[0x14:], []byte{'e', 'd', 0, 'C', 'G', 'C', 'o', 'l', 'o', 'r'})
	sections := []binfile.Section{
		{Name: "prev", Addr: 0x10203cb04, Size: 0x13, Offset: 0x14, FileSize: 3, Alloc: true},
		{Name: "__objc_methname", Addr: 0x10203cb17, Size: 0x20, Offset: 0x17, FileSize: 0x20, Alloc: true},
	}
	rawModel := &Model{
		theme:       DefaultTheme(),
		file:        &binfile.File{Sections: sections},
		layoutState: layoutState{width: 120, height: 10},
		byteViews:   hexraw.State{RawData: raw, RawCur: 0x17, RawTop: 0x14},
	}
	assertSectionBytesBelowSeparator(t, ansi.Strip(renderRawTest(rawModel)), "__objc_methname", "43  47 43", "0x0000000000000010")

	hexData := make([]byte, 0x30)
	copy(hexData[0x10:], []byte{'e', 'd', 0, 'C', 'G', 'C', 'o', 'l', 'o', 'r'})
	hexModel := &Model{
		theme:            DefaultTheme(),
		file:             &binfile.File{Sections: sections},
		layoutState:      layoutState{width: 120, height: 10},
		interactionState: interactionState{viewportDetached: true},
		byteViews: hexraw.State{HexImg: binfile.NewImage(hexData, []binfile.Region{
			{Addr: 0x10203cb04, Size: 0x13, Off: 0, Name: "prev"},
			{Addr: 0x10203cb17, Size: 0x20, Off: 0x13, Name: "__objc_methname"},
		}), HexCur: 0x13, HexTop: 0x10},
	}
	assertSectionBytesBelowSeparator(t, ansi.Strip(renderHexTest(hexModel)), "__objc_methname", "43  47 43", "0x000000010203cb10")
}

func TestOpeningUnalignedSectionPinsSeparatorAtTop(t *testing.T) {
	section := binfile.Section{Name: "__objc_methname", Addr: 0x10203cb17, Size: 0x20, Offset: 0x17, FileSize: 0x20, Alloc: true}
	hexModel := &Model{
		theme:            DefaultTheme(),
		file:             &binfile.File{Sections: []binfile.Section{section}},
		layoutState:      layoutState{width: 120, height: 8},
		interactionState: interactionState{viewportDetached: true},
		byteViews:        hexraw.State{HexRenderedTop: 99, HexImg: binfile.NewImage([]byte("CGColor.CGContext._device"), []binfile.Region{{Addr: section.Addr, Size: section.FileSize, Off: 0, Name: section.Name}})},
	}
	hexModel.openHexAt(section.Addr)
	if hexModel.viewportDetached {
		t.Fatal("openHexAt did not reattach viewport")
	}
	if hexModel.byteViews.HexTop != hexModel.byteViews.HexCur {
		t.Fatalf("hexTop = %d, want section cursor %d", hexModel.byteViews.HexTop, hexModel.byteViews.HexCur)
	}
	assertSeparatorDirectlyUnderBanner(t, ansi.Strip(renderHexTest(hexModel)), section.Name)

	rawModel := &Model{
		theme:            DefaultTheme(),
		file:             &binfile.File{Sections: []binfile.Section{section}},
		layoutState:      layoutState{width: 120, height: 8},
		interactionState: interactionState{viewportDetached: true},
		byteViews:        hexraw.State{RawRenderedTop: 99, RawData: []byte("abcdefghijklmnopqrstuvwxyzzzzzzzzzzzzzzzzzzzzzz")},
	}
	rawModel.openRawAt(section.Offset)
	if rawModel.viewportDetached {
		t.Fatal("openRawAt did not reattach viewport")
	}
	if rawModel.byteViews.RawTop != rawModel.byteViews.RawCur {
		t.Fatalf("rawTop = %d, want section cursor %d", rawModel.byteViews.RawTop, rawModel.byteViews.RawCur)
	}
	assertSeparatorDirectlyUnderBanner(t, ansi.Strip(renderRawTest(rawModel)), section.Name)
}

func TestCurrentUnalignedSectionSnapsPastPreviousSectionGap(t *testing.T) {
	sections := []binfile.Section{
		{Name: "prev", Addr: 0x102043bb0, Size: 0x3e, Offset: 0x10, FileSize: 0x3e, Alloc: true},
		{Name: "__objc_classname", Addr: 0x102043bee, Size: 0x80, Offset: 0x4e, FileSize: 0x80, Alloc: true},
	}
	hexData := make([]byte, 0xd0)
	copy(hexData[0x4e:], []byte("VibrantLayer.MetalBuffer.FramebufferDescriptor"))
	hexModel := &Model{
		mode:        modeHex,
		theme:       DefaultTheme(),
		file:        &binfile.File{Sections: sections},
		layoutState: layoutState{width: 120, height: 10},
		byteViews: hexraw.State{HexImg: binfile.NewImage(hexData, []binfile.Region{
			{Addr: sections[0].Addr, Size: sections[0].FileSize, Off: 0, Name: sections[0].Name},
			{Addr: sections[1].Addr, Size: sections[1].FileSize, Off: 0x4e, Name: sections[1].Name},
		}), HexCur: 0x7f, HexTop: 0},
	}
	assertSeparatorDirectlyUnderBanner(t, ansi.Strip(renderHexTest(hexModel)), sections[1].Name)
	if got, want := hexModel.byteViews.HexTop, 0x4e; got != want {
		t.Fatalf("hexTop = 0x%x, want current section start 0x%x", got, want)
	}
	model, _ := hexModel.handleMouse(tea.MouseWheelMsg(tea.Mouse{Button: tea.MouseWheelUp, X: 10, Y: 4}))
	hexModel = model.(*Model)
	if !hexModel.viewportDetached {
		t.Fatal("hex wheel up did not detach viewport")
	}
	if got, limit := hexModel.byteViews.HexTop, 0x4e; got >= limit {
		t.Fatalf("hex wheel up top = 0x%x, want before section start 0x%x", got, limit)
	}

	rawData := make([]byte, 0xd0)
	copy(rawData[0x4e:], []byte("VibrantLayer.MetalBuffer.FramebufferDescriptor"))
	rawModel := &Model{
		mode:        modeRaw,
		theme:       DefaultTheme(),
		file:        &binfile.File{Sections: sections},
		layoutState: layoutState{width: 120, height: 10},
		byteViews:   hexraw.State{RawData: rawData, RawCur: 0x7f, RawTop: 0x10},
	}
	assertSeparatorDirectlyUnderBanner(t, ansi.Strip(renderRawTest(rawModel)), sections[1].Name)
	if got, want := rawModel.byteViews.RawTop, 0x4e; got != want {
		t.Fatalf("rawTop = 0x%x, want current section start 0x%x", got, want)
	}
	model, _ = rawModel.handleMouse(tea.MouseWheelMsg(tea.Mouse{Button: tea.MouseWheelUp, X: 10, Y: 4}))
	rawModel = model.(*Model)
	if !rawModel.viewportDetached {
		t.Fatal("raw wheel up did not detach viewport")
	}
	if got, limit := rawModel.byteViews.RawTop, 0x4e; got >= limit {
		t.Fatalf("raw wheel up top = 0x%x, want before section start 0x%x", got, limit)
	}
}

func TestPinnedUnalignedSectionOverridesStaleDetachedTop(t *testing.T) {
	sections := []binfile.Section{
		{Name: "prev", Addr: 0x10203cab0, Size: 0x67, Offset: 0, FileSize: 0x67, Alloc: true},
		{Name: "__objc_methname", Addr: 0x10203cb17, Size: 0x80, Offset: 0x67, FileSize: 0x80, Alloc: true},
	}
	hexData := make([]byte, 0x100)
	copy(hexData[0x67:], []byte("CGColor.CGContext._device"))
	m := &Model{
		mode:             modeHex,
		theme:            DefaultTheme(),
		file:             &binfile.File{Sections: sections},
		layoutState:      layoutState{width: 120, height: 10},
		interactionState: interactionState{viewportDetached: true},
		byteViews: hexraw.State{HexRenderedTop: 0, HexImg: binfile.NewImage(hexData, []binfile.Region{
			{Addr: sections[0].Addr, Size: sections[0].FileSize, Off: 0, Name: sections[0].Name},
			{Addr: sections[1].Addr, Size: sections[1].FileSize, Off: 0x67, Name: sections[1].Name},
		}), HexCur: 0x67, HexTop: 0, HexPinnedTop: 0x67, HexPinned: true},
	}
	assertSeparatorDirectlyUnderBanner(t, ansi.Strip(renderHexTest(m)), sections[1].Name)
	if got, want := m.byteViews.HexTop, 0x67; got != want {
		t.Fatalf("hexTop = 0x%x, want pinned section start 0x%x", got, want)
	}
	m.wheelSuppressUntil = time.Time{}
	model, _ := m.handleMouse(tea.MouseWheelMsg(tea.Mouse{Button: tea.MouseWheelUp, X: 10, Y: 4}))
	m = model.(*Model)
	if m.byteViews.HexPinned {
		t.Fatal("wheel up did not clear pinned section")
	}
	if got, limit := m.byteViews.HexTop, 0x67; got >= limit {
		t.Fatalf("wheel up top = 0x%x, want before pinned section 0x%x", got, limit)
	}
}

func TestHexSearchReattachesViewportAtUnalignedSectionStart(t *testing.T) {
	sections := []binfile.Section{
		{Name: "prev", Addr: 0x102043bb0, Size: 0x3e, Offset: 0x10, FileSize: 0x3e, Alloc: true},
		{Name: "__objc_classname", Addr: 0x102043bee, Size: 0x80, Offset: 0x4e, FileSize: 0x80, Alloc: true},
	}
	hexData := make([]byte, 0xd0)
	copy(hexData[0x4e:], []byte("VibrantLayer.MetalBuffer.FramebufferDescriptor"))
	m := &Model{
		mode:             modeHex,
		theme:            DefaultTheme(),
		file:             &binfile.File{Sections: sections},
		layoutState:      layoutState{width: 120, height: 10},
		interactionState: interactionState{viewportDetached: true},
		byteViews: hexraw.State{HexImg: binfile.NewImage(hexData, []binfile.Region{
			{Addr: sections[0].Addr, Size: sections[0].FileSize, Off: 0, Name: sections[0].Name},
			{Addr: sections[1].Addr, Size: sections[1].FileSize, Off: 0x4e, Name: sections[1].Name},
		}), HexCur: 0, HexTop: 0},
	}
	m.search.Init(textinput.New())
	m.search.SetOptions(searchmodal.Options{Mode: searchutil.ModeText, Forward: true})
	m.search.Open()
	m.search.HandleInput(tea.PasteMsg{Content: "Vibrant"})
	model, _ := m.updateSearchInput(keyPress("enter"), "enter")
	m = model.(*Model)
	if m.viewportDetached {
		t.Fatal("search did not reattach viewport")
	}
	if got, want := m.byteViews.HexCur, 0x4e; got != want {
		t.Fatalf("hex search cursor = 0x%x, want 0x%x", got, want)
	}
	assertSeparatorDirectlyUnderBanner(t, ansi.Strip(renderHexTest(m)), sections[1].Name)
}

func TestGhosttyObjcMethnameOpenPinsSeparatorAtTop(t *testing.T) {
	const path = "/Users/psimonenko/Prog/pr/sources/ghostty/macos/build/Debug/Ghostty.app/Contents/MacOS/ghostty"
	if _, err := os.Stat(path); err != nil {
		t.Skip("ghostty debug binary unavailable")
	}
	f, err := binfile.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	m, err := New(f)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m.width, m.height = 120, 20
	m.openHexAt(0x10203cb17)
	if m.byteViews.HexTop != m.byteViews.HexCur {
		t.Fatalf("hexTop = %d addr 0x%x, hexCur = %d addr 0x%x", m.byteViews.HexTop, m.byteViews.HexImg.AddrAt(m.byteViews.HexTop), m.byteViews.HexCur, m.byteViews.HexImg.AddrAt(m.byteViews.HexCur))
	}
	assertSeparatorDirectlyUnderBanner(t, ansi.Strip(renderHexTest(m)), "__objc_methname")
}

func TestGhosttyObjcMethnameSectionKeyPinsSeparatorAtTop(t *testing.T) {
	const path = "/Users/psimonenko/Prog/pr/sources/ghostty/macos/build/Debug/Ghostty.app/Contents/MacOS/ghostty"
	if _, err := os.Stat(path); err != nil {
		t.Skip("ghostty debug binary unavailable")
	}
	f, err := binfile.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	m, err := New(f)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m.width, m.height = 120, 20
	// ] jumps to the next section start and pins the separator at the top.
	m.openHexAt(0x10203cae0)
	m.byteViews.Update(m.viewContextPtr(), m, hexraw.Hex, "]")
	addr := m.byteViews.HexImg.AddrAt(m.byteViews.HexCur)
	if addr != 0x10203cb17 {
		t.Fatalf("] landed at 0x%x, want 0x10203cb17", addr)
	}
	if m.byteViews.HexTop != m.byteViews.HexCur {
		t.Fatalf("hexTop = %d addr 0x%x, hexCur = %d addr 0x%x", m.byteViews.HexTop, m.byteViews.HexImg.AddrAt(m.byteViews.HexTop), m.byteViews.HexCur, m.byteViews.HexImg.AddrAt(m.byteViews.HexCur))
	}
	assertSeparatorDirectlyUnderBanner(t, ansi.Strip(renderHexTest(m)), "__objc_methname")

	// [ jumps back to the previous section, again pinning its separator on top.
	m.byteViews.Update(m.viewContextPtr(), m, hexraw.Hex, "[")
	if m.byteViews.HexTop != m.byteViews.HexCur {
		t.Fatalf("after [ hexTop = %d, hexCur = %d", m.byteViews.HexTop, m.byteViews.HexCur)
	}
	if got := m.byteViews.HexImg.AddrAt(m.byteViews.HexCur); got >= 0x10203cb17 {
		t.Fatalf("[ landed at 0x%x, want a section before 0x10203cb17", got)
	}
}

func assertSeparatorDirectlyUnderBanner(t *testing.T, out, section string) {
	t.Helper()
	lines := strings.Split(out, "\n")
	if len(lines) < 2 {
		t.Fatalf("rendered output has too few lines:\n%s", out)
	}
	if !strings.Contains(lines[1], section) || !strings.Contains(lines[1], "===") {
		t.Fatalf("first content row is not %q separator:\n%s", section, out)
	}
}

func assertSectionBytesBelowSeparator(t *testing.T, out, section, bytes, lineAddr string) {
	t.Helper()
	lines := strings.Split(out, "\n")
	sepLine := -1
	byteLine := -1
	for i, line := range lines {
		if strings.Contains(line, section) && strings.Contains(line, "===") && sepLine < 0 {
			sepLine = i
		}
		if strings.Contains(line, bytes) && byteLine < 0 {
			byteLine = i
		}
	}
	if sepLine < 0 {
		t.Fatalf("section separator %q not found in:\n%s", section, out)
	}
	if byteLine <= sepLine {
		t.Fatalf("bytes %q line = %d, separator line = %d; output:\n%s", bytes, byteLine, sepLine, out)
	}
	line := lines[byteLine]
	if !strings.Contains(line, lineAddr) {
		t.Fatalf("post-separator line %q does not contain aligned address %q", line, lineAddr)
	}
	if idx := strings.Index(line, bytes[:2]); idx <= testHexBodyStart(16) {
		t.Fatalf("post-separator bytes are not offset on line: %q", line)
	}
}

func TestPadBodyRowsClampsAndPads(t *testing.T) {
	got := layout.PadBodyRows([]string{"abc", "abcdef"}, 4, 3)
	lines := strings.Split(got, "\n")
	if len(lines) != 3 {
		t.Fatalf("padded line count = %d, want 3", len(lines))
	}
	for i, line := range lines {
		if w := lipgloss.Width(ansi.Strip(line)); w != 4 {
			t.Fatalf("line %d width = %d, want 4 (%q)", i, w, line)
		}
	}
}

func TestTruncateMiddleKeepsEnds(t *testing.T) {
	got := layout.TruncateMiddle("/very/long/source/path/main.go", 16)
	if got == "/very/long/source/path/main.go" || lipgloss.Width(got) > 16 {
		t.Fatalf("layout.TruncateMiddle returned %q", got)
	}
	if got[:1] != "/" || got[len(got)-5:] != "in.go" {
		t.Fatalf("layout.TruncateMiddle did not keep useful ends: %q", got)
	}
}

func TestRenderLineRowsActuallyWraps(t *testing.T) {
	line := "0123456789 abcdefghij klmnopqrst"
	rows := layout.RenderLineRowsIndented(line, 12, true, 0)
	if len(rows) < 3 {
		t.Fatalf("wrapped rows = %d, want at least 3: %q", len(rows), rows)
	}
	for _, row := range rows {
		if w := lipgloss.Width(ansi.Strip(row)); w > 12 {
			t.Fatalf("row width = %d, want <= 12: %q", w, row)
		}
	}
	if got := layout.RenderLineRowsIndented(line, 12, false, 0); len(got) != 1 {
		t.Fatalf("non-wrapped rows = %d, want 1", len(got))
	}
}

func TestRenderLineRowsIndentedContinuation(t *testing.T) {
	rows := layout.RenderLineRowsIndented("addr type very-long-content-that-wraps", 18, true, 6)
	if len(rows) < 2 {
		t.Fatalf("rows = %q, want wrapped continuation", rows)
	}
	for i, row := range rows[1:] {
		plain := ansi.Strip(row)
		if len(plain) < 6 || plain[:6] != "      " {
			t.Fatalf("continuation row %d not indented: %q", i+1, plain)
		}
		if w := lipgloss.Width(plain); w > 18 {
			t.Fatalf("continuation row width = %d, want <= 18: %q", w, plain)
		}
	}
}

func TestSearchPopupClickTogglesSwitches(t *testing.T) {
	m := &Model{
		theme:       DefaultTheme(),
		layoutState: layoutState{width: 100, height: 30},
	}
	m.search.Init(textinput.New())
	m.search.Open()
	modal := m.search.Render(m.modalContext(), m)
	left := (m.width - lipgloss.Width(modal)) / 2
	top := (m.height - lipgloss.Height(modal)) / 2

	// The switch strip lives at content row searchSwitchLine, inside the modal's
	// border (1) + padding (1,2). Compute the centre x of each segment from the
	// shared searchSwitches() layout so the test can't drift from the renderer.
	rowY := top + 2 + searchmodal.SwitchLine
	sepW := lipgloss.Width(searchmodal.SwitchSep)
	sw := m.search.Switches()
	center := map[string]int{}
	pos := 1 // the switch strip is indented one column
	for _, s := range sw {
		w := lipgloss.Width(s.Label())
		center[s.Name] = left + 3 + pos + w/2
		pos += w + sepW
	}

	m.handleSearchPopupClick(center["mode"], rowY)
	if m.search.Mode() != searchutil.ModeText {
		t.Fatalf("mode click set mode = %s, want text", m.search.Mode())
	}
	m.handleSearchPopupClick(center["case"], rowY)
	if !m.search.CaseSensitive() {
		t.Fatal("case click did not toggle case sensitivity")
	}
	m.handleSearchPopupClick(center["dir"], rowY)
	if m.search.Forward() {
		t.Fatal("direction click did not toggle direction")
	}
	m.handleSearchPopupClick(center["origin"], rowY)
	if m.search.FromCursor() {
		t.Fatal("origin click did not toggle origin")
	}
}

func TestWrappedSymbolsKeepAddressGrayOnContinuation(t *testing.T) {
	m := &Model{
		theme:            DefaultTheme(),
		layoutState:      layoutState{width: 42},
		interactionState: interactionState{wrap: true},
		file: &binfile.File{
			Symbols: []binfile.Symbol{{
				Name: strings.Repeat("very_long_symbol_name_", 5), Addr: 0x1000, Kind: binfile.SymFunc,
			}},
		},
	}
	m.symbols.Filtered = []int{0}
	m.symbols.Recompute(m.viewContext())
	rows := m.symbols.RowLines(m.viewContext(), 0)
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
		theme:            DefaultTheme(),
		mode:             modeSymbols,
		layoutState:      layoutState{width: 42, height: 120},
		interactionState: interactionState{wrap: true},
		file: &binfile.File{Symbols: []binfile.Symbol{
			{Name: strings.Repeat("very_long_symbol_name_", 5), Addr: 0x1000, Kind: binfile.SymFunc},
			{Name: "second", Addr: 0x2000, Kind: binfile.SymObject},
		}},
	}
	m.symbols.Filtered = []int{0, 1}
	m.symbols.Recompute(m.viewContext())
	firstRows := m.symbols.RowHeightFn(m.viewContext())(0)
	if firstRows < 2 {
		t.Fatalf("first symbol did not wrap")
	}
	m.handleClick(1, 1+2+firstRows-1)
	if m.symbols.Cur != 0 {
		t.Fatalf("click on first continuation selected %d, want 0", m.symbols.Cur)
	}
	m.handleClick(1, 1+2+firstRows)
	if m.symbols.Cur != 1 {
		t.Fatalf("click after wrapped first selected %d, want 1", m.symbols.Cur)
	}
}

func TestVisualItemAtRowUsesWrappedHeights(t *testing.T) {
	heights := func(i int) int {
		if i == 0 {
			return 3
		}
		return 1
	}
	if got, ok := layout.VisualItemAtRow(0, 3, 2, heights); !ok || got != 0 {
		t.Fatalf("row 2 maps to %d,%v; want first wrapped item", got, ok)
	}
	if got, ok := layout.VisualItemAtRow(0, 3, 3, heights); !ok || got != 1 {
		t.Fatalf("row 3 maps to %d,%v; want second item", got, ok)
	}
}

func TestRawClickSkipsSectionSplitRows(t *testing.T) {
	m := &Model{layoutState: layoutState{width: 100, height: 10}, file: &binfile.File{Sections: []binfile.Section{{Name: ".text", Offset: 0, FileSize: 32}}}}
	data := make([]byte, 64)
	m.byteViews = hexraw.State{RawData: data, RawCur: 7}
	m.byteViews.Click(m.viewContextPtr(), hexraw.Raw, testHexBodyStart(16), 1)
	if cur := m.byteViews.RawCur; cur != 7 {
		t.Fatalf("click on split row changed cursor to %d", cur)
	}
	m.byteViews.Click(m.viewContextPtr(), hexraw.Raw, testHexBodyStart(16), 2)
	if cur := m.byteViews.RawCur; cur != 0 {
		t.Fatalf("click on first data row selected %d, want 0", cur)
	}
}

func TestDisasmAnnotationWrapsSeparatelyAndAddressLinks(t *testing.T) {
	m := &Model{
		theme:            DefaultTheme(),
		layoutState:      layoutState{width: 64},
		interactionState: interactionState{wrap: true},
		file: &binfile.File{
			Sections: []binfile.Section{{
				Name: strings.Repeat("very_long_section_name_", 5), Addr: 0x2000, Size: 8, Alloc: true,
			}},
		},
	}
	inst := disasm.Inst{Addr: 0x1000, Text: "call 0x2000", Class: disasm.ClassCall, Bytes: []byte{0xe8}}
	rows := m.disasmInstRows(inst, 64, false, nil)
	if len(rows) < 2 {
		t.Fatalf("annotation did not wrap into separate rows: %q", rows)
	}
	plain := ansi.Strip(rows[0])
	if strings.Contains(plain, "#") {
		t.Fatalf("annotation was rendered as an assembly comment: %q", plain)
	}
	allPlain := strings.ReplaceAll(strings.Join(stripANSILines(rows), ""), " ", "")
	if !strings.Contains(plain, "call 0x2000") || !strings.Contains(allPlain, "very_long_section_name_") {
		t.Fatalf("assembly or separate annotation missing: %q", rows)
	}
	if !strings.Contains(rows[0], ";4") {
		t.Fatalf("followable address was not underlined: %q", rows[0])
	}
}

func stripANSILines(lines []string) []string {
	out := make([]string, len(lines))
	for i, line := range lines {
		out[i] = ansi.Strip(line)
	}
	return out
}
