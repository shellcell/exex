package ui

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/ui/views/sections"
	"github.com/rabarbra/exex/internal/ui/views/strs"
	"github.com/rabarbra/exex/internal/ui/views/symbols"
)

func wheelDownModel() *Model {
	m := &Model{
		theme:       DefaultTheme(),
		file:        &binfile.File{},
		mode:        modeStrings,
		layoutState: layoutState{width: 80, height: 24},
	}
	m.strs.List = make([]binfile.StringEntry, 5000)
	m.strs.Filter = newPromptInput("", "/ ")
	m.strs.Recompute(m.viewContext()) // empty filter → all rows visible
	return m
}

func wheelDown(m *Model) {
	m.handleMouse(tea.MouseWheelMsg(tea.Mouse{Button: tea.MouseWheelDown, X: 10, Y: 5}))
}

// TestWheelCoalescing verifies a flood of wheel events stays cheap: the first
// applies immediately and starts the coalescing tick, the rest only accumulate,
// and the accumulated delta is applied on the next tick.
func TestWheelCoalescing(t *testing.T) {
	m := wheelDownModel()

	wheelDown(m) // first event applies immediately + starts ticking
	if !m.wheelTicking {
		t.Fatal("first wheel event should start the coalescing tick")
	}
	firstTop := m.strs.Top
	if firstTop == 0 {
		t.Fatal("first wheel event should have scrolled")
	}

	for range 200 { // a burst that must NOT each run a scroll
		m.viewDirty = true // Update sets this before every message
		wheelDown(m)
		if m.viewDirty {
			t.Fatal("a coalesced wheel event must leave the frame clean so View() is skipped")
		}
	}
	if m.strs.Top != firstTop {
		t.Fatalf("burst scrolled mid-flood (top %d → %d); events should only accumulate", firstTop, m.strs.Top)
	}
	if m.pendingWheel == 0 {
		t.Fatal("burst should have accumulated pending wheel delta")
	}

	m.handleWheelTick() // applies the accumulated delta in one shot
	if m.strs.Top == firstTop {
		t.Fatal("tick should have applied the accumulated scroll")
	}
	if m.pendingWheel != 0 {
		t.Fatalf("tick should have drained pending wheel, got %d", m.pendingWheel)
	}

	// A click cancels in-flight momentum, and the next idle tick stops ticking.
	wheelDown(m)
	m.handleMouse(tea.MouseClickMsg(tea.Mouse{Button: tea.MouseLeft, X: 10, Y: 5}))
	if m.pendingWheel != 0 {
		t.Fatal("click should cancel pending wheel momentum")
	}
	m.handleWheelTick()
	if m.wheelTicking {
		t.Fatal("ticker should stop once the burst has drained")
	}
}

func clickBodyRow(m *Model, x, bodyRow int) {
	m.handleMouse(tea.MouseClickMsg(tea.Mouse{Button: tea.MouseLeft, X: x, Y: bodyRow + 1}))
}

func TestSectionsHeaderClickSorts(t *testing.T) {
	f := &binfile.File{Format: binfile.FormatELF, Sections: []binfile.Section{
		{Name: "zeta", Addr: 0x3000, Size: 10},
		{Name: "alpha", Addr: 0x1000, Size: 50},
		{Name: "mid", Addr: 0x2000, Size: 30},
	}}
	m := newTestModel(t, f)
	m.setMode(modeSections)
	m.sections.Recompute()

	clickBodyRow(m, 7, 1) // Name header.
	if m.sections.Sort != sections.SortName {
		t.Fatalf("header click sort = %v, want name", m.sections.Sort)
	}
	if got := m.sections.Sections[m.sections.Filtered[0]].Name; got != "alpha" {
		t.Fatalf("name sort first = %q, want alpha", got)
	}

	clickBodyRow(m, 7, 1)
	if !m.sections.SortDesc {
		t.Fatal("second header click did not reverse sections sort")
	}
	if got := m.sections.Sections[m.sections.Filtered[0]].Name; got != "zeta" {
		t.Fatalf("name desc first = %q, want zeta", got)
	}
	if header := ansi.Strip(m.sections.Render(m.viewContext(), m)); !strings.Contains(header, "Name ") || !strings.Contains(header, "▽") || strings.Contains(header, "Name▽") {
		t.Fatalf("section header missing descending marker: %q", header)
	}
}

func TestSymbolsHeaderClickSorts(t *testing.T) {
	f := &binfile.File{Format: binfile.FormatELF, Symbols: []binfile.Symbol{
		{Name: "b", Addr: 0x3000, Size: 50},
		{Name: "a", Addr: 0x1000, Size: 10},
		{Name: "c", Addr: 0x2000, Size: 30},
	}}
	m := newTestModel(t, f)
	m.setMode(modeSymbols)
	m.symbols.Recompute(m.viewContext())

	clickBodyRow(m, 2, 1) // Address header.
	if m.symbols.Sort != symbols.SortAddr {
		t.Fatalf("header click sort = %v, want address", m.symbols.Sort)
	}
	if got := m.file.Symbols[m.symbols.Rows[0].Node.Leaf].Addr; got != 0x1000 {
		t.Fatalf("address sort first = %#x, want 0x1000", got)
	}

	clickBodyRow(m, 2, 1)
	if !m.symbols.SortDesc {
		t.Fatal("second header click did not reverse symbols sort")
	}
	if got := m.file.Symbols[m.symbols.Rows[0].Node.Leaf].Addr; got != 0x3000 {
		t.Fatalf("address desc first = %#x, want 0x3000", got)
	}
	if header := ansi.Strip(m.symbols.Render(m.viewContext(), m)); !strings.Contains(header, "Address ") || !strings.Contains(header, "▽") || strings.Contains(header, "Address▽") {
		t.Fatalf("symbol header missing descending marker: %q", header)
	}
}

func TestStringsHeaderClickSorts(t *testing.T) {
	m := &Model{
		theme:       DefaultTheme(),
		file:        binfile.NewRawFile([]byte("abc")),
		mode:        modeStrings,
		layoutState: layoutState{width: 120, height: 30},
	}
	m.strs.List = []binfile.StringEntry{
		{Offset: 0, Addr: 0x3000, HasAddr: true, Len: 1},
		{Offset: 1, Addr: 0x1000, HasAddr: true, Len: 1},
		{Offset: 2, Addr: 0x2000, HasAddr: true, Len: 1},
	}
	m.strs.Filter = newPromptInput("", "/ ")
	m.strs.Recompute(m.viewContext())

	clickBodyRow(m, 13, 1) // Address header.
	if m.strs.Sort != strs.SortAddr {
		t.Fatalf("header click sort = %v, want address", m.strs.Sort)
	}
	if got := m.strs.List[m.strs.Filtered[0]].Offset; got != 1 {
		t.Fatalf("address sort first offset = %#x, want 1", got)
	}
	if header := ansi.Strip(m.strs.Render(m.viewContext(), m)); !strings.Contains(header, "Address ") || !strings.Contains(header, "△") || strings.Contains(header, "Address△") {
		t.Fatalf("strings header missing ascending marker: %q", header)
	}
}

func TestLibsHeaderClickSorts(t *testing.T) {
	f := &binfile.File{Format: binfile.FormatELF, Info: &binfile.Info{DynamicLibs: []string{"z.so", "a.so"}}}
	m := newTestModel(t, f)
	m.setMode(modeLibs)
	m.libs.Tree = false
	m.libs.BuildRows(m.viewContext())

	first := func() string {
		for _, row := range m.libs.Rows {
			if row.Node.Leaf >= 0 {
				return m.file.Info.DynamicLibs[row.Node.Leaf]
			}
		}
		return ""
	}
	if got := first(); got != "a.so" {
		t.Fatalf("initial first lib = %q, want a.so", got)
	}

	clickBodyRow(m, 2, m.libs.TitleRow(m.viewContext())+1)
	if m.libs.SortDesc {
		t.Fatal("click below libs header sorted instead of selecting a row")
	}

	clickBodyRow(m, 2, m.libs.TitleRow(m.viewContext()))
	if !m.libs.SortDesc {
		t.Fatal("libs header click did not reverse sort")
	}
	if got := first(); got != "z.so" {
		t.Fatalf("descending first lib = %q, want z.so", got)
	}
	if header := ansi.Strip(m.libs.Render(m.viewContext(), m)); !strings.Contains(header, "Needed libraries ") || !strings.Contains(header, "▽") || strings.Contains(header, "Needed libraries▽") {
		t.Fatalf("libs header missing descending marker: %q", header)
	}
}
