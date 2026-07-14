package ui

import (
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/shellcell/exex/internal/binfile"
)

// TestPasteIntoGotoModal guards clipboard paste routing: a tea.PasteMsg (sent by
// bracketed paste, and by the textinput's ctrl+v command) must reach the active
// input and re-filter, rather than being dropped by Model.Update.
func TestPasteIntoGotoModal(t *testing.T) {
	m := &Model{
		theme:       DefaultTheme(),
		layoutState: layoutState{width: 120, height: 30},
		file:        &binfile.File{Symbols: []binfile.Symbol{{Name: "main", Addr: 0x1000}}},
	}
	m.palette.SetInput(newPromptInput("", "→ "))
	m.palette.Open(m)

	upd, _ := m.Update(tea.PasteMsg{Content: "main"})
	got := upd.(*Model)
	if v := got.palette.Value(); v != "main" {
		t.Fatalf("goto value after paste = %q, want %q", v, "main")
	}
	if len(got.palette.Results()) == 0 {
		t.Fatal("paste did not re-run the goto match")
	}
}

func TestPasteIntoSearchModal(t *testing.T) {
	m := &Model{
		theme:       DefaultTheme(),
		layoutState: layoutState{width: 120, height: 30},
		file:        &binfile.File{},
	}
	m.search.Init(newPromptInput("", "/ "))
	m.search.Open()

	upd, _ := m.Update(tea.PasteMsg{Content: "de ad be ef"})
	if v := upd.(*Model).search.Value(); v != "de ad be ef" {
		t.Fatalf("search value after paste = %q, want %q", v, "de ad be ef")
	}
}
