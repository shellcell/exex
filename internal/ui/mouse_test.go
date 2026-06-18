package ui

import (
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/rabarbra/exex/internal/binfile"
)

func wheelDownModel() *Model {
	return &Model{
		theme:       DefaultTheme(),
		file:        &binfile.File{},
		mode:        modeStrings,
		layoutState: layoutState{width: 80, height: 24},
		stringsState: stringsState{
			stringsList: make([]binfile.StringEntry, 5000),
		},
	}
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
	firstTop := m.stringsTop
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
	if m.stringsTop != firstTop {
		t.Fatalf("burst scrolled mid-flood (top %d → %d); events should only accumulate", firstTop, m.stringsTop)
	}
	if m.pendingWheel == 0 {
		t.Fatal("burst should have accumulated pending wheel delta")
	}

	m.handleWheelTick() // applies the accumulated delta in one shot
	if m.stringsTop == firstTop {
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
