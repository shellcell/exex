package ui

import (
	"testing"

	"github.com/rabarbra/exex/internal/binfile"
)

// TestKeyCoalescing verifies a held navigation key stays cheap: the first press
// applies immediately and starts the tick, the repeats only accumulate (reusing
// the last frame), and the accumulated moves are applied together on the tick.
func TestKeyCoalescing(t *testing.T) {
	m := &Model{
		theme:        DefaultTheme(),
		file:         &binfile.File{},
		mode:         modeStrings,
		layoutState:  layoutState{width: 80, height: 24},
		stringsState: stringsState{stringsList: make([]binfile.StringEntry, 5000)},
	}
	m.stringsFilter = newPromptInput("", "/ ")
	m.recomputeStrings()

	m.enqueueNavKey("down")
	if !m.keyTicking {
		t.Fatal("first nav key should start the coalescing tick")
	}
	first := m.stringsCur
	if first == 0 {
		t.Fatal("first press should move the cursor immediately")
	}

	for range 200 {
		m.viewDirty = true // Update sets this before every message
		m.enqueueNavKey("down")
		if m.viewDirty {
			t.Fatal("a coalesced repeat must leave the frame clean so View() is skipped")
		}
	}
	if m.stringsCur != first {
		t.Fatalf("repeats moved the cursor mid-flood (%d → %d); they should only accumulate", first, m.stringsCur)
	}
	if m.pendingKeyN == 0 {
		t.Fatal("repeats should have accumulated a pending count")
	}

	m.handleKeyTick()
	if m.stringsCur == first {
		t.Fatal("tick should apply the accumulated moves")
	}
	if m.pendingKeyN != 0 {
		t.Fatalf("tick should drain the pending count, got %d", m.pendingKeyN)
	}

	m.handleKeyTick()
	if m.keyTicking {
		t.Fatal("an idle tick should stop the chain")
	}
}
