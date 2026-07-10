package ui

import (
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/rabarbra/exex/internal/binfile"
)

// tabInfoX is an x coordinate inside the "Info" tab of the row-0 tab strip, for
// an 80-column overlayModel. Guarded by TestTabInfoXHitsATab so a tab-strip
// layout change can't quietly make the click assertions vacuous.
const tabInfoX = 12

func TestTabInfoXHitsATab(t *testing.T) {
	m := overlayModel()
	md, ok := m.tabHitTest(tabInfoX)
	if !ok {
		t.Fatalf("tabHitTest(%d) missed the tab strip; pick a new tabInfoX", tabInfoX)
	}
	if md == m.mode {
		t.Fatalf("tabHitTest(%d) = %v, the model's current mode; the click assertions would be vacuous", tabInfoX, md)
	}
}

func overlayModel() *Model {
	m := &Model{
		theme:       DefaultTheme(),
		file:        &binfile.File{},
		mode:        modeStrings,
		layoutState: layoutState{width: 80, height: 24},
	}
	m.strs.List = make([]binfile.StringEntry, 5000)
	m.strs.Filter = newPromptInput("", "/ ")
	m.strs.Recompute(m.viewContext())
	return m
}

func click(m *Model, x, y int) {
	m.handleMouse(tea.MouseClickMsg(tea.Mouse{Button: tea.MouseLeft, X: x, Y: y}))
}

func wheel(m *Model, btn tea.MouseButton) {
	m.handleMouse(tea.MouseWheelMsg(tea.Mouse{Button: btn, X: 10, Y: 5}))
}

// TestTextOverlaysCaptureMouse pins the fix for events falling through a
// full-screen overlay: handleMouse consulted only a modalActive() helper that
// omitted helpActive and headerActive, so a wheel scrolled — and a click at row
// 0 switched tabs on — the view hidden behind the overlay.
func TestTextOverlaysCaptureMouse(t *testing.T) {
	for _, tc := range []struct {
		name string
		open func(*Model)
	}{
		{"help", func(m *Model) { m.helpActive = true }},
		{"header", func(m *Model) { m.headerActive = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := overlayModel()
			tc.open(m)
			mode, top := m.mode, m.strs.Top

			// Row 0 is the tab strip: a click there must not switch views.
			// tabInfoX lands inside a tab, so this would switch modes if the
			// event reached the strip.
			click(m, tabInfoX, 0)
			if m.mode != mode {
				t.Errorf("click through overlay switched mode to %v", m.mode)
			}
			// The wheel must page the overlay, not the view behind it.
			wheel(m, tea.MouseWheelDown)
			if m.strs.Top != top {
				t.Errorf("wheel through overlay scrolled the view (top %d → %d)", top, m.strs.Top)
			}
			if m.pendingWheel != 0 {
				t.Errorf("wheel through overlay queued view scroll (pendingWheel = %d)", m.pendingWheel)
			}
		})
	}
}

// TestTextOverlayWheelScrollsOverlay checks the wheel drives the overlay's own
// scroll offset, matching what the arrow keys already did.
func TestTextOverlayWheelScrollsOverlay(t *testing.T) {
	m := overlayModel()
	m.helpActive = true
	wheel(m, tea.MouseWheelDown)
	if m.helpScroll != wheelScrollLines {
		t.Errorf("helpScroll = %d, want %d", m.helpScroll, wheelScrollLines)
	}
	wheel(m, tea.MouseWheelUp)
	if m.helpScroll != 0 {
		t.Errorf("helpScroll = %d after scrolling back, want 0", m.helpScroll)
	}

	m = overlayModel()
	m.headerActive = true
	wheel(m, tea.MouseWheelDown)
	if m.headerScroll != wheelScrollLines {
		t.Errorf("headerScroll = %d, want %d", m.headerScroll, wheelScrollLines)
	}
}

// TestFindQueryPromptCapturesMouse: the free-text search prompt is an overlay
// with no list, so it swallows the mouse rather than letting it reach the view.
func TestFindQueryPromptCapturesMouse(t *testing.T) {
	m := overlayModel()
	m.openFindQuery()
	top := m.strs.Top

	wheel(m, tea.MouseWheelDown)
	if m.strs.Top != top || m.pendingWheel != 0 {
		t.Errorf("wheel through find-query prompt reached the view (top %d → %d, pending %d)", top, m.strs.Top, m.pendingWheel)
	}
	click(m, tabInfoX, 0)
	if m.mode != modeStrings {
		t.Errorf("click through find-query prompt switched mode to %v", m.mode)
	}
}

// TestActiveModalOrdering: render, keys and mouse all resolve the overlay
// through activeModal, so the ordering is defined exactly once. Two flags set at
// once must resolve the same way for every consumer — which is what the old
// per-site chains got wrong (render preferred settings, keys preferred xref).
func TestActiveModalOrdering(t *testing.T) {
	m := overlayModel()
	m.settingsActive = true
	m.xrefActive = true
	if got := m.activeModal(); got != modalXref {
		t.Fatalf("activeModal = %v, want modalXref (higher priority than settings)", got)
	}
	// The renderer must draw the same modal the keyboard drives.
	if got := m.renderActiveModal(); got != m.renderXrefModal() {
		t.Error("renderActiveModal drew a different modal than activeModal selected")
	}

	m = overlayModel()
	if got := m.activeModal(); got != modalNone {
		t.Errorf("activeModal with no overlay = %v, want modalNone", got)
	}
	if got := m.renderActiveModal(); got != "" {
		t.Errorf("renderActiveModal with no overlay = %q, want empty", got)
	}
}
