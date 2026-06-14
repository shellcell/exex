package ui

import (
	"os"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/rabarbra/exex/internal/binfile"
)

// TestRenderAllViews drives the model through every view (and some navigation)
// against a real binary, asserting each frame renders without panicking and
// produces output. It's a smoke test for the format-neutral rewrite and the
// new full-file hex / disasm / raw views.
func TestRenderAllViews(t *testing.T) {
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

	var model tea.Model = m

	// pump applies a message and, if it kicked off the background disasm decode,
	// completes that decode synchronously (other commands — e.g. the textinput
	// cursor-blink tick — are discarded so the test stays fast).
	pump := func(msg tea.Msg) {
		t.Helper()
		model, _ = model.Update(msg)
		if mm, ok := model.(*Model); ok && mm.disasmDecoding {
			model, _ = model.Update(disasmReadyMsg{insts: mm.decodeExecImage()})
		}
	}

	pump(tea.WindowSizeMsg{Width: 120, Height: 40})

	send := func(s string) {
		t.Helper()
		var msg tea.KeyMsg
		switch s {
		case "down", "up", "pgdown", "pgup", "end", "home", "enter", "right", "left":
			msg = tea.KeyMsg{Type: keyType(s)}
		default:
			msg = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
		}
		pump(msg)
		if strings.TrimSpace(model.View()) == "" {
			t.Fatalf("empty render after key %q", s)
		}
	}

	// Visit each view, then exercise scrolling/navigation in the byte and
	// disasm views where the new full-file logic lives.
	for _, view := range []string{"1", "2", "3", "4", "5", "6", "7", "8"} {
		send(view)
	}
	// Sections: move and open whatever is selected.
	send("2")
	send("down")
	send("enter")
	// Hex view: scroll across the mapped image and seek non-zero bytes.
	send("5")
	for i := 0; i < 5; i++ {
		send("pgdown")
	}
	send("end")
	send("home")
	send("]")
	send("[")
	// Raw view: scroll across the whole file and seek non-zero bytes.
	send("7")
	send("end")
	send("pgup")
	send("]")
	send("[")
	// Disasm: scroll, step symbols, follow, and walk history.
	send("4")
	send("pgdown")
	send("]")
	send("[")
	send("enter")
	send("left")
	send("end")
	send("home")

	// Mouse: wheel scroll and a left click in a few views.
	mouse := func(b tea.MouseButton, action tea.MouseAction, x, y int) {
		t.Helper()
		pump(tea.MouseMsg{Button: b, Action: action, X: x, Y: y})
		if strings.TrimSpace(model.View()) == "" {
			t.Fatalf("empty render after mouse event")
		}
	}
	for _, v := range []string{"2", "3", "4", "5", "7"} {
		send(v)
		mouse(tea.MouseButtonWheelDown, tea.MouseActionPress, 10, 10)
		mouse(tea.MouseButtonWheelUp, tea.MouseActionPress, 10, 10)
		mouse(tea.MouseButtonLeft, tea.MouseActionPress, 20, 6)
	}

	// Clicking along the tab strip (y == 0) should switch views.
	for x := 16; x < 90; x += 6 {
		mouse(tea.MouseButtonLeft, tea.MouseActionPress, x, 0)
	}

	// Strings view: scroll and jump.
	send("8")
	send("down")
	send("enter")

	// Disasm double-click: two quick left clicks on the same row should follow.
	send("4")
	mouse(tea.MouseButtonLeft, tea.MouseActionPress, 30, 5)
	mouse(tea.MouseButtonLeft, tea.MouseActionPress, 30, 5)

	// Goto modal: type, watch the live result list, select and jump.
	send("g")
	send("m")
	send("a")
	send("down")
	send("enter")

	// Search in the hex view, then repeat forward/backward.
	send("5")
	send("/")
	send("0")
	send("0")
	send("enter")
	send("n")
	send("N")

	// Search in disasm by mnemonic text.
	send("4")
	send("/")
	send("m")
	send("enter")
	send("n")

	// Sections filter.
	send("2")
	send("/")
	send("t")
	send("esc")
	send("down")

	// macOS-friendly begin/end via ctrl+a / ctrl+e.
	model, _ = model.Update(tea.KeyMsg{Type: tea.KeyCtrlE})
	model, _ = model.Update(tea.KeyMsg{Type: tea.KeyCtrlA})

	// Strings search.
	send("8")
	send("/")
	send("l")
	send("s")
	send("enter")
	send("n")

	// Info view: Enter follows the entry point into disasm.
	send("1")
	send("enter")
	if strings.TrimSpace(model.View()) == "" {
		t.Fatal("empty render at end")
	}
}

func keyType(s string) tea.KeyType {
	switch s {
	case "down":
		return tea.KeyDown
	case "up":
		return tea.KeyUp
	case "left":
		return tea.KeyLeft
	case "right":
		return tea.KeyRight
	case "pgdown":
		return tea.KeyPgDown
	case "pgup":
		return tea.KeyPgUp
	case "home":
		return tea.KeyHome
	case "end":
		return tea.KeyEnd
	case "enter":
		return tea.KeyEnter
	}
	return tea.KeyRunes
}

func firstExisting(paths ...string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
