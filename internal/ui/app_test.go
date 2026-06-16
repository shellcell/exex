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
// new full-file hex / raw views and the bounded disasm window.
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
	m.disasmMaxBytes = 16 << 10

	var model tea.Model = m

	// pump applies a message and, if it kicked off the background disasm decode,
	// completes that decode synchronously (other commands — e.g. the textinput
	// cursor-blink tick — are discarded so the test stays fast).
	pump := func(msg tea.Msg) {
		t.Helper()
		model, _ = model.Update(msg)
		if mm, ok := model.(*Model); ok && mm.disasmDecoding {
			addr := mm.disasmPendingAddr
			win, insts := mm.decodeDisasmAt(addr, mm.disasmLeadBytes())
			model, _ = model.Update(disasmReadyMsg{addr: addr, posLo: win.Start, posHi: win.End, insts: insts})
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
	assertDisasmBudget := func() {
		t.Helper()
		mm, ok := model.(*Model)
		if !ok || len(mm.disasmInst) == 0 {
			return
		}
		if got := mm.disasmPosHi - mm.disasmPosLo; got > mm.disasmMaxBytes {
			t.Fatalf("disasm window = %d bytes, budget = %d", got, mm.disasmMaxBytes)
		}
	}

	// Visit each view, then exercise scrolling/navigation in the byte and
	// disasm views where the new full-file logic lives.
	for _, view := range []string{"1", "2", "3", "4", "5", "6", "7", "8", "9"} {
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
	// Disasm: scroll across multiple windows, step symbols, follow, search, and
	// walk history.
	send("4")
	assertDisasmBudget()
	send("pgdown")
	assertDisasmBudget()
	send("]")
	assertDisasmBudget()
	send("[")
	send("enter")
	assertDisasmBudget()
	send("left")
	send("end")
	assertDisasmBudget()
	send("home")
	assertDisasmBudget()

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
	assertDisasmBudget()
	send("n")
	assertDisasmBudget()

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

func TestGotoChromeMainOnChromiumBinary(t *testing.T) {
	const path = "/usr/lib/chromium-browser/chromium-browser"
	if _, err := os.Stat(path); err != nil {
		t.Skip("chromium binary unavailable")
	}
	f, err := binfile.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	m, err := New(f)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m.disasmMaxBytes = 256 << 10

	model := tea.Model(m)
	model, _ = model.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	mm := model.(*Model)

	mm.gotoInput.SetValue("ChromeMain")
	mm.recomputeGoto()
	if len(mm.gotoResults) == 0 {
		t.Fatal("expected goto results for ChromeMain")
	}
	mm.activateGoto()
	if mm.mode != modeDisasm {
		t.Fatalf("mode = %v, want disasm", mm.mode)
	}
	if len(mm.disasmInst) == 0 {
		t.Fatal("expected disasm window after goto")
	}
	addr := mm.disasmInst[mm.disasmCur].Addr
	sym, ok := mm.file.SymbolAt(addr)
	if !ok {
		t.Fatalf("no symbol at current disasm address 0x%x", addr)
	}
	if sym.Display() != "ChromeMain" {
		t.Fatalf("landed on %q at 0x%x, want ChromeMain", sym.Display(), addr)
	}
	if got := mm.disasmPosHi - mm.disasmPosLo; got > mm.disasmMaxBytes {
		t.Fatalf("disasm window = %d bytes, budget = %d", got, mm.disasmMaxBytes)
	}

	mm.jumpDisasmBoundary(false)
	mm.searchQuery = "ChromeMain"
	runModelCmd(t, mm, mm.runSearch(true, true))
	if len(mm.disasmInst) == 0 {
		t.Fatal("expected disasm window after search")
	}
	addr = mm.disasmInst[mm.disasmCur].Addr
	sym, ok = mm.file.SymbolAt(addr)
	if !ok || sym.Display() != "ChromeMain" {
		t.Fatalf("search landed on %q at 0x%x, want ChromeMain", sym.Display(), addr)
	}
}

func TestSearchMovsblOnChromiumBinary(t *testing.T) {
	const path = "/usr/lib/chromium-browser/chromium-browser"
	if _, err := os.Stat(path); err != nil {
		t.Skip("chromium binary unavailable")
	}
	f, err := binfile.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	m, err := New(f)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m.disasmMaxBytes = 256 << 10
	m.width, m.height = 120, 40

	m.jumpDisasmBoundary(false)
	m.searchQuery = "movsbl"
	runModelCmd(t, m, m.runSearch(true, true))
	if len(m.disasmInst) == 0 {
		t.Fatal("expected disasm window after search")
	}
	got := strings.ToLower(m.disasmInst[m.disasmCur].Text)
	if !strings.Contains(got, "movsbl") {
		t.Fatalf("search landed on %q, want movsbl", got)
	}
	if got := m.disasmPosHi - m.disasmPosLo; got > m.disasmMaxBytes {
		t.Fatalf("disasm window = %d bytes, budget = %d", got, m.disasmMaxBytes)
	}
	first := m.disasmInst[m.disasmCur].Addr
	if len(m.searchResults.hits) < 2 {
		t.Fatalf("expected cached movsbl hits, got %d", len(m.searchResults.hits))
	}
	cmd := m.runSearch(true, false)
	if m.searchRunning {
		t.Fatal("expected cached movsbl hit not to start background search")
	}
	runModelCmd(t, m, cmd)
	second := m.disasmInst[m.disasmCur].Addr
	if second <= first {
		t.Fatalf("expected later cached movsbl hit, got 0x%x after 0x%x", second, first)
	}
	for i := 0; i < 6; i++ {
		runModelCmd(t, m, m.runSearch(true, false))
	}
	if len(m.searchResults.hits) < 6 {
		t.Fatalf("expected several cached movsbl hits, got %d", len(m.searchResults.hits))
	}
	for i := 0; i < 4; i++ {
		cmd = m.runSearch(false, false)
		if m.searchRunning {
			t.Fatal("expected backward cached hit not to restart background search")
		}
		runModelCmd(t, m, cmd)
	}
}

func TestSearchBadbeefBacktracksFromEndUsingCache(t *testing.T) {
	const path = "/usr/lib/chromium-browser/chromium-browser"
	if _, err := os.Stat(path); err != nil {
		t.Skip("chromium binary unavailable")
	}
	f, err := binfile.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	m, err := New(f)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m.disasmMaxBytes = 256 << 10
	m.width, m.height = 120, 40

	m.jumpDisasmBoundary(false)
	m.searchQuery = "badbeef"
	runModelCmd(t, m, m.runSearch(true, true))
	first := m.disasmInst[m.disasmCur].Addr
	if !strings.Contains(strings.ToLower(m.disasmInst[m.disasmCur].Text), "badbeef") {
		t.Fatalf("first hit = %q, want badbeef", m.disasmInst[m.disasmCur].Text)
	}
	runModelCmd(t, m, m.runSearch(true, false))
	second := m.disasmInst[m.disasmCur].Addr
	if second <= first {
		t.Fatalf("second hit 0x%x should be after first 0x%x", second, first)
	}
	runModelCmd(t, m, m.runSearch(true, false))
	if !m.searchResults.forwardExhausted {
		t.Fatal("expected forward search to be exhausted after second badbeef hit")
	}
	cmd := m.runSearch(false, false)
	if m.searchRunning {
		t.Fatal("expected backward repeat after end to use cache")
	}
	runModelCmd(t, m, cmd)
	if got := m.disasmInst[m.disasmCur].Addr; got != second {
		t.Fatalf("first backward cached hit = 0x%x, want last hit 0x%x", got, second)
	}
	cmd = m.runSearch(false, false)
	if m.searchRunning {
		t.Fatal("expected second backward repeat after end to use cache")
	}
	runModelCmd(t, m, cmd)
	if got := m.disasmInst[m.disasmCur].Addr; got != first {
		t.Fatalf("second backward cached hit = 0x%x, want first hit 0x%x", got, first)
	}
	cmd = m.runSearch(false, false)
	if m.searchRunning {
		t.Fatal("expected backward repeat before first hit not to rescan fully covered search")
	}
	if cmd != nil {
		runModelCmd(t, m, cmd)
	}
	if got := m.disasmInst[m.disasmCur].Addr; got != first {
		t.Fatalf("backward repeat before first hit moved to 0x%x, want to stay at first hit 0x%x", got, first)
	}
}

func TestDisasmNavigationAutoLoadsVisibleScreenOnChromiumBinary(t *testing.T) {
	const path = "/usr/lib/chromium-browser/chromium-browser"
	if _, err := os.Stat(path); err != nil {
		t.Skip("chromium binary unavailable")
	}
	f, err := binfile.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	m, err := New(f)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m.disasmMaxBytes = 128 << 10
	m.width, m.height = 120, 20

	m.jumpDisasmBoundary(false)
	m.disasmCur = len(m.disasmInst) - 1
	_, oldHi := m.disasmPosLo, m.disasmPosHi
	m.updateDisasm("down")
	if m.disasmPosHi <= oldHi {
		t.Fatal("expected navigation to load more code below")
	}

	m.jumpDisasmBoundary(true)
	m.disasmCur = 0
	oldLo, _ := m.disasmPosLo, m.disasmPosHi
	m.updateDisasm("up")
	if m.disasmPosLo >= oldLo {
		t.Fatal("expected navigation to load more code above")
	}
}

func TestDisasmSearchShowsProgressAndCancels(t *testing.T) {
	const path = "/usr/lib/chromium-browser/chromium-browser"
	if _, err := os.Stat(path); err != nil {
		t.Skip("chromium binary unavailable")
	}
	f, err := binfile.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	m, err := New(f)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m.disasmMaxBytes = 256 << 10
	m.width, m.height = 120, 40
	m.jumpDisasmBoundary(false)
	m.searchQuery = "definitely-not-present-search-token"

	cmd := m.runSearch(true, true)
	if !m.searchRunning {
		t.Fatal("expected async disasm search to start")
	}
	msg := cmd()
	model, next := m.Update(msg)
	mm := model.(*Model)
	if !mm.searchRunning {
		t.Fatal("expected search to continue after first chunk")
	}
	if next == nil {
		t.Fatal("expected follow-up search command")
	}
	if !strings.Contains(mm.status, "searching disasm") || !strings.Contains(mm.status, "Esc cancels") {
		t.Fatalf("unexpected search status: %q", mm.status)
	}
	mm.cancelSearch("search cancelled")
	if mm.searchRunning {
		t.Fatal("expected search cancellation to stop search")
	}
	if mm.status != "search cancelled" {
		t.Fatalf("unexpected cancel status: %q", mm.status)
	}
	model, cmd = mm.Update(next())
	mm = model.(*Model)
	if mm.status != "search cancelled" {
		t.Fatalf("stale search message changed status to %q", mm.status)
	}
	if cmd != nil {
		t.Fatal("expected cancelled stale search message not to schedule more work")
	}
}

func TestDisasmSearchWorkersAndBatchSizing(t *testing.T) {
	m := &Model{disasmSearchWorkers: 3, disasmMaxBytes: 256 << 10}
	if got := m.disasmSearchWorkersFor(10); got != 3 {
		t.Fatalf("workers = %d, want 3", got)
	}
	if got := m.disasmSearchWorkersFor(2); got != 2 {
		t.Fatalf("workers capped to chunks = %d, want 2", got)
	}
	if got := m.disasmSearchBatchChunks(); got < 2 {
		t.Fatalf("batch chunks = %d, want >= 2", got)
	}
	m.disasmMaxBytes = 64 << 10
	if got := m.disasmSearchBatchChunks(); got < 4 {
		t.Fatalf("small-chunk batch = %d, want >= 4", got)
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

func runModelCmd(t *testing.T, m *Model, cmd tea.Cmd) {
	t.Helper()
	for cmd != nil {
		msg := cmd()
		var model tea.Model
		model, cmd = m.Update(msg)
		mm, ok := model.(*Model)
		if !ok {
			t.Fatal("expected *Model from Update")
		}
		m = mm
	}
}

func firstExisting(paths ...string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
