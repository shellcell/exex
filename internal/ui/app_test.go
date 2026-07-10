package ui

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/ui/layout"
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
		model = settleDisasmDecode(model)
	}

	pump(tea.WindowSizeMsg{Width: 120, Height: 40})

	send := func(s string) {
		t.Helper()
		pump(keyPress(s))
		if strings.TrimSpace(model.View().Content) == "" {
			t.Fatalf("empty render after key %q", s)
		}
	}
	assertDisasmBudget := func() {
		t.Helper()
		mm, ok := model.(*Model)
		if !ok || len(mm.dasm.Inst) == 0 {
			return
		}
		if got := mm.dasm.PosHi - mm.dasm.PosLo; got > mm.disasmMaxBytes {
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
	mouse := func(b tea.MouseButton, x, y int) {
		t.Helper()
		if b == tea.MouseWheelUp || b == tea.MouseWheelDown {
			pump(tea.MouseWheelMsg(tea.Mouse{Button: b, X: x, Y: y}))
		} else {
			pump(tea.MouseClickMsg(tea.Mouse{Button: b, X: x, Y: y}))
		}
		if strings.TrimSpace(model.View().Content) == "" {
			t.Fatalf("empty render after mouse event")
		}
	}
	for _, v := range []string{"2", "3", "4", "5", "7"} {
		send(v)
		mouse(tea.MouseWheelDown, 10, 10)
		mouse(tea.MouseWheelUp, 10, 10)
		mouse(tea.MouseLeft, 20, 6)
	}

	// Clicking along the tab strip (y == 0) should switch views.
	for x := 16; x < 90; x += 6 {
		mouse(tea.MouseLeft, x, 0)
	}

	// Strings view: scroll and jump.
	send("8")
	send("down")
	send("enter")

	// Disasm double-click: two quick left clicks on the same row should follow.
	send("4")
	mouse(tea.MouseLeft, 30, 5)
	mouse(tea.MouseLeft, 30, 5)

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
	model, _ = model.Update(keyPress("ctrl+e"))
	model, _ = model.Update(keyPress("ctrl+a"))

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
	if strings.TrimSpace(model.View().Content) == "" {
		t.Fatal("empty render at end")
	}
}

func TestCtrlENavigatesDisasmToEnd(t *testing.T) {
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
	m.width, m.height = 120, 40
	m.disasmMaxBytes = 16 << 10
	m.jumpDisasmBoundary(false)
	if len(m.dasm.Inst) < 2 {
		t.Skip("not enough disassembly to test end navigation")
	}
	m.dasm.Cur = 0

	model, _ := m.handleKey(keyPress("ctrl+e"))
	m = model.(*Model)
	if got, want := m.dasm.Cur, len(m.dasm.Inst)-1; got != want {
		t.Fatalf("ctrl+e disasm cursor = %d, want %d", got, want)
	}
	_ = m.View()
	rowHeight := func(i int) int { return m.disasmInstVisualHeight(i, m.disasmRenderWidth()) }
	if got, want := m.dasm.Top, layout.MaxViewportTop(len(m.dasm.Inst), m.disasmViewportHeight(), rowHeight); got != want {
		t.Fatalf("ctrl+e disasm top = %d, want bottom-aligned %d", got, want)
	}

	endCur := m.dasm.Cur
	endTop := m.dasm.Top
	model, _ = m.handleKey(keyPress("up"))
	m = model.(*Model)
	if got, want := m.dasm.Cur, endCur-1; got != want {
		t.Fatalf("up after ctrl+e cursor = %d, want %d", got, want)
	}
	if got := m.dasm.Top; got != endTop {
		t.Fatalf("up after ctrl+e top = %d, want unchanged %d", got, endTop)
	}

	model, _ = m.handleKey(keyPress("ctrl+e"))
	m = model.(*Model)
	_ = m.View()
	endTop = m.dasm.Top
	endLo := m.dasm.PosLo
	endAddr := m.dasm.Inst[m.dasm.Cur].Addr
	m.wheelSuppressUntil = time.Time{}
	model, _ = m.handleMouse(tea.MouseWheelMsg(tea.Mouse{Button: tea.MouseWheelUp, X: 2, Y: 5}))
	m = model.(*Model)
	if !m.viewportDetached {
		t.Fatal("wheel up after ctrl+e did not detach viewport")
	}
	if endTop == 0 && endLo > 0 {
		if got := m.dasm.PosLo; got >= endLo {
			t.Fatalf("wheel up after ctrl+e posLo = %d, want before %d", got, endLo)
		}
		if got := m.dasm.Inst[m.dasm.Cur].Addr; got > endAddr {
			t.Fatalf("wheel up after ctrl+e cursor addr = 0x%x, want at or before 0x%x", got, endAddr)
		}
	} else if got := m.dasm.Top; got >= endTop {
		t.Fatalf("wheel up after ctrl+e top = %d, want less than %d", got, endTop)
	}
}

func TestMouseWheelOverRightDisasmPaneScrollsRightPane(t *testing.T) {
	path := buildDebugSample(t)
	f, err := binfile.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !f.HasDWARF() {
		t.Skip("debug sample has no DWARF")
	}
	m, err := New(f)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m.width, m.height = 120, 30
	m.disasmMaxBytes = 16 << 10
	m.jumpDisasmBoundary(false)
	m.wheelSuppressUntil = time.Time{}
	if !m.rightPaneActive() {
		t.Skip("right pane is not active")
	}
	m.rightScroll = 9

	model, _ := m.handleMouse(tea.MouseWheelMsg(tea.Mouse{Button: tea.MouseWheelUp, X: m.width - 2, Y: 10}))
	m = model.(*Model)
	if got := m.rightScroll; got != 6 {
		t.Fatalf("rightScroll after wheel up = %d, want 6", got)
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

	mm.palette.SetQuery(mm, "ChromeMain")
	if len(mm.palette.Results()) == 0 {
		t.Fatal("expected goto results for ChromeMain")
	}
	mm.palette.Activate(mm)
	if mm.mode != modeDisasm {
		t.Fatalf("mode = %v, want disasm", mm.mode)
	}
	if len(mm.dasm.Inst) == 0 {
		t.Fatal("expected disasm window after goto")
	}
	addr := mm.dasm.Inst[mm.dasm.Cur].Addr
	sym, ok := mm.file.SymbolAt(addr)
	if !ok {
		t.Fatalf("no symbol at current disasm address 0x%x", addr)
	}
	if sym.Display() != "ChromeMain" {
		t.Fatalf("landed on %q at 0x%x, want ChromeMain", sym.Display(), addr)
	}
	if got := mm.dasm.PosHi - mm.dasm.PosLo; got > mm.disasmMaxBytes {
		t.Fatalf("disasm window = %d bytes, budget = %d", got, mm.disasmMaxBytes)
	}

	mm.jumpDisasmBoundary(false)
	mm.searchQuery = "ChromeMain"
	runModelCmd(t, mm, mm.runSearch(true, true))
	if len(mm.dasm.Inst) == 0 {
		t.Fatal("expected disasm window after search")
	}
	addr = mm.dasm.Inst[mm.dasm.Cur].Addr
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
	if len(m.dasm.Inst) == 0 {
		t.Fatal("expected disasm window after search")
	}
	got := strings.ToLower(m.dasm.Inst[m.dasm.Cur].Text)
	if !strings.Contains(got, "movsbl") {
		t.Fatalf("search landed on %q, want movsbl", got)
	}
	if got := m.dasm.PosHi - m.dasm.PosLo; got > m.disasmMaxBytes {
		t.Fatalf("disasm window = %d bytes, budget = %d", got, m.disasmMaxBytes)
	}
	first := m.dasm.Inst[m.dasm.Cur].Addr
	if len(m.searchResults.Hits()) < 2 {
		t.Fatalf("expected cached movsbl hits, got %d", len(m.searchResults.Hits()))
	}
	cmd := m.runSearch(true, false)
	if m.searchRunning {
		t.Fatal("expected cached movsbl hit not to start background search")
	}
	runModelCmd(t, m, cmd)
	second := m.dasm.Inst[m.dasm.Cur].Addr
	if second <= first {
		t.Fatalf("expected later cached movsbl hit, got 0x%x after 0x%x", second, first)
	}
	for i := 0; i < 6; i++ {
		runModelCmd(t, m, m.runSearch(true, false))
	}
	if len(m.searchResults.Hits()) < 6 {
		t.Fatalf("expected several cached movsbl hits, got %d", len(m.searchResults.Hits()))
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
	first := m.dasm.Inst[m.dasm.Cur].Addr
	if !strings.Contains(strings.ToLower(m.dasm.Inst[m.dasm.Cur].Text), "badbeef") {
		t.Fatalf("first hit = %q, want badbeef", m.dasm.Inst[m.dasm.Cur].Text)
	}
	runModelCmd(t, m, m.runSearch(true, false))
	second := m.dasm.Inst[m.dasm.Cur].Addr
	if second <= first {
		t.Fatalf("second hit 0x%x should be after first 0x%x", second, first)
	}
	runModelCmd(t, m, m.runSearch(true, false))
	if !m.searchResults.Exhausted(true) {
		t.Fatal("expected forward search to be exhausted after second badbeef hit")
	}
	cmd := m.runSearch(false, false)
	if m.searchRunning {
		t.Fatal("expected backward repeat after end to use cache")
	}
	runModelCmd(t, m, cmd)
	if got := m.dasm.Inst[m.dasm.Cur].Addr; got != second {
		t.Fatalf("first backward cached hit = 0x%x, want last hit 0x%x", got, second)
	}
	cmd = m.runSearch(false, false)
	if m.searchRunning {
		t.Fatal("expected second backward repeat after end to use cache")
	}
	runModelCmd(t, m, cmd)
	if got := m.dasm.Inst[m.dasm.Cur].Addr; got != first {
		t.Fatalf("second backward cached hit = 0x%x, want first hit 0x%x", got, first)
	}
	cmd = m.runSearch(false, false)
	if m.searchRunning {
		t.Fatal("expected backward repeat before first hit not to rescan fully covered search")
	}
	if cmd != nil {
		runModelCmd(t, m, cmd)
	}
	if got := m.dasm.Inst[m.dasm.Cur].Addr; got != first {
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
	m.dasm.Cur = len(m.dasm.Inst) - 1
	_, oldHi := m.dasm.PosLo, m.dasm.PosHi
	m.updateDisasm("down")
	if m.dasm.PosHi <= oldHi {
		t.Fatal("expected navigation to load more code below")
	}

	m.jumpDisasmBoundary(true)
	m.dasm.Cur = 0
	oldLo, _ := m.dasm.PosLo, m.dasm.PosHi
	m.updateDisasm("up")
	if m.dasm.PosLo >= oldLo {
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

func keyPress(s string) tea.KeyPressMsg {
	switch s {
	case "down":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyDown})
	case "up":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyUp})
	case "left":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyLeft})
	case "right":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyRight})
	case "pgdown":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyPgDown})
	case "pgup":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyPgUp})
	case "home":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyHome})
	case "end":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyEnd})
	case "enter":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter})
	case "esc":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyEscape})
	case "tab":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyTab})
	case "ctrl+a":
		return tea.KeyPressMsg(tea.Key{Code: 'a', Mod: tea.ModCtrl})
	case "ctrl+e":
		return tea.KeyPressMsg(tea.Key{Code: 'e', Mod: tea.ModCtrl})
	}
	r := []rune(s)
	return tea.KeyPressMsg(tea.Key{Text: s, Code: r[0]})
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

func buildDebugSample(t *testing.T) string {
	t.Helper()
	cc, err := exec.LookPath("gcc")
	if err != nil {
		cc, err = exec.LookPath("cc")
	}
	if err != nil {
		t.Skip("no C compiler available")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "sample.c")
	bin := filepath.Join(dir, "sample")
	const code = `
#include <stdio.h>
static int twice(int x) {
    return x * 2;
}
int main(int argc, char **argv) {
    int value = twice(argc);
    printf("%d\n", value);
    return value;
}
`
	if err := os.WriteFile(src, []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(cc, "-g", "-O0", "-o", bin, src).CombinedOutput()
	if err != nil {
		t.Fatalf("compile failed: %v\n%s", err, out)
	}
	return bin
}

func firstExisting(paths ...string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
