package findquery

import (
	"strings"
	"testing"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/ui/modal"
)

type started struct {
	text          string
	caseSensitive bool
}

type fakeHost struct {
	searches []started
	cmd      tea.Cmd
}

func (h *fakeHost) SetStatus(string, bool) {}
func (h *fakeHost) LoadDisasmAt(uint64)    {}
func (h *fakeHost) StartTextSearch(text string, caseSensitive bool) tea.Cmd {
	h.searches = append(h.searches, started{text, caseSensitive})
	return h.cmd
}

func testCtx() modal.Context {
	id := func(s string) string { return s }
	return modal.Context{
		File:   &binfile.File{},
		Width:  100,
		Height: 30,
		Styles: &modal.Styles{Title: id, Frame: id, Hint: id},
	}
}

func key() tea.KeyMsg { return tea.KeyMsg(tea.KeyPressMsg{}) }

func opened() *State {
	s := &State{}
	in := textinput.New()
	in.Prompt = "search "
	s.SetInput(in)
	s.Open()
	return s
}

func TestOpenClearsAndFocuses(t *testing.T) {
	s := opened()
	s.input.SetValue("stale")
	s.Close()
	s.Open()
	if !s.Active() || s.Value() != "" {
		t.Errorf("Open: active=%v value=%q, want true/empty", s.Active(), s.Value())
	}
}

func TestEnterStartsTheSearchAndCloses(t *testing.T) {
	s := opened()
	s.input.SetValue("  malloc  ")
	host := &fakeHost{}

	s.Update(host, key(), "enter")
	if len(host.searches) != 1 {
		t.Fatalf("searches = %v, want one", host.searches)
	}
	// The prompt trims; deciding what the text *means* is the shell's job.
	if host.searches[0].text != "malloc" {
		t.Errorf("search text = %q, want the trimmed value", host.searches[0].text)
	}
	if s.Active() {
		t.Error("Enter did not close the prompt")
	}
}

// TestEnterOnEmptyStillReachesTheHost: the prompt does not decide that an empty
// query is meaningless — the shell reports "type something to search for", and
// keeping that in one place is why the text is handed over unjudged.
func TestEnterOnEmptyStillReachesTheHost(t *testing.T) {
	s := opened()
	host := &fakeHost{}
	s.Update(host, key(), "enter")
	if len(host.searches) != 1 || host.searches[0].text != "" {
		t.Errorf("searches = %v, want one empty query", host.searches)
	}
}

// TestCaseToggleIsStickyAcrossOpens: it is a search option, not a per-query field.
func TestCaseToggleIsStickyAcrossOpens(t *testing.T) {
	s := opened()
	host := &fakeHost{}
	if s.CaseSensitive() {
		t.Fatal("case sensitivity should default to off")
	}
	s.Update(host, key(), "ctrl+i")
	if !s.CaseSensitive() {
		t.Fatal("^i did not toggle case sensitivity")
	}
	if !s.Active() {
		t.Error("^i closed the prompt")
	}

	s.input.SetValue("x")
	s.Update(host, key(), "enter")
	if !host.searches[0].caseSensitive {
		t.Error("the toggle did not reach the search")
	}

	s.Open()
	if !s.CaseSensitive() {
		t.Error("the toggle did not survive a reopen")
	}
}

func TestEscClosesWithoutSearching(t *testing.T) {
	s := opened()
	host := &fakeHost{}
	s.Update(host, key(), "esc")
	if s.Active() {
		t.Error("esc did not close the prompt")
	}
	if len(host.searches) != 0 {
		t.Error("esc started a search")
	}
}

func TestEnterPropagatesTheHostCommand(t *testing.T) {
	s := opened()
	host := &fakeHost{cmd: func() tea.Msg { return nil }}
	if got := s.Update(host, key(), "enter"); got == nil {
		t.Error("Update dropped the host's command; the search would never run")
	}
}

func TestRenderShowsTheCaseTag(t *testing.T) {
	s := opened()
	out := s.Render(testCtx())
	if !strings.Contains(out, "Search the binary") {
		t.Error("title missing")
	}
	if !strings.Contains(out, "case-insensitive") {
		t.Errorf("default case tag missing:\n%s", out)
	}
	s.Update(&fakeHost{}, key(), "ctrl+i")
	if out = s.Render(testCtx()); !strings.Contains(out, "case-sensitive") {
		t.Errorf("toggled case tag missing:\n%s", out)
	}
}
