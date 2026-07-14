package search

import (
	"strings"
	"testing"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/shellcell/exex/internal/bytesearch"
	"github.com/shellcell/exex/internal/ui/modal"
)

type submitted struct {
	query string
	opts  Options
}

type fakeHost struct {
	submits     []submitted
	caseChanges int
	cmd         tea.Cmd
}

func (h *fakeHost) SetStatus(string, bool) {}
func (h *fakeHost) LoadDisasmAt(uint64)    {}
func (h *fakeHost) SearchHint() string     { return "bytes or text" }
func (h *fakeHost) SearchCaseChanged()     { h.caseChanges++ }
func (h *fakeHost) SubmitSearch(q string, o Options) tea.Cmd {
	h.submits = append(h.submits, submitted{q, o})
	return h.cmd
}

func testCtx() modal.Context {
	id := func(s string) string { return s }
	return modal.Context{Width: 100, Height: 30, Styles: &modal.Styles{Title: id, Frame: id, Hint: id}}
}

func key() tea.KeyMsg { return tea.KeyMsg(tea.KeyPressMsg{}) }

func opened() *State {
	s := &State{}
	in := textinput.New()
	in.Prompt = "/ "
	s.Init(in)
	s.Open()
	return s
}

// TestInitSetsNonZeroDefaults: forward and from-cursor are true, which the zero
// value is not — a State must be initialised, not merely declared.
func TestInitSetsNonZeroDefaults(t *testing.T) {
	var bare State
	if bare.Forward() || bare.FromCursor() {
		t.Fatal("the zero value should not look initialised")
	}
	s := opened()
	if !s.Forward() || !s.FromCursor() || s.CaseSensitive() || s.Mode() != bytesearch.ModeAuto {
		t.Errorf("defaults: forward=%v fromCursor=%v case=%v mode=%v",
			s.Forward(), s.FromCursor(), s.CaseSensitive(), s.Mode())
	}
}

// TestOpenClearsQueryButKeepsOptions: options are search settings, the query is
// per-prompt.
func TestOpenClearsQueryButKeepsOptions(t *testing.T) {
	s := opened()
	host := &fakeHost{}
	s.Update(host, key(), "ctrl+r") // backward
	s.HandleInput(tea.PasteMsg{Content: "stale"})
	if s.Value() != "stale" {
		t.Fatalf("paste did not reach the query box: %q", s.Value())
	}
	s.Open()
	if s.Value() != "" {
		t.Errorf("Open kept a stale query: %q", s.Value())
	}
	if s.Forward() {
		t.Error("Open reset the direction toggle")
	}
}

func TestEnterSubmitsTrimmedQueryWithOptions(t *testing.T) {
	s := opened()
	host := &fakeHost{}
	s.Update(host, key(), "ctrl+o") // origin: start/end
	s.HandleInput(tea.PasteMsg{Content: "  de ad  "})

	s.Update(host, key(), "enter")
	if len(host.submits) != 1 {
		t.Fatalf("submits = %v, want one", host.submits)
	}
	if host.submits[0].query != "de ad" {
		t.Errorf("query = %q, want trimmed", host.submits[0].query)
	}
	if host.submits[0].opts.FromCursor {
		t.Error("the origin toggle did not reach the search")
	}
	if s.Active() {
		t.Error("Enter did not close the prompt")
	}
}

func TestEnterPropagatesTheHostCommand(t *testing.T) {
	s := opened()
	host := &fakeHost{cmd: func() tea.Msg { return nil }}
	if got := s.Update(host, key(), "enter"); got == nil {
		t.Error("Update dropped the host's command; the search would never run")
	}
}

func TestEscClosesWithoutSearching(t *testing.T) {
	s := opened()
	host := &fakeHost{}
	s.Update(host, key(), "esc")
	if s.Active() || len(host.submits) != 0 {
		t.Errorf("esc: active=%v submits=%v", s.Active(), host.submits)
	}
}

func TestModeCyclesAutoTextHex(t *testing.T) {
	s := opened()
	host := &fakeHost{}
	want := []bytesearch.Mode{bytesearch.ModeText, bytesearch.ModeHex, bytesearch.ModeAuto}
	for i, w := range want {
		s.Update(host, key(), "ctrl+t")
		if s.Mode() != w {
			t.Errorf("step %d: mode = %v, want %v", i, s.Mode(), w)
		}
	}
}

// TestCaseToggleNotifiesTheHost: cached disasm hits were computed under the old
// setting, so the shell must be told to drop them. Nothing else does.
func TestCaseToggleNotifiesTheHost(t *testing.T) {
	s := opened()
	host := &fakeHost{}

	s.Update(host, key(), "ctrl+i")
	if !s.CaseSensitive() || host.caseChanges != 1 {
		t.Errorf("case: sensitive=%v hostNotified=%d", s.CaseSensitive(), host.caseChanges)
	}
	// The other toggles have no such side effect.
	s.Update(host, key(), "ctrl+t")
	s.Update(host, key(), "ctrl+r")
	s.Update(host, key(), "ctrl+o")
	if host.caseChanges != 1 {
		t.Errorf("an unrelated toggle notified the host (%d times)", host.caseChanges)
	}
}

// TestOriginLabelFollowsDirection: with the origin off the cursor, "start" and
// "end" depend on which way the search runs.
func TestOriginLabelFollowsDirection(t *testing.T) {
	s := opened()
	host := &fakeHost{}
	labels := func() map[string]string {
		out := map[string]string{}
		for _, sw := range s.Switches() {
			out[sw.Name] = sw.Value
		}
		return out
	}
	if got := labels()["origin"]; got != "cursor" {
		t.Errorf("origin = %q, want cursor", got)
	}
	s.Update(host, key(), "ctrl+o") // off the cursor, still forward
	if got := labels()["origin"]; got != "start" {
		t.Errorf("forward origin = %q, want start", got)
	}
	s.Update(host, key(), "ctrl+r") // backward
	if got := labels()["origin"]; got != "end" {
		t.Errorf("backward origin = %q, want end", got)
	}
}

// TestClickAtMapsColumnsToSwitches walks the strip the way the renderer lays it
// out, so a change to one without the other fails here.
func TestClickAtMapsColumnsToSwitches(t *testing.T) {
	s := opened()
	host := &fakeHost{}

	pos := 1 // switchIndent
	sepW := lipgloss.Width(SwitchSep)
	centres := map[string]int{}
	for _, sw := range s.Switches() {
		w := lipgloss.Width(sw.Label())
		centres[sw.Name] = pos + w/2
		pos += w + sepW
	}

	if !s.ClickAt(host, centres["mode"]) || s.Mode() != bytesearch.ModeText {
		t.Errorf("mode click: mode = %v", s.Mode())
	}
	if !s.ClickAt(host, centres["case"]) || !s.CaseSensitive() {
		t.Error("case click did not toggle case sensitivity")
	}
	if !s.ClickAt(host, centres["dir"]) || s.Forward() {
		t.Error("dir click did not toggle direction")
	}
	if !s.ClickAt(host, centres["origin"]) || s.FromCursor() {
		t.Error("origin click did not toggle origin")
	}
}

func TestClickAtOutsideAnySwitchIsInert(t *testing.T) {
	s := opened()
	host := &fakeHost{}
	before := s.Options()
	for _, cx := range []int{-1, 0, 1000} {
		if s.ClickAt(host, cx) {
			t.Errorf("ClickAt(%d) reported a hit", cx)
		}
	}
	if s.Options() != before {
		t.Error("a missed click changed the options")
	}
}

func TestRenderShowsHintAndSwitches(t *testing.T) {
	s := opened()
	out := s.Render(testCtx(), &fakeHost{})
	for _, want := range []string{"Search", "bytes or text", "mode", "⟦auto⟧", "case", "⟦insensitive⟧", "dir", "origin"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered prompt is missing %q", want)
		}
	}
}

// TestSwitchLineMatchesRender pins the constant the mouse hit-test relies on: the
// strip really is on content row SwitchLine.
func TestSwitchLineMatchesRender(t *testing.T) {
	s := opened()
	lines := strings.Split(s.Render(testCtx(), &fakeHost{}), "\n")
	if SwitchLine >= len(lines) {
		t.Fatalf("SwitchLine %d is past the rendered %d lines", SwitchLine, len(lines))
	}
	if !strings.Contains(lines[SwitchLine], "⟦auto⟧") {
		t.Errorf("content row %d is not the switch strip: %q", SwitchLine, lines[SwitchLine])
	}
}
