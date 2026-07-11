package syscalls

import (
	"strings"
	"testing"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/dump"
	"github.com/rabarbra/exex/internal/ui/modal"
)

type fakeHost struct {
	loaded     []uint64
	statuses   []string
	errs       []bool
	fullStarts int
	fullCancel int
	cmd        tea.Cmd
}

func (h *fakeHost) SetStatus(msg string, isErr bool) {
	h.statuses = append(h.statuses, msg)
	h.errs = append(h.errs, isErr)
}
func (h *fakeHost) LoadDisasmAt(a uint64) { h.loaded = append(h.loaded, a) }
func (h *fakeHost) StartFullScan() tea.Cmd {
	h.fullStarts++
	return h.cmd
}
func (h *fakeHost) CancelFullScan() { h.fullCancel++ }

func testCtx() modal.Context {
	id := func(s string) string { return s }
	return modal.Context{
		File:   &binfile.File{},
		Width:  110,
		Height: 30,
		Styles: &modal.Styles{Title: id, Frame: id, Hint: id},
	}
}

func key() tea.KeyMsg { return tea.KeyMsg(tea.KeyPressMsg{}) }

func newState() *State {
	s := &State{}
	in := textinput.New()
	in.Prompt = "/ "
	s.SetInput(in)
	return s
}

// sites: two calls to #1 inside the cursor's function, one #60 outside it.
func sites() []dump.SyscallSite {
	return []dump.SyscallSite{
		{Addr: 0x1010, Num: 1, HasNum: true, Name: "write", Text: "syscall"},
		{Addr: 0x1020, Num: 1, HasNum: true, Name: "write", Text: "syscall"},
		{Addr: 0x2000, Num: 60, HasNum: true, Name: "exit", Text: "syscall"},
	}
}

func opened() *State {
	s := newState()
	s.SetFunc(0x1000, 0x1100, "main")
	s.Open(sites())
	return s
}

// TestScopesFilterRows moved here from the shell's newviews_test: function scope
// shows only the cursor's function, unique aggregates by number with counts.
func TestScopesFilterRows(t *testing.T) {
	s := opened()

	if s.Scope() != ScopeFunc {
		t.Fatalf("Open landed in scope %v, want ScopeFunc (its function has syscalls)", s.Scope())
	}
	if s.Shown() != 2 {
		t.Errorf("function scope = %d rows, want 2", s.Shown())
	}
	s.SetScope(ScopeAll)
	if s.Shown() != 3 {
		t.Errorf("all scope = %d rows, want 3", s.Shown())
	}
	s.SetScope(ScopeUnique)
	if s.Shown() != 2 {
		t.Fatalf("unique scope = %d rows, want 2 (#1, #60)", s.Shown())
	}
	for _, r := range s.Rows() {
		if r.Site.Num == 1 && r.Count != 2 {
			t.Errorf("unique count for #1 = %d, want 2", r.Count)
		}
	}
}

// TestOpenLandsInAllWhenTheFunctionHasNone: the function scope would be empty.
func TestOpenLandsInAllWhenTheFunctionHasNone(t *testing.T) {
	s := newState()
	s.SetFunc(0x9000, 0x9100, "elsewhere")
	s.Open(sites())
	if s.Scope() != ScopeAll {
		t.Errorf("scope = %v, want ScopeAll", s.Scope())
	}
	if s.Shown() != 3 {
		t.Errorf("shown = %d, want 3", s.Shown())
	}
}

// TestOpenFullReportsWhetherAScanIsNeeded: the library scan is lazy, and must not
// be started twice.
func TestOpenFullReportsWhetherAScanIsNeeded(t *testing.T) {
	s := newState()
	if !s.OpenFull() {
		t.Error("a fresh overlay should ask for the library scan")
	}
	if s.Scope() != ScopeFull || !s.Active() {
		t.Errorf("OpenFull: scope=%v active=%v", s.Scope(), s.Active())
	}

	s.SetFullRunning(true)
	if s.OpenFull() {
		t.Error("a running scan should not be started again")
	}
	s.SetFullResults(nil, nil, 1)
	if s.OpenFull() {
		t.Error("a finished scan should not be started again")
	}
}

// TestEnteringFullScopeStartsTheScanOnce is the lazy-scan contract from the key
// handler's side.
func TestEnteringFullScopeStartsTheScanOnce(t *testing.T) {
	s := opened()
	host := &fakeHost{cmd: func() tea.Msg { return nil }}

	// ScopeFunc → All → Unique → Full
	for range 3 {
		s.Update(host, key(), "t")
	}
	if s.Scope() != ScopeFull {
		t.Fatalf("scope = %v, want ScopeFull", s.Scope())
	}
	if host.fullStarts != 1 {
		t.Errorf("full scans started = %d, want 1", host.fullStarts)
	}

	// Leaving full scope cancels it; the results are not yet in.
	s.Update(host, key(), "t")
	if host.fullCancel != 1 {
		t.Errorf("leaving full scope did not cancel the scan (%d)", host.fullCancel)
	}
}

// TestFullScopeDoesNotRescanWhenDone
func TestFullScopeDoesNotRescanWhenDone(t *testing.T) {
	s := opened()
	s.SetFullResults([]dump.SyscallSite{{Addr: 0x5000, Num: 5, HasNum: true, Name: "read"}}, nil, 2)
	host := &fakeHost{}
	for range 3 {
		s.Update(host, key(), "t")
	}
	if s.Scope() != ScopeFull {
		t.Fatalf("scope = %v", s.Scope())
	}
	if host.fullStarts != 0 {
		t.Errorf("a completed scan was restarted (%d times)", host.fullStarts)
	}
	if s.Shown() != 1 {
		t.Errorf("full scope shows %d rows, want the library's 1", s.Shown())
	}
}

func TestSortCyclesAndReverses(t *testing.T) {
	s := opened()
	s.SetScope(ScopeAll)
	host := &fakeHost{}

	if got := s.Rows()[0].Site.Num; got != 1 {
		t.Errorf("default sort: first = #%d, want #1 (by number)", got)
	}
	s.Update(host, key(), "r") // reverse
	if got := s.Rows()[0].Site.Num; got != 60 {
		t.Errorf("reversed: first = #%d, want #60", got)
	}
	s.Update(host, key(), "r") // back
	s.Update(host, key(), "s") // → name
	if got := s.Rows()[0].Site.Name; got != "exit" {
		t.Errorf("by name: first = %q, want exit", got)
	}
	if len(host.statuses) == 0 || !strings.Contains(host.statuses[len(host.statuses)-1], "name") {
		t.Errorf("sort change did not report the key: %v", host.statuses)
	}
}

func TestFilterMatchesNameNumberAndText(t *testing.T) {
	for _, tc := range []struct {
		needle string
		want   int
	}{
		{"write", 2},
		{"exit", 1},
		{"60", 1},
		{"0x3c", 1}, // 60 in hex
		{"syscall", 3},
		{"nothing", 0},
	} {
		t.Run(tc.needle, func(t *testing.T) {
			s := opened()
			s.SetScope(ScopeAll)
			s.filter.SetValue(tc.needle)
			s.rebuild()
			if s.Shown() != tc.want {
				t.Errorf("filter %q = %d rows, want %d", tc.needle, s.Shown(), tc.want)
			}
			if s.total != 3 {
				t.Errorf("total = %d, want 3 (pre-filter)", s.total)
			}
		})
	}
}

func TestActivateJumpsAndCancelsTheLibraryScan(t *testing.T) {
	s := opened()
	host := &fakeHost{}
	s.Update(host, key(), "enter")
	if len(host.loaded) != 1 || host.loaded[0] != 0x1010 {
		t.Errorf("jumped to %#x, want [0x1010]", host.loaded)
	}
	if host.fullCancel != 1 {
		t.Error("jumping did not cancel the library scan")
	}
	if s.Active() {
		t.Error("Enter did not close the overlay")
	}
}

// TestActivateRefusesSitesInOtherObjects: a library site is in a different
// address space, so following it would land in the wrong image.
func TestActivateRefusesSitesInOtherObjects(t *testing.T) {
	s := newState()
	s.SetFullResults([]dump.SyscallSite{
		{Addr: 0x5000, Num: 5, HasNum: true, Name: "read", Origin: "libsystem_kernel.dylib"},
	}, nil, 2)
	s.OpenFull()

	host := &fakeHost{}
	s.Activate(host)
	if len(host.loaded) != 0 {
		t.Errorf("followed a site in another object: %#x", host.loaded)
	}
	if len(host.statuses) != 1 || !strings.Contains(host.statuses[0], "libsystem_kernel.dylib") {
		t.Errorf("statuses = %v, want an explanation naming the object", host.statuses)
	}
	if !host.errs[0] {
		t.Error("the refusal should be reported as an error")
	}
	if !s.Active() {
		t.Error("a refused jump closed the overlay")
	}
}

func TestEscInFilterOnlyClearsIt(t *testing.T) {
	s := opened()
	s.SetScope(ScopeAll)
	host := &fakeHost{}

	s.Update(host, key(), "/")
	if !s.Filtering() {
		t.Fatal("/ did not focus the filter")
	}
	s.filter.SetValue("exit")
	s.rebuild()
	s.Update(host, key(), "esc")
	if s.Filtering() || !s.Active() {
		t.Errorf("esc in filter: filtering=%v active=%v", s.Filtering(), s.Active())
	}
	if s.Shown() != 3 {
		t.Errorf("esc did not clear the filter: shown=%d", s.Shown())
	}
	s.Update(host, key(), "esc")
	if s.Active() {
		t.Error("esc outside the filter did not close the overlay")
	}
}

// TestNameColumnSizesToContent is the fix for truncated syscall names: a fixed
// 16-wide column turned "kdebug_trace_string" into "kd…e_string" while the
// origin column beside it was padded with blanks.
func TestNameColumnSizesToContent(t *testing.T) {
	short := []Row{{Site: dump.SyscallSite{Num: 1, HasNum: true, Name: "write"}, Count: 1}}
	if got := nameColumnWidth(short); got != minNameW {
		t.Errorf("short labels widened the column to %d, want the %d minimum", got, minNameW)
	}

	long := []Row{{Site: dump.SyscallSite{Num: 178, HasNum: true, Name: "kdebug_trace_string"}, Count: 1}}
	want := len("#178 kdebug_trace_string")
	if got := nameColumnWidth(long); got != want {
		t.Errorf("column width = %d, want %d (the whole label)", got, want)
	}

	huge := []Row{{Site: dump.SyscallSite{Num: 1, HasNum: true, Name: strings.Repeat("x", 100)}, Count: 1}}
	if got := nameColumnWidth(huge); got != maxNameW {
		t.Errorf("a pathological name widened the column to %d, want the %d cap", got, maxNameW)
	}

	// Rendering it must show the name in full.
	s := newState()
	s.SetFullResults([]dump.SyscallSite{
		{Addr: 0x1, Num: 178, HasNum: true, Name: "kdebug_trace_string", Origin: "libsystem_kernel.dylib", Text: "svc"},
	}, nil, 2)
	s.OpenFull()
	if out := s.Render(testCtx()); !strings.Contains(out, "#178 kdebug_trace_string") {
		t.Errorf("the rendered row truncated the name:\n%s", out)
	}
}

func TestLabelWidthMatchesLabelText(t *testing.T) {
	for _, s := range []dump.SyscallSite{
		{Num: 1, HasNum: true, Name: "write"},
		{Num: 1234, HasNum: true},
		{Name: "only_a_name"},
		{VDSO: true},
		{},
	} {
		if got, want := labelWidth(s), len(labelText(s)); got != want {
			t.Errorf("labelWidth(%+v) = %d, labelText is %d wide", s, got, want)
		}
	}
}

func TestScopeLabelDescribesTheFullScan(t *testing.T) {
	s := newState()
	s.OpenFull()
	if got := s.ScopeLabel(); got != "full (+libs)" {
		t.Errorf("before the scan: %q", got)
	}
	s.SetFullRunning(true)
	if got := s.ScopeLabel(); !strings.Contains(got, "scanning") {
		t.Errorf("during the scan: %q", got)
	}
	s.SetFullResults(nil, nil, 3)
	if got := s.ScopeLabel(); got != "full · binary + 2 libs" {
		t.Errorf("after the scan: %q", got)
	}
}

func TestRenderEmptyStates(t *testing.T) {
	s := newState()
	s.OpenFull()
	if !strings.Contains(s.Render(testCtx()), "no syscalls") {
		t.Error("an idle empty full scope should say so")
	}
	s.SetFullRunning(true)
	if !strings.Contains(s.Render(testCtx()), "scanning binary + libraries…") {
		t.Error("a running scan should say it is scanning, not that there are none")
	}
	s.SetFullResults(nil, nil, 2)
	if !strings.Contains(s.Render(testCtx()), "no syscalls found in the binary or its libraries") {
		t.Error("a finished empty scan should say so")
	}

	s2 := opened()
	s2.SetScope(ScopeAll)
	s2.filter.SetValue("zzz")
	s2.rebuild()
	if !strings.Contains(s2.Render(testCtx()), "no syscalls match the filter") {
		t.Error("an over-narrow filter should say so")
	}
}
