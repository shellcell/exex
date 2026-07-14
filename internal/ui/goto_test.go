package ui

import (
	"fmt"
	"testing"

	"github.com/shellcell/exex/internal/binfile"
	palettemodal "github.com/shellcell/exex/internal/ui/modals/palette"
)

func TestResolveSymbolGoto(t *testing.T) {
	m := &Model{file: &binfile.File{Symbols: []binfile.Symbol{
		{Name: "xmainy", Addr: 0x3000},
		{Name: "main_helper", Addr: 0x2000},
		{Name: "main", Addr: 0x1000},
	}}}
	// "main" matches all three by substring, but is a unique exact name.
	best, count, exact, exactN := m.resolveSymbolGoto("main")
	if count != 3 || exactN != 1 || exact.Name != "main" || best.Name != "main" {
		t.Fatalf("resolve(main): count=%d exactN=%d exact=%q best=%q", count, exactN, exact.Name, best.Name)
	}
	// "main_h" is a single prefix match, no exact.
	best, count, _, exactN = m.resolveSymbolGoto("main_h")
	if count != 1 || exactN != 0 || best.Name != "main_helper" {
		t.Fatalf("resolve(main_h): count=%d exactN=%d best=%q", count, exactN, best.Name)
	}
	if _, count, _, _ := m.resolveSymbolGoto("definitely_absent"); count != 0 {
		t.Fatalf("absent needle matched %d", count)
	}
}

func TestAppendSymbolMatchesRanksBeforeTableOrder(t *testing.T) {
	m := &Model{file: &binfile.File{Symbols: []binfile.Symbol{
		{Name: "zzz_target", Addr: 0x3000},
		{Name: "target_helper", Addr: 0x2000},
		{Name: "target", Addr: 0x1000},
	}}}
	got := m.appendSymbolMatches(nil, "target")
	if len(got) != 3 {
		t.Fatalf("matches = %d, want 3", len(got))
	}
	want := []string{"target", "target_helper", "zzz_target"}
	for i, w := range want {
		if got[i].Label != w {
			t.Fatalf("result[%d] = %q, want %q", i, got[i].Label, w)
		}
	}
}

func TestAppendSymbolMatchesFlushesWhenExactBucketFillsCap(t *testing.T) {
	m := &Model{file: &binfile.File{Symbols: []binfile.Symbol{
		{Name: "needle", Addr: 0x1000},
		{Name: "needle", Addr: 0x2000},
		{Name: "needle", Addr: 0x3000},
	}}}
	seeded := make([]palettemodal.Target, gotoMaxResults-2)
	got := m.appendSymbolMatches(seeded, "needle")
	if len(got) != gotoMaxResults {
		t.Fatalf("matches after bounded append = %d, want %d", len(got), gotoMaxResults)
	}
	for i := gotoMaxResults - 2; i < gotoMaxResults; i++ {
		if got[i].Label != "needle" {
			t.Fatalf("result[%d] = %q, want needle", i, got[i].Label)
		}
	}
}

func TestStartupGotoMultipleMatchesOpensSymbols(t *testing.T) {
	m := &Model{
		theme:       DefaultTheme(),
		layoutState: layoutState{width: 120, height: 30},
		file:        &binfile.File{Symbols: []binfile.Symbol{{Name: "do_thing", Addr: 0x1000}, {Name: "do_other", Addr: 0x2000}}},
	}
	m.symbols.Filter = newPromptInput("", "/ ")
	m.symbols.Recompute(m.viewContext())
	m.gotoTargetString("do_") // two substring matches, no exact
	if m.mode != modeSymbols {
		t.Fatalf("multiple matches should open Symbols view, got mode %v", m.mode)
	}
	if got := m.symbols.Filter.Value(); got != "do_" {
		t.Fatalf("filter = %q, want do_", got)
	}
	if len(m.symbols.Filtered) != 2 {
		t.Fatalf("filtered count = %d, want 2", len(m.symbols.Filtered))
	}
}

func TestGotoTargetStringUnknownReportsError(t *testing.T) {
	m := &Model{theme: DefaultTheme(), file: &binfile.File{}}
	m.gotoTargetString("definitely_not_here_zz")
	if !m.statusError {
		t.Fatalf("unknown goto target should set an error status; got %q", m.status)
	}
}

func TestStartupGotoNavigatesAwayFromDefault(t *testing.T) {
	path := firstExisting("/bin/ls", "/usr/bin/true", "/bin/cat")
	if path == "" {
		t.Skip("no system binary available")
	}
	f, err := binfile.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	m, err := New(f, Options{Goto: fmt.Sprintf("0x%x", f.Entry())})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if m.mode == modeInfo {
		t.Fatal("startup goto to the entry point should have navigated off the Info view")
	}
}

func TestOpenSymbolFallsBackToHexWithoutDisasm(t *testing.T) {
	path := firstExisting("/bin/ls", "/usr/bin/true", "/bin/cat")
	if path == "" {
		t.Skip("no system binary available")
	}
	f, err := binfile.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	var fn binfile.Symbol
	found := false
	for _, s := range f.Symbols {
		if s.Kind == binfile.SymFunc && s.Addr != 0 {
			if _, ok := f.ExecImage().PosForAddr(s.Addr); ok {
				fn, found = s, true
				break
			}
		}
	}
	if !found {
		t.Skip("no executable function symbol")
	}

	// With a decoder for the host CPU, a function symbol opens in disasm.
	m, err := New(f)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m.openSymbol(fn)
	if m.mode != modeDisasm {
		t.Fatalf("with a disassembler, openSymbol(FUNC) mode = %v, want disasm", m.mode)
	}

	// Simulating an unsupported architecture (no decoder), the same function must
	// fall back to the hex view rather than erroring.
	m2, err := New(f)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m2.dis = nil
	m2.openSymbol(fn)
	if m2.mode != modeHex {
		t.Fatalf("without a disassembler, openSymbol(FUNC) mode = %v, want hex", m2.mode)
	}
	if m2.statusError {
		t.Fatalf("hex fallback should not set an error status; got %q", m2.status)
	}
}

func TestOpenWithMissingDebugPathStillOpens(t *testing.T) {
	path := firstExisting("/bin/ls", "/usr/bin/true", "/bin/cat")
	if path == "" {
		t.Skip("no system binary available")
	}
	// A bogus debug path must be ignored, not fatal.
	f, err := binfile.Open(path, binfile.WithDebugPath("/no/such/debug/path"))
	if err != nil {
		t.Fatalf("Open with bogus debug path: %v", err)
	}
	f.Close()
}
