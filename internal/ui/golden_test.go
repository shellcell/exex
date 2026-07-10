package ui

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/config"
	"github.com/rabarbra/exex/internal/dump"
	"github.com/rabarbra/exex/internal/testbin"
)

// Golden-frame tests.
//
// Every view and every modal is rendered at a fixed size against a fixed binary
// (internal/testbin's hand-built ELF, byte-identical on every machine) and the
// full ANSI frame is compared to a committed snapshot.
//
// These exist for the refactor: moving a view or a modal out of the shell must
// produce byte-identical frames. "It renders without panicking and the output is
// non-empty" — which is all the existing smoke tests assert — would not notice a
// row rendered one line off, a lost colour role, or a dropped column.
//
// Regenerate after an intended visual change, and read the diff. Both build
// variants have their own snapshots (see golden_variant_test.go):
//
//	go test ./internal/ui/ -run TestGolden -update
//	go test -tags lite ./internal/ui/ -run TestGolden -update

var updateGolden = flag.Bool("update", false, "rewrite the golden frame snapshots")

const (
	goldenWidth  = 100
	goldenHeight = 30
)

// goldenFixture writes the fixture to a fixed *relative* path and returns it.
//
// The path matters: the Info view renders it, so a t.TempDir() path would bake a
// random directory into every frame. A relative path under testdata renders the
// same everywhere. The file is regenerated each run, so it is derived state and
// need not be committed.
func goldenFixture(t *testing.T) string {
	t.Helper()
	const path = "testdata/tiny.elf"
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, testbin.TinyELF64(), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// goldenModel builds the model every frame is rendered from: fixed binary, fixed
// terminal size, fixed theme, no config overrides.
func goldenModel(t *testing.T) *Model {
	t.Helper()
	f, err := binfile.Open(goldenFixture(t))
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	t.Cleanup(func() { f.Close() })

	m, err := New(f)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m.resize(goldenWidth, goldenHeight)
	m.cfg = config.Config{Theme: defaultThemeName}
	m.applyThemeChange()
	return m
}

// enterMode switches to a view and drains the commands it returns.
//
// Without the drain, Disasm snapshots as "decoding instructions…" — its decode
// runs as a tea.Cmd — which would make the golden frame for the single most
// complex view a picture of its loading state.
func enterMode(t *testing.T, m *Model, md mode) {
	t.Helper()
	runModelCmd(t, m, m.switchMode(md))
}

// frame renders the current model state the way the event loop does, and returns
// the exact string View() would put on the terminal.
func frame(m *Model) string {
	m.viewDirty = true
	m.View()
	return m.viewCache
}

// goldenViews renders each top-level view.
func goldenViews(t *testing.T) map[string]string {
	t.Helper()
	frames := map[string]string{}
	for _, md := range []mode{
		modeInfo, modeSections, modeSymbols, modeDisasm, modeHex,
		modeLibs, modeRaw, modeStrings, modeSources, modeRelocs,
	} {
		m := goldenModel(t)
		enterMode(t, m, md)
		frames["view_"+strings.ToLower(md.String())] = frame(m)
	}
	return frames
}

// goldenModals renders each overlay. The scan-backed modals (xref, syscalls,
// cpu-features) are opened with injected results rather than by running their
// background scans, so the frames stay deterministic and the test stays fast.
func goldenModals(t *testing.T) map[string]string {
	t.Helper()
	cases := []struct {
		name string
		open func(*Model)
	}{
		{"help", func(m *Model) { m.helpActive = true }},
		{"header", func(m *Model) { m.headerActive = true }},
		{"settings", func(m *Model) { m.openSettings() }},
		// Field 14 scrolls the list so its window starts on a group header, which
		// is the one row whose leading blank separator is suppressed. Nothing else
		// exercises that branch.
		{"settings_scrolled", func(m *Model) {
			m.openSettings()
			m.settings.SetCur(14)
		}},
		{"goto", func(m *Model) {
			m.gotoActive = true
			m.gotoInput.Focus()
			m.recomputeGoto()
		}},
		{"search", func(m *Model) { m.openSearch() }},
		{"find_query", func(m *Model) { m.openFindQuery() }},
		{"find_seeds", func(m *Model) {
			enterMode(t, m, modeSymbols)
			m.openFindModal()
		}},
		{"jump", func(m *Model) {
			enterMode(t, m, modeDisasm)
			m.openJumpModal()
		}},
		{"xref", func(m *Model) {
			enterMode(t, m, modeDisasm)
			m.xrefLabel = "helper"
			m.xrefTarget = 0x401020
			m.openXrefResults([]xrefHit{
				{addr: 0x401000, text: "mov rax, 1", sym: "_start"},
				{addr: 0x40100e, text: "call 0x401020", sym: "_start"},
			})
		}},
		// A populated set, so the frame covers the row layout (name padding, count
		// column, first-use address) and the selection bar — not just the
		// "no optional features detected" branch an empty set would render.
		{"cpufeatures", func(m *Model) {
			m.cpufeat.Open(dump.CPUFeatureSet{
				Total:    12345,
				Baseline: "x86-64-v3",
				Counts:   map[string]int{"AVX": 42, "SSE2": 7, "AVX512F": 1, "BMI2": 300},
				FirstUse: map[string]uint64{"AVX": 0x401000, "SSE2": 0x401020, "AVX512F": 0x4010ff, "BMI2": 0x402000},
			})
		}},
		{"cpufeatures_empty", func(m *Model) { m.cpufeat.Open(dump.CPUFeatureSet{Total: 99}) }},
		{"syscalls", func(m *Model) {
			enterMode(t, m, modeDisasm)
			m.openSyscallResults([]dump.SyscallSite{
				{Addr: 0x401013, Num: 1, Name: "write", Sym: "_start"},
			})
		}},
	}

	frames := map[string]string{}
	for _, tc := range cases {
		m := goldenModel(t)
		tc.open(m)
		frames["modal_"+tc.name] = frame(m)
	}
	return frames
}

// TestGoldenFramesAreDeterministic guards the guard: a frame that varies between
// renders of identical state would make every golden comparison a coin flip
// (map iteration order in a render path, a timestamp, a cached-style race).
func TestGoldenFramesAreDeterministic(t *testing.T) {
	for name, got := range allGoldenFrames(t) {
		if want := allGoldenFrames(t)[name]; got != want {
			t.Errorf("%s: frame differs between two renders of identical state", name)
		}
	}
}

func allGoldenFrames(t *testing.T) map[string]string {
	t.Helper()
	frames := goldenViews(t)
	for k, v := range goldenModals(t) {
		frames[k] = v
	}
	return frames
}

func TestGoldenFrames(t *testing.T) {
	frames := allGoldenFrames(t)
	if len(frames) == 0 {
		t.Fatal("no frames rendered")
	}
	dir := filepath.Join("testdata", goldenVariant)
	if *updateGolden {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, got := range frames {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name+".frame")
			if *updateGolden {
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("missing golden frame; run: go test ./internal/ui/ -run TestGolden -update\n%v", err)
			}
			if got != string(want) {
				t.Errorf("frame changed.\n%s", frameDiff(string(want), got))
			}
		})
	}
}

// frameDiff reports the first differing line with its escapes made visible, plus
// the line counts — enough to tell "a row moved" from "a colour changed".
func frameDiff(want, got string) string {
	wl, gl := strings.Split(want, "\n"), strings.Split(got, "\n")
	var b strings.Builder
	if len(wl) != len(gl) {
		b.WriteString("line count: want ")
		b.WriteString(itoa(len(wl)))
		b.WriteString(", got ")
		b.WriteString(itoa(len(gl)))
		b.WriteString("\n")
	}
	for i := 0; i < len(wl) && i < len(gl); i++ {
		if wl[i] != gl[i] {
			b.WriteString("first diff at line ")
			b.WriteString(itoa(i + 1))
			b.WriteString("\n  want: ")
			b.WriteString(visible(wl[i]))
			b.WriteString("\n  got:  ")
			b.WriteString(visible(gl[i]))
			b.WriteString("\n")
			break
		}
	}
	b.WriteString("\nrun `go test ./internal/ui/ -run TestGolden -update` if the change is intended")
	return b.String()
}

// visible replaces ESC with a printable marker so a colour-only diff is legible.
func visible(s string) string { return strings.ReplaceAll(s, "\x1b", "^[") }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
