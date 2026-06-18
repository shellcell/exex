package ui

import (
	"testing"

	"github.com/rabarbra/exex/internal/binfile"
)

func stringsModel(entries ...binfile.StringEntry) *Model {
	m := &Model{
		theme:        DefaultTheme(),
		file:         &binfile.File{},
		mode:         modeStrings,
		layoutState:  layoutState{width: 100, height: 24},
		stringsState: stringsState{stringsList: entries},
	}
	m.stringsFilter = newPromptInput("", "/ ")
	m.recomputeStrings()
	return m
}

func TestStringsFilter(t *testing.T) {
	m := stringsModel(
		binfile.StringEntry{Text: "hello world", Offset: 1},
		binfile.StringEntry{Text: "goodbye", Offset: 2},
		binfile.StringEntry{Text: "hello again", Offset: 3},
	)
	if len(m.stringsFiltered) != 3 {
		t.Fatalf("unfiltered count = %d, want 3", len(m.stringsFiltered))
	}
	m.stringsFilter.SetValue("hello")
	m.recomputeStrings()
	if len(m.stringsFiltered) != 2 {
		t.Fatalf("filtered count = %d, want 2", len(m.stringsFiltered))
	}
	if s, ok := m.currentString(); !ok || s.Text != "hello world" {
		t.Fatalf("current = %q (%v), want 'hello world'", s.Text, ok)
	}
}

func TestOpenStringSearch(t *testing.T) {
	// Several matches → Strings view filtered.
	m := stringsModel(
		binfile.StringEntry{Text: "libfoo", Offset: 1},
		binfile.StringEntry{Text: "libbar", Offset: 2},
		binfile.StringEntry{Text: "zzz", Offset: 3},
	)
	m.mode = modeInfo
	m.openStringSearch("lib")
	if m.mode != modeStrings {
		t.Fatalf("multiple matches: mode = %v, want strings", m.mode)
	}
	if len(m.stringsFiltered) != 2 {
		t.Fatalf("multiple matches: filtered = %d, want 2", len(m.stringsFiltered))
	}

	// No match → Strings view with an error status, not a crash.
	m = stringsModel(binfile.StringEntry{Text: "abc", Offset: 1})
	m.openStringSearch("nope")
	if m.mode != modeStrings || !m.statusError {
		t.Fatalf("no match: mode=%v statusError=%v", m.mode, m.statusError)
	}
}
