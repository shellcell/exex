package ui

import (
	"testing"

	"github.com/shellcell/exex/internal/binfile"
)

// stringsModel builds a Strings-view Model whose entries point into a synthesized
// raw image, so StringText/StringBytes recover each text from its offset+length.
func stringsModel(texts ...string) *Model {
	var raw []byte
	var entries []binfile.StringEntry
	for _, txt := range texts {
		entries = append(entries, binfile.StringEntry{Offset: uint64(len(raw)), Len: uint32(len(txt))})
		raw = append(raw, txt...)
	}
	m := &Model{
		theme:       DefaultTheme(),
		file:        binfile.NewRawFile(raw),
		mode:        modeStrings,
		layoutState: layoutState{width: 100, height: 24},
	}
	m.strs.List = entries
	m.strs.Filter = newPromptInput("", "/ ")
	m.strs.Recompute(m.viewContext())
	return m
}

func TestStringsFilter(t *testing.T) {
	m := stringsModel("hello world", "goodbye", "hello again")
	if len(m.strs.Filtered) != 3 {
		t.Fatalf("unfiltered count = %d, want 3", len(m.strs.Filtered))
	}
	m.strs.Filter.SetValue("hello")
	m.strs.Recompute(m.viewContext())
	if len(m.strs.Filtered) != 2 {
		t.Fatalf("filtered count = %d, want 2", len(m.strs.Filtered))
	}
	if s, ok := m.strs.Current(); !ok || m.file.StringText(s) != "hello world" {
		t.Fatalf("current = %q (%v), want 'hello world'", m.file.StringText(s), ok)
	}
}

func TestOpenStringSearch(t *testing.T) {
	// Several matches → Strings view filtered.
	m := stringsModel("libfoo", "libbar", "zzz")
	m.mode = modeInfo
	m.openStringSearch("lib")
	if m.mode != modeStrings {
		t.Fatalf("multiple matches: mode = %v, want strings", m.mode)
	}
	if len(m.strs.Filtered) != 2 {
		t.Fatalf("multiple matches: filtered = %d, want 2", len(m.strs.Filtered))
	}

	// No match → Strings view with an error status, not a crash.
	m = stringsModel("abc")
	m.openStringSearch("nope")
	if m.mode != modeStrings || !m.statusError {
		t.Fatalf("no match: mode=%v statusError=%v", m.mode, m.statusError)
	}
}
