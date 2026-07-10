package ui

import (
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/rabarbra/exex/internal/binfile"
)

// TestTextMatcherCaseSensitivity covers the predicate shared by the disasm and
// relocation facets.
func TestTextMatcherCaseSensitivity(t *testing.T) {
	sensitive := textMatcher(findQuery{text: "Malloc", caseSensitive: true})
	if !sensitive("xMallocy") {
		t.Error("case-sensitive matcher missed an exact substring")
	}
	if sensitive("xmallocy") {
		t.Error("case-sensitive matcher folded case")
	}

	insensitive := textMatcher(findQuery{text: "Malloc"})
	if !insensitive("xmallocy") || !insensitive("xMALLOCy") {
		t.Error("case-insensitive matcher failed to fold")
	}

	if textMatcher(findQuery{})("anything") {
		t.Error("empty query matched")
	}
}

// TestBytesMatcherCaseSensitivity mirrors the above for the strings facet.
// findStringsCmd used to run the fold path over every string in the binary and
// then overwrite the result when the query was case-sensitive — which every
// seed-driven search is.
func TestBytesMatcherCaseSensitivity(t *testing.T) {
	sensitive := bytesMatcher(findQuery{text: "Malloc", caseSensitive: true})
	if !sensitive([]byte("xMallocy")) {
		t.Error("case-sensitive matcher missed an exact substring")
	}
	if sensitive([]byte("xmallocy")) {
		t.Error("case-sensitive matcher folded case")
	}

	insensitive := bytesMatcher(findQuery{text: "Malloc"})
	if !insensitive([]byte("xmallocy")) || !insensitive([]byte("xMALLOCy")) {
		t.Error("case-insensitive matcher failed to fold")
	}

	if bytesMatcher(findQuery{})([]byte("anything")) {
		t.Error("empty query matched")
	}
}

// TestRelocSymbolMatchIsSubstring pins the findRelocsCmd fix. The relocation
// facet compared with `==`, so a search for "malloc" never surfaced the
// relocation binding "malloc@GLIBC_2.2.5" even though the disasm, data and
// strings facets all matched it.
func TestRelocSymbolMatchIsSubstring(t *testing.T) {
	match := textMatcher(findQuery{text: "malloc", caseSensitive: true})
	for _, sym := range []string{"malloc", "malloc@GLIBC_2.2.5", "_malloc", "__libc_malloc"} {
		if !match(sym) {
			t.Errorf("reloc symbol %q did not match query %q", sym, "malloc")
		}
	}
	if match("calloc") {
		t.Error("unrelated symbol matched")
	}
}

// collectFacet runs one facet's command and returns its hits.
func collectFacet(t *testing.T, cmd tea.Cmd) []findHit {
	t.Helper()
	msg, ok := cmd().(findPartialMsg)
	if !ok {
		t.Fatalf("facet command returned %T, want findPartialMsg", msg)
	}
	return msg.hits
}

// TestFindDataCapIsPerFacet: findMaxPerFacet counts the facet, not each pattern.
// findDataCmd reset the counter per pattern, so an address+text query could
// return twice the documented cap.
func TestFindDataCapIsPerFacet(t *testing.T) {
	path := firstExisting("/bin/ls", "/usr/bin/true", "/bin/cat")
	if path == "" {
		t.Skip("no system binary available")
	}
	f, err := binfile.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	m := newTestModel(t, f)

	// Both patterns run: a zero pointer word and a single NUL byte, each of which
	// occurs far more than findMaxPerFacet times in any real binary.
	q := findQuery{label: "cap", addr: 0, hasAddr: true, text: "\x00", caseSensitive: true}
	hits := collectFacet(t, m.findDataCmd(q, 1, nil))
	if len(hits) > findMaxPerFacet {
		t.Errorf("data facet returned %d hits, cap is %d", len(hits), findMaxPerFacet)
	}
	if len(hits) != findMaxPerFacet {
		t.Errorf("expected the scan to saturate the cap, got %d hits", len(hits))
	}
}

// TestFindDisasmCapIsApplied: the disasm facet never applied findMaxPerFacet at
// all — it returned whatever the (then unbounded) scan collected.
func TestFindDisasmCapIsApplied(t *testing.T) {
	path := firstExisting("/bin/ls", "/usr/bin/true", "/bin/cat")
	if path == "" {
		t.Skip("no system binary available")
	}
	f, err := binfile.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	m := newTestModel(t, f)
	m.disasmMaxBytes = 1 << 20

	// A substring present in essentially every instruction stream.
	hits := collectFacet(t, m.findDisasmCmd(findQuery{label: "e", text: "e"}, 1, nil))
	if len(hits) > findMaxPerFacet {
		t.Errorf("disasm facet returned %d hits, cap is %d", len(hits), findMaxPerFacet)
	}
}
