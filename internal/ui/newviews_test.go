package ui

import (
	"strings"
	"testing"

	"github.com/shellcell/exex/internal/binfile"
)

// TestSectionsHeaderMode cycles the Sections view's `t` toggle to the raw-header
// mode and checks the field table renders with real fields.
func TestSectionsHeaderMode(t *testing.T) {
	h := newKeyHarness(t, systemBinary(t))
	h.goView(modeSections, "2")
	// The raw header is now a ⇧H overlay (not a Sections sub-mode).
	h.press("H")
	if !h.m().header.Active() {
		t.Fatalf("H did not open the raw-header overlay")
	}
	out := h.m().header.Render(h.m().modalContext())
	if h.m().file.Format == binfile.FormatELF && !strings.Contains(out, "Machine") {
		t.Errorf("ELF header overlay missing Machine field:\n%s", out)
	}
	// Any non-scroll key closes it.
	h.press("esc")
	if h.m().header.Active() {
		t.Fatal("esc did not close the header overlay")
	}
}

// TestLibsRelocsMode cycles the Libraries view's `t` toggle to the relocation
// table and exercises filter + navigation without panicking (pump renders).
func TestLibsRelocsMode(t *testing.T) {
	h := newKeyHarness(t, systemBinary(t))
	// Relocations are now their own top-level view (key 0).
	h.goView(modeRelocs, "0")
	out := h.m().relocs.Render(h.m().viewContext(), h.m())
	if len(h.m().file.Relocations()) == 0 {
		// No decoded relocations (e.g. a Mach-O using dyld chained fixups): the view
		// shows a clean centred message with no table header, like other empty views.
		if strings.Contains(out, "Offset") {
			t.Errorf("empty relocs view should have no table header:\n%s", out)
		}
		if !strings.Contains(out, "No relocations") {
			t.Errorf("empty relocs view missing its message:\n%s", out)
		}
		return
	}
	if !strings.Contains(out, "Offset") {
		t.Errorf("relocs view missing header:\n%s", out)
	}
	// Filtering by type substring narrows the list.
	full := len(h.m().relocs.Filtered)
	h.press("/")
	for _, r := range "JUMP" {
		h.press(string(r))
	}
	if h.m().relocs.Filter.Value() == "" {
		t.Error("relocs filter did not capture typed text")
	}
	if h.m().libs.Filter.Value() != "" {
		t.Errorf("relocs filter leaked into libs filter: %q", h.m().libs.Filter.Value())
	}
	if len(h.m().relocs.Filtered) > full {
		t.Errorf("filter grew the list: %d -> %d", full, len(h.m().relocs.Filtered))
	}
	h.press("esc") // clear filter
	if h.m().relocs.Filter.Value() != "" {
		t.Errorf("esc did not clear relocs filter: %q", h.m().relocs.Filter.Value())
	}

	// s cycles the sort field; r reverses it.
	srt0 := h.m().relocs.Sort
	h.press("s")
	if h.m().relocs.Sort == srt0 {
		t.Error("s did not change the relocation sort field")
	}
	desc0 := h.m().relocs.SortDesc
	h.press("r")
	if h.m().relocs.SortDesc == desc0 {
		t.Error("r did not reverse the relocation sort")
	}
}

// TestRelocsViewKeys exercises the relocs view's shared navigation surface: the
// `e` argument-abbreviation toggle (its bind targets are demangled symbol names,
// like Symbols/disasm) and the d/h/m jumps to the patched address.
func TestRelocsViewKeys(t *testing.T) {
	h := newKeyHarness(t, systemBinary(t))
	h.goView(modeRelocs, "0")
	if len(h.m().file.Relocations()) == 0 {
		t.Skip("no decoded relocations to navigate")
	}

	// `e` flips the global argument-abbreviation state (shared with Symbols/disasm)
	// and must not leave the relocs view.
	abbrev0 := h.m().symbols.Abbrev
	h.press("e")
	if h.m().symbols.Abbrev == abbrev0 {
		t.Error("e did not toggle argument abbreviation from the relocs view")
	}
	if h.m().mode != modeRelocs {
		t.Errorf("e left the relocs view: mode = %v", h.m().mode)
	}
	h.press("e") // toggle back

	// d/h/m jump to the patched address in the disasm/hex/raw views.
	for key, want := range map[string]mode{"h": modeHex, "m": modeRaw} {
		h.goView(modeRelocs, "0")
		h.press(key)
		if h.m().mode != want {
			t.Errorf("relocs %q: mode = %v, want %v", key, h.m().mode, want)
		}
	}
}
