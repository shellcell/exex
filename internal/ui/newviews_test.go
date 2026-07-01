package ui

import (
	"strings"
	"testing"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/dump"
)

// TestSectionsHeaderMode cycles the Sections view's `t` toggle to the raw-header
// mode and checks the field table renders with real fields.
func TestSectionsHeaderMode(t *testing.T) {
	h := newKeyHarness(t, systemBinary(t))
	h.goView(modeSections, "2")
	// The raw header is now a ⇧H overlay (not a Sections sub-mode).
	h.press("H")
	if !h.m().headerActive {
		t.Fatalf("H did not open the raw-header overlay")
	}
	out := h.m().renderHeaderModal()
	if h.m().file.Format == binfile.FormatELF && !strings.Contains(out, "Machine") {
		t.Errorf("ELF header overlay missing Machine field:\n%s", out)
	}
	// Any non-scroll key closes it.
	h.press("esc")
	if h.m().headerActive {
		t.Fatal("esc did not close the header overlay")
	}
}

// TestLibsRelocsMode cycles the Libraries view's `t` toggle to the relocation
// table and exercises filter + navigation without panicking (pump renders).
func TestLibsRelocsMode(t *testing.T) {
	h := newKeyHarness(t, systemBinary(t))
	// Relocations are now their own top-level view (key 0).
	h.goView(modeRelocs, "0")
	out := h.m().renderRelocs()
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
	full := len(h.m().relocFiltered)
	h.press("/")
	for _, r := range "JUMP" {
		h.press(string(r))
	}
	if h.m().relocFilter.Value() == "" {
		t.Error("relocs filter did not capture typed text")
	}
	if h.m().libsFilter.Value() != "" {
		t.Errorf("relocs filter leaked into libs filter: %q", h.m().libsFilter.Value())
	}
	if len(h.m().relocFiltered) > full {
		t.Errorf("filter grew the list: %d -> %d", full, len(h.m().relocFiltered))
	}
	h.press("esc") // clear filter
	if h.m().relocFilter.Value() != "" {
		t.Errorf("esc did not clear relocs filter: %q", h.m().relocFilter.Value())
	}

	// s cycles the sort field; r reverses it.
	srt0 := h.m().relocSort
	h.press("s")
	if h.m().relocSort == srt0 {
		t.Error("s did not change the relocation sort field")
	}
	desc0 := h.m().relocSortDesc
	h.press("r")
	if h.m().relocSortDesc == desc0 {
		t.Error("r did not reverse the relocation sort")
	}
}

// TestSyscallRowsScopes checks the modal's scope views: function, whole binary
// and unique (with counts).
func TestSyscallRowsScopes(t *testing.T) {
	m := &Model{}
	m.syscallFnLo, m.syscallFnHi = 0x1000, 0x1100
	m.syscallResults = []dump.SyscallSite{
		{Addr: 0x1010, Num: 1, HasNum: true, Text: "syscall"},  // in func
		{Addr: 0x1020, Num: 1, HasNum: true, Text: "syscall"},  // in func, same num
		{Addr: 0x2000, Num: 60, HasNum: true, Text: "syscall"}, // outside
	}

	m.syscallScope = sysScopeFunc
	m.rebuildSyscallRows()
	if len(m.syscallShown) != 2 {
		t.Errorf("function scope = %d rows, want 2", len(m.syscallShown))
	}

	m.syscallScope = sysScopeAll
	m.rebuildSyscallRows()
	if len(m.syscallShown) != 3 {
		t.Errorf("all scope = %d rows, want 3", len(m.syscallShown))
	}

	m.syscallScope = sysScopeUnique
	m.rebuildSyscallRows()
	if len(m.syscallShown) != 2 {
		t.Fatalf("unique scope = %d rows, want 2 (#1, #60)", len(m.syscallShown))
	}
	// #1 appears twice; the unique row should carry that count.
	for _, r := range m.syscallShown {
		if r.site.Num == 1 && r.count != 2 {
			t.Errorf("unique count for #1 = %d, want 2", r.count)
		}
	}

	// Full scope aggregates the separate full result set (binary + libs), tagging
	// origin.
	m.syscallFull = []dump.SyscallSite{
		{Num: 1, HasNum: true, Text: "syscall", Origin: "this binary"},
		{Num: 2, HasNum: true, Text: "syscall", Origin: "libc.so.6"},
		{Num: 2, HasNum: true, Text: "syscall", Origin: "libc.so.6"},
	}
	m.syscallScope = sysScopeFull
	m.rebuildSyscallRows()
	if len(m.syscallShown) != 2 {
		t.Fatalf("full scope = %d rows, want 2", len(m.syscallShown))
	}
	for _, r := range m.syscallShown {
		if r.site.Num == 2 && (r.count != 2 || r.site.Origin != "libc.so.6") {
			t.Errorf("full #2 = count %d origin %q, want 2 / libc.so.6", r.count, r.site.Origin)
		}
	}
}
