package ui

import "testing"

// TestJumpModalFromDisasm: the cross-view "open caret in…" modal opens on the
// disasm cursor's address, offers the other address views (not Disasm itself)
// with resolved previews, and Enter navigates to the selected target.
func TestJumpModalFromDisasm(t *testing.T) {
	h := newKeyHarness(t, systemBinary(t))
	h.goView(modeDisasm, "4")
	h.press(">")
	if !h.m().jumpActive {
		t.Fatalf("jump modal did not open from disasm; status=%q", h.m().status)
	}

	byLabel := map[string]jumpTarget{}
	for _, tg := range h.m().jumpTargets {
		byLabel[tg.label] = tg
		if tg.mode == modeDisasm {
			t.Error("jump modal offered the current (Disasm) view as a target")
		}
	}
	// Hex/Raw/Sections are reliably reachable for any mapped code caret. Symbols
	// depends on a covering symbol, which a stripped binary (e.g. Ubuntu's system
	// binaries) doesn't have — so require it only as a listed target, not enabled.
	for _, want := range []string{"Hex", "Raw", "Sections"} {
		tg, ok := byLabel[want]
		if !ok {
			t.Errorf("missing %s target", want)
			continue
		}
		if !tg.enabled || tg.preview == "" {
			t.Errorf("%s target should be enabled with a preview, got enabled=%v preview=%q", want, tg.enabled, tg.preview)
		}
	}
	if _, ok := byLabel["Symbols"]; !ok {
		t.Error("missing Symbols target")
	}

	// The selection starts on the first enabled row; Enter navigates and closes.
	h.press("enter")
	if h.m().jumpActive {
		t.Error("modal still open after Enter")
	}
	if h.m().mode == modeDisasm {
		t.Error("Enter did not navigate away from Disasm")
	}
}

// TestJumpModalDisabledRowSkipped: selection movement lands only on reachable
// targets, and Esc dismisses without navigating.
func TestJumpModalNavAndEsc(t *testing.T) {
	h := newKeyHarness(t, systemBinary(t))
	h.goView(modeDisasm, "4")
	h.press(">")
	if !h.m().jumpActive {
		t.Skip("no caret address to open from")
	}
	// Every landing the cursor stops on must be an enabled target.
	for i := 0; i < len(h.m().jumpTargets)+1; i++ {
		if tg := h.m().jumpTargets[h.m().jumpSel]; !tg.enabled {
			t.Fatalf("selection rested on a disabled target %q", tg.label)
		}
		h.press("down")
	}
	h.press("esc")
	if h.m().jumpActive {
		t.Error("Esc did not close the jump modal")
	}
	if h.m().mode != modeDisasm {
		t.Errorf("Esc navigated away: mode=%v", h.m().mode)
	}
}

// TestJumpModalFromInfo: the Info view has no cursor, so the modal opens on the
// binary's natural starting point — the entry point (or the lowest mapped address
// when there is none) — rather than reporting "no address".
func TestJumpModalFromInfo(t *testing.T) {
	h := newKeyHarness(t, systemBinary(t))
	h.goView(modeInfo, "1")
	h.press("space")
	if !h.m().jumpActive {
		t.Fatalf("modal did not open from Info; status=%q", h.m().status)
	}
	if !h.m().jumpCaret.hasAddr {
		t.Error("Info caret has no virtual address")
	}
	if entry := h.m().file.Entry(); entry != 0 && h.m().jumpCaret.addr != entry {
		t.Errorf("Info caret = 0x%x, want entry 0x%x", h.m().jumpCaret.addr, entry)
	}
	// Info is not an address view, so it isn't offered as a target.
	for _, tg := range h.m().jumpTargets {
		if tg.mode == modeInfo {
			t.Error("Info offered as a jump target")
		}
	}
}

// TestJumpModalRawStringByOffset: a Raw caret parked on a string's file offset —
// in an unmapped region with no virtual address — must still offer the Strings
// target, found by offset (regression: it used to report "nothing can open this").
func TestJumpModalRawStringByOffset(t *testing.T) {
	h := newKeyHarness(t, systemBinary(t))
	h.goView(modeStrings, "7")
	if len(h.m().strs.Filtered) == 0 {
		t.Skip("no strings")
	}
	s, _ := h.m().strs.Current()
	h.m().openRawAt(s.Offset)
	h.m().setMode(modeRaw)
	h.press("space")
	if !h.m().jumpActive {
		t.Fatalf("modal did not open from Raw; status=%q", h.m().status)
	}
	strEnabled := false
	for _, tg := range h.m().jumpTargets {
		if tg.mode == modeStrings && tg.enabled {
			strEnabled = true
		}
	}
	if !strEnabled {
		t.Error("Strings target not enabled at a string's file offset in the Raw view")
	}
	// Opening it lands in the Strings view on that string.
	h.press("7")
	if h.m().jumpActive || h.m().mode != modeStrings {
		t.Errorf("digit 7 did not open Strings: active=%v mode=%v", h.m().jumpActive, h.m().mode)
	}
}

// TestJumpModalSpaceAndDigit: space opens the modal, and a target's view digit
// jumps straight to it.
func TestJumpModalSpaceAndDigit(t *testing.T) {
	h := newKeyHarness(t, systemBinary(t))
	h.goView(modeDisasm, "4")
	h.press("space")
	if !h.m().jumpActive {
		t.Fatalf("space did not open the jump modal; status=%q", h.m().status)
	}
	// Every listed target carries its view digit; Hex (5) is always reachable from
	// a mapped code address.
	hasHex := false
	for _, tg := range h.m().jumpTargets {
		if tg.mode == modeHex && tg.enabled && modeDigit(tg.mode) == "5" {
			hasHex = true
		}
	}
	if !hasHex {
		t.Fatal("expected an enabled Hex (5) target")
	}
	h.press("5")
	if h.m().jumpActive || h.m().mode != modeHex {
		t.Errorf("digit 5 did not open Hex: active=%v mode=%v", h.m().jumpActive, h.m().mode)
	}
}

// TestJumpModalFromStrings: a string always has a file offset even when it has no
// virtual address, so the modal must open from the Strings view with Raw enabled
// (offset-addressed) — the previous behaviour reported "no address" and refused.
func TestJumpModalFromStrings(t *testing.T) {
	h := newKeyHarness(t, systemBinary(t))
	h.goView(modeStrings, "7")
	if len(h.m().strs.Filtered) == 0 {
		t.Skip("no strings")
	}
	h.press("space")
	if !h.m().jumpActive {
		t.Fatalf("space did not open the modal from Strings; status=%q", h.m().status)
	}
	if !h.m().jumpCaret.hasOff {
		t.Error("string caret has no file offset")
	}
	rawEnabled, offeredStrings := false, false
	for _, tg := range h.m().jumpTargets {
		if tg.mode == modeRaw && tg.enabled {
			rawEnabled = true
		}
		if tg.mode == modeStrings {
			offeredStrings = true // must not offer the current view
		}
	}
	if !rawEnabled {
		t.Error("Raw target not enabled from a string caret (offset is always available)")
	}
	if offeredStrings {
		t.Error("Strings offered as a target while already in the Strings view")
	}
	// Jumping to Raw lands in the Raw view.
	h.press("6")
	if h.m().jumpActive || h.m().mode != modeRaw {
		t.Errorf("digit 6 did not open Raw: active=%v mode=%v", h.m().jumpActive, h.m().mode)
	}
}
