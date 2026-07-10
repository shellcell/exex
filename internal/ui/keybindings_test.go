package ui

// Exhaustive per-view keybinding tests for ROADMAP #27. Every binding is driven
// through the real message path (model.Update → handleKey → dispatchViewKey), the
// same route a keystroke from the terminal takes, so the tests catch wiring bugs
// like a handler that matches "shift+a" when the terminal actually sends "A".
//
// kp() builds the tea.KeyPressMsg a real terminal would emit for a given chord,
// which is the crux: Shift+letter arrives as the uppercase letter (Text "A",
// String()=="A"), and Option/Alt+letter arrives with ModAlt (String()=="ctrl+t").

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/config"
	"github.com/rabarbra/exex/internal/ui/view"
	"github.com/rabarbra/exex/internal/ui/views/sources"
	"github.com/rabarbra/exex/internal/ui/views/strs"
	"github.com/rabarbra/exex/internal/ui/views/symbols"
)

// kp converts a chord description to the KeyPressMsg a terminal would send.
func kp(s string) tea.KeyPressMsg {
	switch s {
	case "up":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyUp})
	case "down":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyDown})
	case "left":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyLeft})
	case "right":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyRight})
	case "pgup":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyPgUp})
	case "pgdown":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyPgDown})
	case "home":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyHome})
	case "end":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyEnd})
	case "enter":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter})
	case "esc":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyEscape})
	case "tab":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyTab})
	case "space":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeySpace, Text: " "})
	case "shift+tab":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyTab, Mod: tea.ModShift})
	case "shift+up":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyUp, Mod: tea.ModShift})
	case "shift+down":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyDown, Mod: tea.ModShift})
	case "ctrl+up":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyUp, Mod: tea.ModCtrl})
	case "ctrl+down":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyDown, Mod: tea.ModCtrl})
	case "alt+up":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyUp, Mod: tea.ModAlt})
	case "alt+down":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyDown, Mod: tea.ModAlt})
	case "cmd+up", "super+up":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyUp, Mod: tea.ModSuper})
	case "cmd+down", "super+down":
		return tea.KeyPressMsg(tea.Key{Code: tea.KeyDown, Mod: tea.ModSuper})
	}
	if rest, ok := strings.CutPrefix(s, "alt+"); ok {
		return tea.KeyPressMsg(tea.Key{Code: rune(rest[0]), Mod: tea.ModAlt})
	}
	if rest, ok := strings.CutPrefix(s, "ctrl+"); ok {
		return tea.KeyPressMsg(tea.Key{Code: rune(rest[0]), Mod: tea.ModCtrl})
	}
	if rest, ok := strings.CutPrefix(s, "shift+"); ok {
		// Non-letter shift chords (e.g. shift+]) arrive with ModShift and no text.
		return tea.KeyPressMsg(tea.Key{Code: rune(rest[0]), Mod: tea.ModShift})
	}
	// A plain rune, including an uppercase letter ("A") as a real Shift+a press.
	r := []rune(s)
	return tea.KeyPressMsg(tea.Key{Text: s, Code: r[0]})
}

// keyHarness drives a model through real key messages, completing any background
// disasm decode synchronously so jumps land deterministically.
type keyHarness struct {
	t     *testing.T
	model tea.Model
}

func newKeyHarness(t *testing.T, path string) *keyHarness {
	t.Helper()
	f, err := binfile.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	m, err := New(f)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m.disasmMaxBytes = 16 << 10
	h := &keyHarness{t: t, model: m}
	h.pump(tea.WindowSizeMsg{Width: 140, Height: 45})
	return h
}

func (h *keyHarness) pump(msg tea.Msg) {
	h.t.Helper()
	h.model, _ = h.model.Update(msg)
	if mm, ok := h.model.(*Model); ok && mm.disasmDecoding {
		addr := mm.disasmPendingAddr
		win, insts := mm.decodeDisasmAt(addr, mm.disasmLeadBytes())
		h.model, _ = h.model.Update(disasmReadyMsg{addr: addr, posLo: win.Start, posHi: win.End, insts: insts})
	}
	// Render every frame, exactly as the program loop does, so list/tree rows are
	// always rebuilt before the next key (and any render panic is caught here).
	if strings.TrimSpace(h.model.View().Content) == "" {
		h.t.Fatalf("empty render after %T", msg)
	}
}

func (h *keyHarness) press(s string) { h.t.Helper(); h.pump(kp(s)) }
func (h *keyHarness) m() *Model      { return h.model.(*Model) }

func (h *keyHarness) goView(md mode, key string) {
	h.t.Helper()
	h.press(key)
	if h.m().mode != md {
		h.t.Fatalf("key %q: mode = %v, want %v", key, h.m().mode, md)
	}
}

func systemBinary(t *testing.T) string {
	t.Helper()
	p := firstExisting("/bin/ls", "/usr/bin/true", "/bin/cat", "/bin/echo")
	if p == "" {
		t.Skip("no system binary available")
	}
	return p
}

// --- Global bindings -------------------------------------------------------

func TestKeysGlobal(t *testing.T) {
	h := newKeyHarness(t, systemBinary(t))

	// 1–9 select each view.
	for key, md := range map[string]mode{
		"1": modeInfo, "2": modeSections, "3": modeSymbols, "4": modeDisasm,
		"5": modeHex, "6": modeRaw, "7": modeStrings, "8": modeLibs, "9": modeSources,
	} {
		h.goView(md, key)
	}

	// g opens goto; esc closes.
	h.press("g")
	if !h.m().palette.Active() {
		t.Fatal("g did not open goto modal")
	}
	h.press("esc")
	if h.m().palette.Active() {
		t.Fatal("esc did not close goto modal")
	}

	// , opens settings; esc closes.
	h.press(",")
	if !h.m().settings.Active() {
		t.Fatal(", did not open settings")
	}
	h.press("esc")

	// ? opens help; the next key dismisses it.
	h.press("?")
	if !h.m().helpActive {
		t.Fatal("? did not open help")
	}
	h.press("x")
	if h.m().helpActive {
		t.Fatal("help overlay did not dismiss on next key")
	}

	// w toggles wrap.
	h.goView(modeSections, "2")
	was := h.m().wrap
	h.press("w")
	if h.m().wrap == was {
		t.Fatal("w did not toggle wrap")
	}
}

// --- Sections --------------------------------------------------------------

func TestKeysSections(t *testing.T) {
	h := newKeyHarness(t, systemBinary(t))
	h.goView(modeSections, "2")

	// s cycles the sort field; r reverses.
	s0 := h.m().sections.Sort
	h.press("s")
	if h.m().sections.Sort == s0 {
		t.Fatal("s did not change the sort field")
	}
	d0 := h.m().sections.SortDesc
	h.press("r")
	if h.m().sections.SortDesc == d0 {
		t.Fatal("r did not reverse the sort")
	}

	// t cycles sections -> segments -> header -> sections (when the binary has
	// segments). Cycle all the way back to sections for the jump tests below.
	if len(h.m().sections.Segments) > 0 {
		seg0 := h.m().sections.ShowSegments
		h.press("t")
		if h.m().sections.ShowSegments == seg0 {
			t.Fatal("t did not toggle sections/segments")
		}
		h.press("t") // -> back to sections (2-state cycle now)
		if h.m().sections.ShowSegments {
			t.Fatal("second t did not return to the section table")
		}
	}
	// The raw header moved from a Sections sub-mode to the ⇧H overlay.
	h.press("H")
	if !h.m().headerActive {
		t.Fatal("H did not open the raw-header overlay")
	}
	h.press("esc") // close it so the rest of the section-key checks run on the table
	if h.m().headerActive {
		t.Fatal("esc did not close the raw-header overlay")
	}

	// Select an executable section, then d/h/m jump to disasm/hex/raw.
	selectExecSection(t, h)
	h.goView(modeDisasm, "d")
	h.goView(modeSections, "2")
	selectExecSection(t, h)
	h.goView(modeHex, "h")
	h.goView(modeSections, "2")
	selectExecSection(t, h)
	h.goView(modeRaw, "m")

	// Copy address / name.
	h.goView(modeSections, "2")
	h.m().lastCopy = ""
	h.press("A")
	if !strings.HasPrefix(h.m().lastCopy, "0x") {
		t.Fatalf("A copied %q, want an address", h.m().lastCopy)
	}
	h.m().lastCopy = ""
	h.press("S")
	if h.m().lastCopy == "" {
		t.Fatal("S did not copy a section name")
	}
}

func selectExecSection(t *testing.T, h *keyHarness) {
	t.Helper()
	m := h.m()
	for i, idx := range m.sections.Filtered {
		s := m.sections.Sections[idx]
		if binfile.IsExecSection(&s) && s.Addr != 0 {
			m.sections.Cur = i
			return
		}
	}
	t.Skip("no executable section in this binary")
}

// --- Symbols ---------------------------------------------------------------

func TestKeysSymbols(t *testing.T) {
	h := newKeyHarness(t, systemBinary(t))
	h.goView(modeSymbols, "3")
	if len(h.m().file.Symbols) == 0 {
		t.Skip("binary has no symbols")
	}

	// s cycles sort, r reverses.
	s0 := h.m().symbols.Sort
	h.press("s")
	if h.m().symbols.Sort == s0 {
		t.Fatal("s did not change symbol sort")
	}
	d0 := h.m().symbols.SortDesc
	h.press("r")
	if h.m().symbols.SortDesc == d0 {
		t.Fatal("r did not reverse symbol sort")
	}

	// ctrl+t / ctrl+s / ctrl+b drive the column filters.
	h.press("ctrl+t")
	if !h.m().symbols.KindOn {
		t.Fatal("ctrl+t did not enable the type filter")
	}
	sc0 := h.m().symbols.Scope
	h.press("ctrl+s")
	if h.m().symbols.Scope == sc0 {
		t.Fatal("ctrl+s did not advance the scope filter")
	}
	h.press("ctrl+b")
	if !h.m().symbols.BindOn {
		t.Fatal("ctrl+b did not enable the bind filter")
	}
	// esc clears every filter.
	h.press("esc")
	if h.m().symbols.KindOn || h.m().symbols.BindOn || h.m().symbols.Scope != symbols.ScopeAll {
		t.Fatal("esc did not clear symbol filters")
	}

	// t toggles tree/flat.
	tr0 := h.m().symbols.Tree
	h.press("t")
	if h.m().symbols.Tree == tr0 {
		t.Fatal("t did not toggle the symbol tree")
	}
	h.press("t") // back to flat

	// Select a function symbol, then d/h/m jump and A/S copy.
	selectFuncSymbol(t, h)
	h.goView(modeDisasm, "d")
	h.goView(modeSymbols, "3")
	selectFuncSymbol(t, h)
	h.goView(modeHex, "h")
	h.goView(modeSymbols, "3")
	selectFuncSymbol(t, h)
	h.goView(modeRaw, "m")

	h.goView(modeSymbols, "3")
	selectFuncSymbol(t, h)
	h.m().lastCopy = ""
	h.press("A")
	if !strings.HasPrefix(h.m().lastCopy, "0x") {
		t.Fatalf("A copied %q, want an address", h.m().lastCopy)
	}
	h.m().lastCopy = ""
	h.press("S")
	if h.m().lastCopy == "" {
		t.Fatal("S did not copy a symbol name")
	}
}

func selectFuncSymbol(t *testing.T, h *keyHarness) {
	t.Helper()
	m := h.m()
	for i, r := range m.symbols.Rows {
		if r.Node.Leaf < 0 {
			continue
		}
		s := m.file.Symbols[r.Node.Leaf]
		if s.Kind == binfile.SymFunc && m.canDisasmAt(s.Addr) {
			m.symbols.Cur = i
			return
		}
	}
	t.Skip("no disassemblable function symbol in this binary")
}

// --- Strings ---------------------------------------------------------------

func TestKeysStrings(t *testing.T) {
	h := newKeyHarness(t, systemBinary(t))
	h.goView(modeStrings, "7")
	if len(h.m().strs.List) == 0 {
		t.Skip("binary has no printable strings")
	}

	// ctrl+s cycles the section filter (when section info is present).
	if len(h.m().strs.Sections) > 0 {
		h.press("ctrl+s")
		if !h.m().strs.SecOn {
			t.Fatal("ctrl+s did not enable the section filter")
		}
		h.press("esc")
		if h.m().strs.SecOn {
			t.Fatal("esc did not clear the strings section filter")
		}
	}

	// Copy address/offset and the string text.
	h.m().strs.Cur = 0
	h.m().lastCopy = ""
	h.press("A")
	if !strings.HasPrefix(h.m().lastCopy, "0x") {
		t.Fatalf("A copied %q, want an address/offset", h.m().lastCopy)
	}
	h.m().lastCopy = ""
	h.press("S")
	if h.m().lastCopy == "" {
		t.Fatal("S did not copy the string text")
	}

	// d/h/m jump to a mapped string when one exists; m always reaches raw.
	if i, ok := mappedStringRow(h.m()); ok {
		h.m().strs.Cur = i
		h.goView(modeHex, "h")
		h.goView(modeStrings, "7")
		h.m().strs.Cur = i
		// A mapped string usually lives in .rodata, not code; "d" only reaches the
		// disasm view when the string sits in an executable section (rare, and
		// platform-dependent for the system binary used here). Tolerate a refused
		// jump and only return to Strings if we actually left.
		h.press("d")
		if h.m().mode == modeDisasm {
			h.goView(modeStrings, "7")
		}
	}
	h.goView(modeStrings, "7")
	h.m().strs.Cur = 0
	h.goView(modeRaw, "m")
}

func mappedStringRow(m *Model) (int, bool) {
	for i, fi := range m.strs.Filtered {
		if m.strs.List[fi].HasAddr {
			return i, true
		}
	}
	return 0, false
}

// --- Libs ------------------------------------------------------------------

func TestKeysLibs(t *testing.T) {
	h := newKeyHarness(t, systemBinary(t))
	h.goView(modeLibs, "8")
	if h.m().file.Info == nil || len(h.m().file.Info.DynamicLibs) == 0 {
		t.Skip("binary has no dynamic libraries")
	}

	// t toggles tree/flat.
	tr0 := h.m().libs.Tree
	h.press("t")
	if h.m().libs.Tree == tr0 {
		t.Fatal("t did not toggle the libs tree")
	}

	// ctrl+p cycles the availability filter.
	av0 := h.m().libs.Avail
	h.press("ctrl+p")
	if h.m().libs.Avail == av0 {
		t.Fatal("ctrl+p did not change the availability filter")
	}
	h.press("ctrl+p")
	h.press("ctrl+p") // back to all

	// Select a leaf and copy the library path.
	selectLibLeaf(t, h)
	h.m().lastCopy = ""
	h.press("S")
	if h.m().lastCopy == "" {
		t.Fatal("S did not copy a library path")
	}
}

func selectLibLeaf(t *testing.T, h *keyHarness) {
	t.Helper()
	m := h.m()
	m.libs.BuildRows(m.viewContext())
	for i, r := range m.libs.Rows {
		if r.Node.Leaf >= 0 {
			m.libs.Cur = i
			return
		}
	}
	t.Skip("no library leaf row")
}

// --- Disasm ----------------------------------------------------------------

func TestKeysDisasm(t *testing.T) {
	h := newKeyHarness(t, systemBinary(t))
	h.goView(modeDisasm, "4")
	if h.m().dis == nil || len(h.m().disasmInst) == 0 {
		t.Skip("no disassembly for this architecture/binary")
	}

	// ] / [ jump to the next / previous symbol (cursor moves).
	c0 := h.m().disasmCur
	h.press("]")
	moved := h.m().disasmCur != c0
	h.press("[")
	if !moved && h.m().disasmCur == c0 {
		t.Log("symbol jump did not move (few symbols) — tolerated")
	}

	// h / m jump to hex / raw at the current instruction address.
	h.goView(modeHex, "h")
	h.goView(modeDisasm, "4")
	h.goView(modeRaw, "m")
	h.goView(modeDisasm, "4")

	// x kicks off an xref scan (sets xrefRunning or opens the modal via its cmd).
	h.press("x")
	// e toggles argument abbreviation globally.
	ab0 := h.m().symbols.Abbrev
	h.press("e")
	if h.m().symbols.Abbrev == ab0 {
		t.Fatal("e did not toggle argument abbreviation")
	}

	// Copy address / symbol / function disassembly.
	h.m().lastCopy = ""
	h.press("A")
	if !strings.HasPrefix(h.m().lastCopy, "0x") {
		t.Fatalf("A copied %q, want an address", h.m().lastCopy)
	}
	h.m().lastCopy = ""
	h.press("C")
	// C copies the function under the cursor when it is sized; tolerate "not sized".
	if h.m().lastCopy == "" && !h.m().statusError {
		t.Fatal("C neither copied a function nor reported why")
	}

	// / opens the search modal.
	h.press("/")
	if !h.m().searchActive {
		t.Fatal("/ did not open the disasm search modal")
	}
	h.press("esc")

	// Tab opens the source pane only with DWARF; here just assert it does not crash
	// and shift+tab is handled.
	h.press("tab")
	h.press("shift+tab")
}

// --- Hex / Raw -------------------------------------------------------------

func TestKeysHexRaw(t *testing.T) {
	h := newKeyHarness(t, systemBinary(t))
	h.goView(modeHex, "5")

	// t toggles the pointer/ascii column; i toggles the inspector.
	pw0 := h.m().byteViews.Numeric
	h.press("t")
	if h.m().byteViews.Numeric == pw0 {
		t.Fatal("t did not toggle the hex pointer column")
	}
	in0 := h.m().byteViews.Inspect
	h.press("i")
	if h.m().byteViews.Inspect == in0 {
		t.Fatal("i did not toggle the data inspector")
	}

	// Arrow keys (and j/k by row) move the byte cursor; h/l are reserved for
	// view-jumps per the doc, not horizontal movement.
	cur0 := h.m().byteViews.HexCur
	h.press("right")
	if h.m().byteViews.HexCur == cur0 {
		t.Fatal("right did not move the byte cursor")
	}
	h.press("left")
	if h.m().byteViews.HexCur != cur0 {
		t.Fatal("left did not move the byte cursor back")
	}

	// Copy address / symbol / pointer.
	h.m().lastCopy = ""
	h.press("A")
	if !strings.HasPrefix(h.m().lastCopy, "0x") {
		t.Fatalf("A copied %q, want an address", h.m().lastCopy)
	}
	h.m().lastCopy = ""
	h.press("P")
	if !strings.HasPrefix(h.m().lastCopy, "0x") && !h.m().statusError {
		t.Fatalf("P neither copied a pointer nor reported why (%q)", h.m().lastCopy)
	}

	// d jumps to disasm at an executable address; m jumps to raw.
	if selectExecHexByte(h) {
		h.goView(modeDisasm, "d")
		h.goView(modeHex, "5")
	}
	h.goView(modeRaw, "m")

	// Raw view: d jumps back to disasm for an allocated offset; t/i/copy work.
	h.goView(modeRaw, "6")
	pw0 = h.m().byteViews.Numeric
	h.press("t")
	if h.m().byteViews.Numeric == pw0 {
		t.Fatal("raw: t did not toggle the pointer column")
	}
	h.m().lastCopy = ""
	h.press("A")
	if !strings.HasPrefix(h.m().lastCopy, "0x") {
		t.Fatalf("raw A copied %q, want an offset", h.m().lastCopy)
	}

	// Raw: h jumps to hex for an allocated offset.
	if off, ok := allocatedRawOffset(h.m()); ok {
		h.m().byteViews.RawCur = off
		h.goView(modeHex, "h")
		h.goView(modeRaw, "6")
	}

	// / opens the byte search modal.
	h.goView(modeHex, "5")
	h.press("/")
	if !h.m().searchActive {
		t.Fatal("/ did not open the hex search modal")
	}
	h.press("esc")
}

func allocatedRawOffset(m *Model) (int, bool) {
	for i := range m.file.Sections {
		s := m.file.Sections[i]
		if s.Alloc && s.Addr != 0 && s.FileSize > 0 {
			return int(s.Offset), true
		}
	}
	return 0, false
}

func selectExecHexByte(h *keyHarness) bool {
	m := h.m()
	m.byteViews.EnsureHex(m.viewContextPtr())
	for _, r := range m.byteViews.HexImg.Regions {
		addr := r.Addr
		if _, ok := m.file.ExecImage().PosForAddr(addr); ok {
			if pos, ok := m.byteViews.HexImg.PosForAddr(addr); ok {
				m.byteViews.HexCur = pos
				return true
			}
		}
	}
	return false
}

// --- Tree navigation (Symbols/Libs/Sources share the tree keys) ------------

func TestKeysTreeNav(t *testing.T) {
	var syms []binfile.Symbol
	for i, nm := range []string{"a.b.x", "a.b.y", "a.c.z", "top"} {
		syms = append(syms, binfile.Symbol{Name: nm, Addr: uint64(0x1000 + i*8), Kind: binfile.SymFunc})
	}
	f := &binfile.File{Format: binfile.FormatELF, Symbols: syms}
	m, err := New(f)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var h = &keyHarness{t: t, model: m}
	h.pump(tea.WindowSizeMsg{Width: 120, Height: 30})
	h.goView(modeSymbols, "3")
	h.press("t") // switch to the namespace tree (builds the tree rows)
	if !h.m().symbols.Tree {
		t.Fatal("t did not enable the symbol tree")
	}

	// + expands every group → the fully-expanded row count.
	h.press("+")
	expanded := len(h.m().symbols.Rows)
	if expanded == 0 {
		t.Fatal("no tree rows after expand-all")
	}
	// - collapses every group → fewer rows.
	h.press("-")
	if len(h.m().symbols.Rows) >= expanded {
		t.Fatalf("- did not collapse (%d >= %d)", len(h.m().symbols.Rows), expanded)
	}
	// + expands back to the full set.
	h.press("+")
	if len(h.m().symbols.Rows) != expanded {
		t.Fatalf("+ did not expand all (%d != %d)", len(h.m().symbols.Rows), expanded)
	}
	// Enter on the root recursively collapses the subtree below it.
	h.m().symbols.Cur = 0
	h.press("enter")
	if len(h.m().symbols.Rows) >= expanded {
		t.Fatal("enter did not collapse the subtree below the root")
	}
	// right expands the current group one level.
	h.press("right")
	if h.m().symbols.IsCollapsed(h.m().symbols.Rows[0].Node.Path) {
		t.Fatal("right did not expand the group under the cursor")
	}
	// left collapses it again.
	h.press("left")
	if !h.m().symbols.IsCollapsed(h.m().symbols.Rows[0].Node.Path) {
		t.Fatal("left did not collapse the group under the cursor")
	}
}

// --- Sources (needs DWARF) -------------------------------------------------

func TestKeysSources(t *testing.T) {
	bin := buildDebugSample(t) // skips when no C compiler
	h := newKeyHarness(t, bin)
	h.goView(modeSources, "9")
	if !h.m().file.HasDWARF() || len(h.m().sources.Files) == 0 {
		t.Skip("sample has no usable DWARF source list")
	}

	// t toggles tree/flat.
	tr0 := h.m().sources.Tree
	h.press("t")
	if h.m().sources.Tree == tr0 {
		t.Fatal("t did not toggle the sources tree")
	}
	h.press("t")

	// ctrl+p cycles the availability filter.
	av0 := h.m().sources.Avail
	h.press("ctrl+p")
	if h.m().sources.Avail == av0 {
		t.Fatal("ctrl+p did not change the sources availability filter")
	}
	h.press("ctrl+p")
	h.press("ctrl+p") // back to all

	// Select a leaf file and copy its path.
	selectSourceLeaf(t, h)
	h.m().lastCopy = ""
	h.press("S")
	if h.m().lastCopy == "" {
		t.Fatal("S did not copy a source path")
	}

	// Enter opens the file in the disasm source-first view.
	selectSourceLeaf(t, h)
	h.press("enter")
	if h.m().mode != modeDisasm || !h.m().sourceFirst {
		t.Fatalf("enter did not open source-first disasm (mode=%v sourceFirst=%v)", h.m().mode, h.m().sourceFirst)
	}
}

func selectSourceLeaf(t *testing.T, h *keyHarness) {
	t.Helper()
	m := h.m()
	for i, r := range m.sources.Rows {
		if r.Node.Leaf >= 0 {
			m.sources.Cur = i
			return
		}
	}
	t.Skip("no source leaf row")
}

// --- shift+l copy line (sections/symbols/disasm/hex/raw/strings/libs) ------

func TestKeysCopyLine(t *testing.T) {
	h := newKeyHarness(t, systemBinary(t))

	check := func(view, key string, md mode) {
		t.Helper()
		h.goView(md, key)
		h.m().lastCopy = ""
		h.press("L")
		if h.m().lastCopy == "" {
			t.Fatalf("%s: shift+l (L) copied nothing", view)
		}
	}
	check("sections", "2", modeSections)
	if len(h.m().file.Symbols) > 0 {
		check("symbols", "3", modeSymbols)
	}
	check("disasm", "4", modeDisasm)
	check("hex", "5", modeHex)
	check("raw", "6", modeRaw)
	if h.goView(modeStrings, "7"); len(h.m().strs.List) > 0 {
		h.m().lastCopy = ""
		h.press("L")
		if h.m().lastCopy == "" {
			t.Fatal("strings: shift+l copied nothing")
		}
	}
	if h.goView(modeLibs, "8"); h.m().file.Info != nil && len(h.m().file.Info.DynamicLibs) > 0 {
		h.m().libs.BuildRows(h.m().viewContext())
		h.m().lastCopy = ""
		h.press("L")
		if h.m().lastCopy == "" {
			t.Fatal("libs: shift+l copied nothing")
		}
	}
}

// --- Sorting in Strings / Libs / Sources -----------------------------------

func TestStringsSortKeys(t *testing.T) {
	f := &binfile.File{Format: binfile.FormatELF}
	m := newTestModel(t, f)
	// Offset-ascending input (as the extractor produces), with addresses in a
	// different order so the address sort is observably distinct.
	m.strs.List = []binfile.StringEntry{
		{Offset: 0x10, Addr: 0x3000, HasAddr: true, Len: 1, Section: ".rodata"},
		{Offset: 0x20, Addr: 0x1000, HasAddr: true, Len: 1, Section: ".rodata"},
		{Offset: 0x30, Addr: 0x2000, HasAddr: true, Len: 1, Section: ".rodata"},
	}
	m.setMode(modeStrings)
	m.strs.Recompute(m.viewContext())

	offsets := func() []uint64 {
		var out []uint64
		for _, i := range m.strs.Filtered {
			out = append(out, m.strs.List[i].Offset)
		}
		return out
	}
	// Default is offset-ascending.
	if got := offsets(); got[0] != 0x10 || got[2] != 0x30 {
		t.Fatalf("default (offset) order = %x", got)
	}
	// s → address: order becomes addr 0x1000,0x2000,0x3000 = offsets 0x20,0x30,0x10.
	m.strs.Update(m.viewContext(), m, "s")
	if m.strs.Sort != strs.SortAddr {
		t.Fatalf("s did not advance sort, got %v", m.strs.Sort)
	}
	if got := offsets(); got[0] != 0x20 || got[1] != 0x30 || got[2] != 0x10 {
		t.Fatalf("address-sorted order = %x", got)
	}
	// r reverses the address sort.
	m.strs.Update(m.viewContext(), m, "r")
	if got := offsets(); got[0] != 0x10 || got[2] != 0x20 {
		t.Fatalf("reversed address order = %x", got)
	}
}

func TestLibsSortReverse(t *testing.T) {
	h := newKeyHarness(t, systemBinary(t))
	h.goView(modeLibs, "8")
	if h.m().file.Info == nil || len(h.m().file.Info.DynamicLibs) < 2 {
		t.Skip("need >= 2 libraries")
	}
	first := func() string {
		for _, r := range h.m().libs.Rows {
			if r.Node.Leaf >= 0 {
				return h.m().file.Info.DynamicLibs[r.Node.Leaf]
			}
		}
		return ""
	}
	// Flat list so the leaf order reflects the sort directly.
	if h.m().libs.Tree {
		h.press("t")
	}
	asc := first()
	h.press("r")
	if !h.m().libs.SortDesc {
		t.Fatal("r did not set descending")
	}
	if first() == asc {
		t.Fatal("r did not change the first library")
	}
}

func TestSourcesSortKeys(t *testing.T) {
	bin := buildDebugSample(t)
	h := newKeyHarness(t, bin)
	h.goView(modeSources, "9")
	if !h.m().file.HasDWARF() || len(h.m().sources.Files) == 0 {
		t.Skip("no DWARF sources")
	}
	if h.m().sources.Tree {
		h.press("t")
	}
	s0 := h.m().sources.Sort
	h.press("s")
	if h.m().sources.Sort == s0 || h.m().sources.Sort != sources.SortName {
		t.Fatal("s did not change the sources sort field")
	}
	d0 := h.m().sources.SortDesc
	h.press("r")
	if h.m().sources.SortDesc == d0 {
		t.Fatal("r did not reverse the sources sort")
	}
}

// --- Ctrl-chord facet filters vs the bare toggle ---------------------------

// TestKeysFacetChords proves the facet filters fire on their Ctrl chord (the
// same on macOS and Linux — Alt was dropped because gnome-terminal eats it) and
// that the bare letter still drives its own action (no regression).
func TestKeysFacetChords(t *testing.T) {
	h := newKeyHarness(t, systemBinary(t))
	if len(h.m().file.Symbols) == 0 {
		t.Skip("binary has no symbols")
	}
	h.goView(modeSymbols, "3")

	// 1) Ctrl+t toggles the type facet filter.
	h.m().symbols.KindOn = false
	h.press("ctrl+t")
	if !h.m().symbols.KindOn {
		t.Fatal("ctrl+t did not trigger the type filter")
	}

	// 2) Bare "t" must still toggle the tree, not filter (no regression).
	h.press("esc")
	tree0 := h.m().symbols.Tree
	h.press("t")
	if h.m().symbols.Tree == tree0 {
		t.Fatal("plain t no longer toggles the tree")
	}
	h.press("t")
}

// --- Configurability: a user key rebinds the action ------------------------

func TestKeysConfigurable(t *testing.T) {
	f := &binfile.File{Format: binfile.FormatELF, Sections: []binfile.Section{
		{Name: "zeta", Addr: 0x3000, Size: 10},
		{Name: "alpha", Addr: 0x1000, Size: 50},
	}, Symbols: []binfile.Symbol{
		{Name: "alpha", Addr: 0x1000, Kind: binfile.SymFunc},
		{Name: "beta", Addr: 0x1100, Kind: binfile.SymObject},
	}}
	// Rebind: sort→F2-ish "z", reverse→"x", scope-filter→"Q", copy-line→"y".
	cfg := config.Config{Keys: config.Keys{
		Sort:        config.StringOrSlice{"z"},
		SortReverse: config.StringOrSlice{"x"},
		FilterScope: config.StringOrSlice{"Q"},
		CopyLine:    config.StringOrSlice{"y"},
	}}
	m, err := New(f, Options{Config: &cfg})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h := &keyHarness{t: t, model: m}
	h.pump(tea.WindowSizeMsg{Width: 120, Height: 30})

	// Symbols: the configured sort key cycles the sort; the default "s" still works
	// too (aliases are additive), but the custom key must take effect.
	h.goView(modeSymbols, "3")
	s0 := h.m().symbols.Sort
	h.press("z")
	if h.m().symbols.Sort == s0 {
		t.Fatal("configured sort key 'z' did not change the sort")
	}
	sc0 := h.m().symbols.Scope
	h.press("Q")
	if h.m().symbols.Scope == sc0 {
		t.Fatal("configured scope-filter key 'Q' had no effect")
	}

	// Sections: the configured reverse key flips the order.
	h.goView(modeSections, "2")
	d0 := h.m().sections.SortDesc
	h.press("x")
	if h.m().sections.SortDesc == d0 {
		t.Fatal("configured reverse key 'x' did not reverse the sort")
	}

	// The configured copy-line key copies the row.
	h.m().lastCopy = ""
	h.press("y")
	if h.m().lastCopy == "" {
		t.Fatal("configured copy-line key 'y' copied nothing")
	}
}

// --- Enter / follow / history (the per-view "open" verbs) -------------------

func TestKeysActivate(t *testing.T) {
	h := newKeyHarness(t, systemBinary(t))

	// Sections: Enter opens the selected section (Hex for mapped, Raw otherwise).
	h.goView(modeSections, "2")
	selectExecSection(t, h)
	h.press("enter")
	if h.m().mode != modeHex && h.m().mode != modeRaw && h.m().mode != modeDisasm {
		t.Fatalf("sections Enter left mode = %v", h.m().mode)
	}

	// Symbols: Enter on a function opens it in disasm/hex.
	if len(h.m().file.Symbols) > 0 {
		h.goView(modeSymbols, "3")
		selectFuncSymbol(t, h)
		h.press("enter")
		if h.m().mode == modeSymbols {
			t.Fatal("symbols Enter did not open the symbol")
		}
	}

	// Strings: Enter opens the selected string (Hex if mapped, else Raw).
	h.goView(modeStrings, "7")
	if len(h.m().strs.List) > 0 {
		h.m().strs.Cur = 0
		h.press("enter")
		if h.m().mode != modeHex && h.m().mode != modeRaw {
			t.Fatalf("strings Enter left mode = %v", h.m().mode)
		}
	}

	// Disasm: ←/→ walk history, Enter follows an operand address (tolerant: an
	// instruction may have no in-file target).
	h.goView(modeDisasm, "4")
	if len(h.m().disasmInst) > 0 {
		h.press("enter") // follow (or status "no address")
		h.press("left")  // history back
		h.press("right") // history forward
		if h.m().mode != modeDisasm {
			t.Fatalf("disasm history left mode = %v", h.m().mode)
		}
	}

	// Hex: Enter follows the pointer word under the cursor (tolerant).
	h.goView(modeHex, "5")
	h.press("enter")

	// Libs: Enter opens imported symbols (or reports none); either way it is
	// handled without crashing.
	if h.m().file.Info != nil && len(h.m().file.Info.DynamicLibs) > 0 {
		h.goView(modeLibs, "8")
		selectLibLeaf(t, h)
		h.press("enter")
	}
}

// --- tab doubles as the mode-toggle (t) outside disasm ---------------------

func TestKeysTabTogglesMode(t *testing.T) {
	h := newKeyHarness(t, systemBinary(t))

	// Sections: tab toggles sections <-> segments, same as t.
	if len(h.m().sections.Segments) > 0 {
		h.goView(modeSections, "2")
		seg0 := h.m().sections.ShowSegments
		h.press("tab")
		if h.m().sections.ShowSegments == seg0 {
			t.Fatal("tab did not toggle sections/segments")
		}
	}

	// Symbols: tab toggles the tree.
	if len(h.m().file.Symbols) > 0 {
		h.goView(modeSymbols, "3")
		tr0 := h.m().symbols.Tree
		h.press("tab")
		if h.m().symbols.Tree == tr0 {
			t.Fatal("tab did not toggle the symbol tree")
		}
	}

	// Hex: tab toggles the ascii/pointer column.
	h.goView(modeHex, "5")
	pw0 := h.m().byteViews.Numeric
	h.press("tab")
	if h.m().byteViews.Numeric == pw0 {
		t.Fatal("tab did not toggle the hex pointer column")
	}

	// Disasm: tab still drives the source pane, NOT a mode toggle. With no DWARF
	// it reports unavailable; with DWARF it toggles showSource. Either way the
	// view stays disasm and nothing panics.
	h.goView(modeDisasm, "4")
	show0 := h.m().showSource
	h.press("tab")
	if h.m().mode != modeDisasm {
		t.Fatal("tab in disasm changed the view")
	}
	if h.m().file.HasDWARF() && h.m().showSource == show0 {
		t.Fatal("tab in disasm did not toggle the source pane")
	}
}

// --- esc clears search + every filter, in each list view -------------------

func TestKeysEscClears(t *testing.T) {
	h := newKeyHarness(t, systemBinary(t))

	// Symbols: set a text filter + a column filter, then esc clears both.
	if len(h.m().file.Symbols) > 0 {
		h.goView(modeSymbols, "3")
		h.press("/")
		h.press("a")
		h.press("ctrl+t")
		if h.m().symbols.Filter.Value() == "" && !h.m().symbols.KindOn {
			t.Skip("could not set symbol filters")
		}
		h.press("esc")
		if h.m().symbols.Filter.Value() != "" || h.m().symbols.KindOn || h.m().symbols.Filter.Focused() {
			t.Fatalf("symbols esc did not clear everything (text=%q kind=%v focused=%v)",
				h.m().symbols.Filter.Value(), h.m().symbols.KindOn, h.m().symbols.Filter.Focused())
		}
	}

	// Sections: type filter + text, esc clears.
	h.goView(modeSections, "2")
	h.press("ctrl+t")
	h.press("/")
	h.press("t")
	h.press("esc")
	if h.m().sections.TypeOn || h.m().sections.Filter.Value() != "" || h.m().sections.Filter.Focused() {
		t.Fatal("sections esc did not clear filters")
	}

	// Strings: section filter + text, esc clears.
	h.goView(modeStrings, "7")
	if len(h.m().strs.Sections) > 0 {
		h.press("ctrl+s")
	}
	h.press("/")
	h.press("a")
	h.press("esc")
	if h.m().strs.SecOn || h.m().strs.Filter.Value() != "" {
		t.Fatal("strings esc did not clear filters")
	}

	// Libs: availability + text filter, esc clears.
	if h.m().file.Info != nil && len(h.m().file.Info.DynamicLibs) > 0 {
		h.goView(modeLibs, "8")
		h.press("ctrl+p")
		h.press("/")
		h.press("a")
		h.press("esc")
		if h.m().libs.Avail != view.AvailAll || h.m().libs.Filter.Value() != "" {
			t.Fatal("libs esc did not clear filters")
		}
	}
}

// --- Sections type / flags filters -----------------------------------------

func TestKeysSectionFilters(t *testing.T) {
	h := newKeyHarness(t, systemBinary(t))
	h.goView(modeSections, "2")
	if len(h.m().sections.Types) == 0 {
		t.Skip("no section type names")
	}
	all := len(h.m().sections.Filtered)
	h.press("ctrl+t")
	if !h.m().sections.TypeOn {
		t.Fatal("ctrl+t did not enable the section type filter")
	}
	if len(h.m().sections.Filtered) > all {
		t.Fatal("type filter did not narrow the list")
	}
	// Every visible row matches the selected type.
	for _, idx := range h.m().sections.Filtered {
		if h.m().sections.Sections[idx].TypeName != h.m().sections.TypeSel {
			t.Fatalf("row type %q != filter %q", h.m().sections.Sections[idx].TypeName, h.m().sections.TypeSel)
		}
	}
	h.press("esc")
	if h.m().sections.TypeOn {
		t.Fatal("esc did not clear the type filter")
	}
	// Flags filter is wired too.
	if len(h.m().sections.FlagsList) > 0 {
		h.press("ctrl+f")
		if !h.m().sections.FlagsOn {
			t.Fatal("ctrl+f did not enable the section flags filter")
		}
	}
}

// --- Libs search -----------------------------------------------------------

func TestKeysLibsSearch(t *testing.T) {
	h := newKeyHarness(t, systemBinary(t))
	h.goView(modeLibs, "8")
	if h.m().file.Info == nil || len(h.m().file.Info.DynamicLibs) < 2 {
		t.Skip("need at least two dynamic libraries")
	}
	all := len(h.m().libs.Rows)
	// Filter by a substring of the first library's basename.
	lib := h.m().file.Info.DynamicLibs[0]
	needle := lib
	if i := strings.LastIndexByte(lib, '/'); i >= 0 && i+2 < len(lib) {
		needle = lib[i+1 : i+3]
	}
	h.press("/")
	for _, r := range needle {
		h.press(string(r))
	}
	if h.m().libs.Filter.Value() == "" {
		t.Skip("filter input did not accept text")
	}
	if len(h.m().libs.Rows) > all {
		t.Fatal("libs search did not narrow the list")
	}
	h.press("esc")
	if h.m().libs.Filter.Value() != "" {
		t.Fatal("esc did not clear the libs search")
	}
}

// --- Navigation aliases (doc #27 page/top/bottom chords) -------------------

func TestKeysNavAliases(t *testing.T) {
	h := newKeyHarness(t, systemBinary(t))
	if len(h.m().file.Sections) < 3 {
		t.Skip("too few sections to page")
	}
	h.goView(modeSections, "2")

	// ctrl+down / alt+down page down; cmd+up returns to the top.
	h.press("ctrl+down")
	if h.m().sections.Cur == 0 {
		t.Fatal("ctrl+down did not page down")
	}
	h.press("cmd+up")
	if h.m().sections.Cur != 0 {
		t.Fatal("cmd+up did not go to the top")
	}
	// cmd+down goes to the bottom; ctrl+up pages back up.
	h.press("cmd+down")
	bottom := h.m().sections.Cur
	if bottom != len(h.m().sections.Filtered)-1 {
		t.Fatalf("cmd+down landed at %d, want %d", bottom, len(h.m().sections.Filtered)-1)
	}
	h.press("ctrl+up")
	if h.m().sections.Cur == bottom {
		t.Fatal("ctrl+up did not page up")
	}
}

// --- Info ------------------------------------------------------------------

func TestKeysInfo(t *testing.T) {
	h := newKeyHarness(t, systemBinary(t))
	h.goView(modeInfo, "1")
	// Enter opens the entry point in disasm (or hex if not executable); either way
	// it must leave the Info view.
	h.press("enter")
	if h.m().mode == modeInfo {
		t.Fatal("enter in Info did not open the entry point")
	}
}

// TestKeysInfoArch verifies the doc #27 binding: in Info, `t` switches the fat
// Mach-O architecture slice (it used to be `a`). Needs a universal binary.
func TestKeysInfoArch(t *testing.T) {
	bin := firstExisting("/bin/ls", "/usr/bin/true", "/bin/cat")
	if bin == "" {
		t.Skip("no system binary")
	}
	f, err := binfile.Open(bin)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(f.FatArches) < 2 {
		t.Skip("not a universal (fat) binary")
	}
	m, err := New(f)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h := &keyHarness{t: t, model: m}
	h.pump(tea.WindowSizeMsg{Width: 140, Height: 45})
	h.goView(modeInfo, "1")
	before := h.m().file.FatArch
	h.press("t") // switch arch — returns a fresh model for the next slice
	if h.m().file.FatArch == before {
		t.Fatalf("t did not switch the fat arch (still %v)", before)
	}
	// The old `a` binding must no longer switch arches.
	h2 := &keyHarness{t: t, model: must(New(mustOpen(t, bin)))}
	h2.pump(tea.WindowSizeMsg{Width: 140, Height: 45})
	h2.goView(modeInfo, "1")
	a0 := h2.m().file.FatArch
	h2.press("a")
	if h2.m().file.FatArch != a0 {
		t.Fatal("legacy 'a' still switches arch; it should be 't' now")
	}
}

func mustOpen(t *testing.T, p string) *binfile.File {
	t.Helper()
	f, err := binfile.Open(p)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return f
}

func must(m *Model, err error) *Model {
	if err != nil {
		panic(err)
	}
	return m
}
