package ui

import (
	"fmt"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/rabarbra/exex/internal/ui/layout"
	"github.com/rabarbra/exex/internal/ui/views/hexraw"
)

// modeView is the per-view behaviour behind the mode dispatch. Each concrete
// view is a thin adapter embedding *Model (via baseView) that delegates to the
// existing render/state methods, so the many scattered `switch m.mode` blocks
// collapse to a single mapping (viewFor) plus interface calls. State still lives
// in the embedded per-view *State structs on Model; this only centralises
// dispatch.
type modeView interface {
	// body renders the view's main content area.
	body() string
	// ensure builds the lazy state a view needs on first switch-in, returning a
	// Cmd for any background work (only disasm has one). No-op for most views.
	ensure() tea.Cmd
	// hints returns the view-specific footer key hints (globals are appended by
	// renderFooter).
	hints() []footerHint
	// lineText returns the plain text of the current row for the copy-line action.
	// ok is false for views without a row concept (so the caller can fall through).
	lineText() (string, bool)
	// headerRow reports whether bodyRow is the view's clickable column header.
	headerRow(bodyRow int) bool
	// sortHeaderClick handles a click at column x on body row bodyRow when it lands
	// on a sortable column header, returning whether it was consumed.
	sortHeaderClick(x, bodyRow int) bool
	// handleKey routes a key press to the view's own key handler.
	handleKey(msg tea.KeyMsg, key string) (tea.Model, tea.Cmd)
	// captureFilter lets a focused filter input consume typing keys; ok is false
	// when the view has no active filter to capture.
	captureFilter(key string, msg tea.KeyMsg) (tea.Cmd, bool)
	// searchHint is the prompt shown in the search modal for this view.
	searchHint() string
	// runSearch runs the view's search; views without search report so via status.
	runSearch(forward, inclusive, fromCursor bool) tea.Cmd
}

// baseView carries the Model pointer and the no-op interface defaults, so a
// concrete view only spells out the behaviour it actually has.
type baseView struct{ *Model }

func (baseView) ensure() tea.Cmd               { return nil }
func (baseView) hints() []footerHint           { return nil }
func (baseView) lineText() (string, bool)      { return "", false }
func (baseView) headerRow(int) bool            { return false }
func (baseView) sortHeaderClick(_, _ int) bool { return false }
func (baseView) searchHint() string            { return "Search this view" }

func (b baseView) captureFilter(string, tea.KeyMsg) (tea.Cmd, bool) { return nil, false }

func (b baseView) runSearch(_, _, _ bool) tea.Cmd {
	b.setStatus("search isn't available in this view", true)
	return nil
}

// viewFor returns the adapter for a mode. This is the one place the mode→view
// mapping lives; every other dispatch site goes through the interface.
func (m *Model) viewFor(md mode) modeView {
	b := baseView{m}
	switch md {
	case modeInfo:
		return infoView{b}
	case modeSections:
		return sectionsView{b}
	case modeSymbols:
		return symbolsView{b}
	case modeDisasm:
		return disasmView{b}
	case modeHex:
		return hexView{b}
	case modeRaw:
		return rawView{b}
	case modeStrings:
		return stringsView{b}
	case modeSources:
		return sourcesView{b}
	case modeLibs:
		return libsView{b}
	case modeRelocs:
		return relocsView{b}
	}
	return infoView{b}
}

// current is the adapter for the active mode.
func (m *Model) current() modeView { return m.viewFor(m.mode) }

type (
	infoView     struct{ baseView }
	sectionsView struct{ baseView }
	symbolsView  struct{ baseView }
	disasmView   struct{ baseView }
	hexView      struct{ baseView }
	rawView      struct{ baseView }
	stringsView  struct{ baseView }
	sourcesView  struct{ baseView }
	libsView     struct{ baseView }
	relocsView   struct{ baseView }
)

func (v infoView) body() string     { return v.renderInfo() }
func (v sectionsView) body() string { return v.sections.Render(v.viewContext(), v.Model) }
func (v symbolsView) body() string  { return v.symbols.Render(v.viewContext(), v.Model) }
func (v disasmView) body() string   { return v.renderDisasm() }
func (v hexView) body() string      { return v.byteViews.Render(v.viewContextPtr(), hexraw.Hex) }
func (v rawView) body() string      { return v.byteViews.Render(v.viewContextPtr(), hexraw.Raw) }
func (v stringsView) body() string  { return v.strs.Render(v.viewContext(), v.Model) }
func (v sourcesView) body() string  { return v.renderSources() }
func (v libsView) body() string     { return v.libs.Render(v.viewContext(), v.Model) }
func (v relocsView) body() string   { return v.relocs.Render(v.viewContext(), v.Model) }

// ensure: only views with lazy state override the baseView no-op.

func (v symbolsView) ensure() tea.Cmd { v.symbols.Ensure(v.viewContext()); return nil }
func (v hexView) ensure() tea.Cmd     { v.byteViews.EnsureHex(v.viewContextPtr()); return nil }
func (v rawView) ensure() tea.Cmd     { v.byteViews.EnsureRaw(v.viewContextPtr()); return nil }
func (v stringsView) ensure() tea.Cmd { v.strs.Ensure(v.viewContext()); return nil }
func (v sourcesView) ensure() tea.Cmd { v.sources.Ensure(v.viewContext()); return nil }

func (v relocsView) ensure() tea.Cmd {
	ctx := v.viewContext()
	v.relocs.BuildFacets(ctx)
	v.relocs.Recompute(ctx)
	return nil
}

func (v disasmView) ensure() tea.Cmd {
	if !v.disasmBuilt {
		// Decode the initial window in the background; later jumps decode a fresh
		// bounded span synchronously so targeted navigation lands immediately.
		if !v.disasmDecoding {
			v.disasmDecoding = true
			v.disasmPendingAddr = v.disasmInitAddr
			return v.decodeDisasmCmd(v.disasmInitAddr)
		}
		return nil
	}
	// Already decoded: land on the entry the first time in.
	if !v.disasmPositioned && v.disasmInitAddr != 0 {
		v.loadDisasmAt(v.disasmInitAddr)
	}
	return nil
}

// hints: view-specific footer key hints. Globals are appended by renderFooter.

func (v infoView) hints() []footerHint {
	if v.isArchive() && v.infoMembers {
		return []footerHint{{"↑/↓", "select"}, {"↵/t", "open member"}, {"esc", "back"}}
	}
	hints := []footerHint{{"↵", "disasm entry"}}
	switch {
	case v.isArchive():
		hints = append(hints, footerHint{"t", "members"})
	case len(v.file.FatArches) > 1:
		hints = append(hints, footerHint{"t", "switch arch"})
	}
	return hints
}

func (v sectionsView) hints() []footerHint {
	return []footerHint{{"↵", "open"}, {"d/h/m", "go to"}, {"␣", "open in…"}, {"s/r", "sort/rev"}, {"t", "sec/seg"}, {"/", "filter"}, {layout.CtrlKeys("t", "f"), "type/flags"}, {"⇧H", "header"}}
}

func (v symbolsView) hints() []footerHint {
	if v.symbols.TreeActive() {
		return []footerHint{{"←/→", "fold/unfold"}, {"↵", "all below"}, {"+/−", "all"}, {"t", "flat"}}
	}
	return []footerHint{{"↵", "jump"}, {"d/h/m", "go to"}, {"␣", "open in…"}, {"s/r", "sort/rev"}, {"t", "tree"}, {"/", "filter"}, {layout.CtrlKeys("t", "s", "b"), "type/scope/bind"}, {"⇧a/⇧s", "copy"}}
}

func (v disasmView) hints() []footerHint {
	dwarf := v.file.HasDWARF()
	switch {
	case v.searchRunning:
		return []footerHint{{"esc", "cancel"}, {"[ ]", "sym"}, {"←/→", "history"}, {"/", "search"}}
	case v.sourceFirst && v.srcFile != "":
		// Source navigation leads: no disasm history, and [ ] steps mapped lines.
		return []footerHint{{"↵", "to disasm"}, {"[ ]", "mapped"}, {"esc", "back"}, {"⇧tab", "swap"}, {"/", "search"}, {"⇧s", "copy"}}
	case v.showSource && dwarf:
		// Disasm-first with the source pane open.
		return []footerHint{{"↵", "follow"}, {"[ ]", "sym"}, {"←/→", "history"}, {"x", "xrefs"}, {"y", "syscalls"}, {"h/m", "hex/raw"}, {"␣", "open in…"}, {"a", v.disasmAllHint()}, {"tab", "pane"}, {"⇧tab", "swap"}, {"/", "search"}, {"⇧a/⇧s/⇧c", "copy"}}
	default:
		// Disasm-first, no pane. Offer tab to open the pane only when there is
		// debug info to show.
		hints := []footerHint{{"↵", "follow"}, {"[ ]", "sym"}, {"←/→", "history"}, {"x", "xrefs"}, {"y", "syscalls"}, {"h/m", "hex/raw"}, {"␣", "open in…"}, {"a", v.disasmAllHint()}, {"/", "search"}, {"⇧a/⇧s/⇧c", "copy"}}
		if dwarf {
			hints = append(hints, footerHint{"tab", "pane"})
		}
		return hints
	}
}

func (v hexView) hints() []footerHint {
	return []footerHint{{"↵", "follow ptr"}, {"d/m", "disasm/raw"}, {"␣", "open in…"}, {"[ ]", "section"}, {"t/⇧t", "ascii·interp"}, {"i", "inspect"}, {"/", "search"}, {"⇧a/⇧s/⇧p", "copy"}}
}

func (v rawView) hints() []footerHint {
	return []footerHint{{"↵", "follow ptr"}, {"d", "disasm"}, {"␣", "open in…"}, {"[ ]", "section"}, {"t/⇧t", "ascii·interp"}, {"i", "inspect"}, {"/", "search"}, {"⇧a/⇧s/⇧p", "copy"}}
}

func (v stringsView) hints() []footerHint {
	return []footerHint{{"↵", "jump"}, {"d/h/m", "go to"}, {"␣", "open in…"}, {"s/r", "sort/rev"}, {"t", "table/flow"}, {"/", "filter"}, {layout.CtrlKeys("s"), "section"}, {layout.CtrlKeys("p"), "paths"}, {"⇧a/⇧s", "copy"}}
}

func (v sourcesView) hints() []footerHint {
	if v.sources.Tree {
		return []footerHint{{"←/→", "fold/unfold"}, {"↵", "open/all below"}, {layout.CtrlKeys("p"), "present"}, {"t", "flat"}}
	}
	return []footerHint{{"↵", "open"}, {"s/r", "sort/rev"}, {"t", "tree"}, {"/", "filter"}, {layout.CtrlKeys("p"), "present"}, {"⇧s", "copy"}}
}

func (v libsView) hints() []footerHint {
	return []footerHint{{"↵", "imports"}, {"o", "open"}, {"r", "rev"}, {"t", "tree"}, {"/", "filter"}, {layout.CtrlKeys("p"), "avail"}, {"⇧s", "copy"}}
}

func (v relocsView) hints() []footerHint {
	return []footerHint{{"↵", "hex"}, {"d/h/m", "go to"}, {"␣", "open in…"}, {"e", "args"}, {"s/r", "sort/rev"}, {layout.CtrlKeys("t", "s"), "type/section"}, {"/", "filter"}, {"⇧a/⇧s", "copy"}}
}

// lineText: plain text of the current row, for the copy-line (⇧L) action. Only
// views with a row concept override the baseView "not copyable" default.

func (v sectionsView) lineText() (string, bool) {
	return cleanCopyLine(v.sections.RowText(v.viewContext())), true
}

func (v symbolsView) lineText() (string, bool) {
	return cleanCopyLine(v.symbols.RowText(v.viewContext())), true
}

func (v stringsView) lineText() (string, bool) {
	return cleanCopyLine(v.strs.RowText(v.viewContext())), true
}

func (v libsView) lineText() (string, bool) {
	return cleanCopyLine(v.libs.RowText(v.viewContext())), true
}

func (v sourcesView) lineText() (string, bool) {
	if v.srcFile != "" {
		return v.srcFile, true // open file: copy its path
	}
	return v.sources.RowText(), true
}

func (v disasmView) lineText() (string, bool) {
	if len(v.disasmInst) == 0 || v.disasmCur < 0 || v.disasmCur >= len(v.disasmInst) {
		return "", true
	}
	in := v.disasmInst[v.disasmCur]
	addrW := v.file.AddrHexWidth()
	return cleanCopyLine(fmt.Sprintf("0x%0*x  %s  %s", addrW, in.Addr, ansi.Strip(bytesHex(in.Bytes, len(in.Bytes))), in.Text)), true
}

func (v hexView) lineText() (string, bool) {
	return cleanCopyLine(v.byteViews.RowText(v.viewContextPtr(), hexraw.Hex)), true
}

func (v rawView) lineText() (string, bool) {
	return cleanCopyLine(v.byteViews.RowText(v.viewContextPtr(), hexraw.Raw)), true
}

// headerRow / sortHeaderClick: only the table views with a clickable sort header
// override the baseView defaults.

func (v sectionsView) headerRow(bodyRow int) bool { return bodyRow == 1 }
func (v symbolsView) headerRow(bodyRow int) bool  { return bodyRow == 1 }
func (v relocsView) headerRow(bodyRow int) bool   { return bodyRow == 1 }
func (v libsView) headerRow(bodyRow int) bool {
	return bodyRow == v.libs.TitleRow(v.viewContext())
}

func (v stringsView) headerRow(bodyRow int) bool {
	v.strs.Ensure(v.viewContext())
	return len(v.strs.List) > 0 && bodyRow == 1
}

func (v sectionsView) sortHeaderClick(x, bodyRow int) bool {
	return bodyRow == 1 && v.sections.ClickHeader(v.viewContext(), v.Model, x)
}
func (v symbolsView) sortHeaderClick(x, bodyRow int) bool {
	return bodyRow == 1 && v.symbols.ClickHeader(v.viewContext(), v.Model, x)
}
func (v stringsView) sortHeaderClick(x, bodyRow int) bool {
	return bodyRow == 1 && v.strs.ClickHeader(v.viewContext(), v.Model, x)
}
func (v relocsView) sortHeaderClick(x, bodyRow int) bool {
	return bodyRow == 1 && v.relocs.ClickHeader(v.viewContext(), v.Model, x)
}
func (v libsView) sortHeaderClick(x, bodyRow int) bool {
	ctx := v.viewContext()
	return bodyRow == v.libs.TitleRow(ctx) && v.libs.ClickHeader(ctx, v.Model, x)
}

// handleKey: each view routes to its own key handler. Info also needs the raw
// message; the rest key off the normalised string.

func (v infoView) handleKey(msg tea.KeyMsg, key string) (tea.Model, tea.Cmd) {
	return v.updateInfo(msg, key)
}
func (v sectionsView) handleKey(_ tea.KeyMsg, key string) (tea.Model, tea.Cmd) {
	v.sections.Update(v.viewContext(), v.Model, key)
	return v.Model, nil
}
func (v symbolsView) handleKey(_ tea.KeyMsg, key string) (tea.Model, tea.Cmd) {
	v.symbols.Update(v.viewContext(), v.Model, key)
	return v.Model, nil
}
func (v disasmView) handleKey(_ tea.KeyMsg, key string) (tea.Model, tea.Cmd) {
	return v.updateDisasm(key)
}
func (v hexView) handleKey(_ tea.KeyMsg, key string) (tea.Model, tea.Cmd) {
	if key == "/" {
		v.openSearch()
		return v.Model, nil
	}
	v.byteViews.Update(v.viewContextPtr(), v.Model, hexraw.Hex, key)
	return v.Model, nil
}
func (v rawView) handleKey(_ tea.KeyMsg, key string) (tea.Model, tea.Cmd) {
	if key == "/" {
		v.openSearch()
		return v.Model, nil
	}
	v.byteViews.Update(v.viewContextPtr(), v.Model, hexraw.Raw, key)
	return v.Model, nil
}
func (v stringsView) handleKey(_ tea.KeyMsg, key string) (tea.Model, tea.Cmd) {
	v.strs.Update(v.viewContext(), v.Model, key)
	return v.Model, nil
}
func (v sourcesView) handleKey(_ tea.KeyMsg, key string) (tea.Model, tea.Cmd) {
	return v.updateSources(key)
}
func (v libsView) handleKey(_ tea.KeyMsg, key string) (tea.Model, tea.Cmd) {
	// Opening a library as the primary file replaces the whole model, which is
	// beyond the view.Host surface — intercept it here.
	if key == "o" {
		if lib, ok := v.libs.CurrentLib(v.viewContext()); ok {
			return v.openLibAsPrimary(lib)
		}
		return v.Model, nil
	}
	v.libs.Update(v.viewContext(), v.Model, key)
	return v.Model, nil
}
func (v relocsView) handleKey(_ tea.KeyMsg, key string) (tea.Model, tea.Cmd) {
	// Reloc bind targets are demangled symbol names, so the global argument-
	// abbreviation toggle (`e`, shared with the disasm/symbols views) applies here
	// too — it flips the state and drops the reloc row cache via SymbolNamesChanged.
	if key == "e" {
		v.symbols.ToggleAbbrevAll(v.Model)
		return v.Model, nil
	}
	v.relocs.Update(v.viewContext(), v.Model, key)
	return v.Model, nil
}

// captureFilter: only the filterable views override the "no filter" default.

func (v symbolsView) captureFilter(key string, msg tea.KeyMsg) (tea.Cmd, bool) {
	ctx := v.viewContext()
	return filterCapture(&v.symbols.Filter, key, msg, func() { v.symbols.Recompute(ctx) })
}
func (v sectionsView) captureFilter(key string, msg tea.KeyMsg) (tea.Cmd, bool) {
	return filterCapture(&v.sections.Filter, key, msg, v.sections.Recompute)
}
func (v stringsView) captureFilter(key string, msg tea.KeyMsg) (tea.Cmd, bool) {
	ctx := v.viewContext()
	return filterCapture(&v.strs.Filter, key, msg, func() { v.strs.Recompute(ctx) })
}
func (v libsView) captureFilter(key string, msg tea.KeyMsg) (tea.Cmd, bool) {
	ctx := v.viewContext()
	return filterCapture(&v.libs.Filter, key, msg, func() { v.libs.BuildRows(ctx) })
}
func (v relocsView) captureFilter(key string, msg tea.KeyMsg) (tea.Cmd, bool) {
	ctx := v.viewContext()
	return filterCapture(&v.relocs.Filter, key, msg, func() { v.relocs.Recompute(ctx) })
}
func (v sourcesView) captureFilter(key string, msg tea.KeyMsg) (tea.Cmd, bool) {
	if v.srcFile == "" {
		ctx := v.viewContext()
		return filterCapture(&v.sources.Filter, key, msg, func() { v.sources.Recompute(ctx) })
	}
	return nil, false
}

// searchHint / runSearch: only the searchable views override the defaults.

func (v disasmView) searchHint() string { return "Search instruction text / symbol" }
func (v hexView) searchHint() string    { return "Search hex bytes (de ad be ef), \"text\", or 0x…" }
func (v rawView) searchHint() string    { return "Search hex bytes (de ad be ef), \"text\", or 0x…" }

func (v sourcesView) searchHint() string {
	if v.srcSearchAll {
		return "Search across all source files"
	}
	return "Search in this source file"
}

func (v disasmView) runSearch(forward, inclusive, fromCursor bool) tea.Cmd {
	return v.runDisasmSearch(forward, inclusive, fromCursor)
}
func (v hexView) runSearch(forward, inclusive, fromCursor bool) tea.Cmd {
	v.runHexSearch(forward, inclusive, fromCursor)
	return nil
}
func (v rawView) runSearch(forward, inclusive, fromCursor bool) tea.Cmd {
	v.runRawSearch(forward, inclusive, fromCursor)
	return nil
}
func (v sourcesView) runSearch(forward, inclusive, _ bool) tea.Cmd {
	v.runSourcesSearch(forward, inclusive)
	return nil
}
