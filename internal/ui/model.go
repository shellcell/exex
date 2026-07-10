package ui

import (
	"time"

	"charm.land/bubbles/v2/viewport"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/config"
	"github.com/rabarbra/exex/internal/disasm"
	"github.com/rabarbra/exex/internal/explorer"
	"github.com/rabarbra/exex/internal/syntax"
	"github.com/rabarbra/exex/internal/ui/asmhl"
	"github.com/rabarbra/exex/internal/ui/layout"
	"github.com/rabarbra/exex/internal/ui/modal"
	cpufeatmodal "github.com/rabarbra/exex/internal/ui/modals/cpufeat"
	findquerymodal "github.com/rabarbra/exex/internal/ui/modals/findquery"
	findresultsmodal "github.com/rabarbra/exex/internal/ui/modals/findresults"
	findtomodal "github.com/rabarbra/exex/internal/ui/modals/findto"
	helpmodal "github.com/rabarbra/exex/internal/ui/modals/help"
	jumptomodal "github.com/rabarbra/exex/internal/ui/modals/jumpto"
	palettemodal "github.com/rabarbra/exex/internal/ui/modals/palette"
	rawheadermodal "github.com/rabarbra/exex/internal/ui/modals/rawheader"
	searchmodal "github.com/rabarbra/exex/internal/ui/modals/search"
	settingsmodal "github.com/rabarbra/exex/internal/ui/modals/settings"
	syscallsmodal "github.com/rabarbra/exex/internal/ui/modals/syscalls"
	xrefmodal "github.com/rabarbra/exex/internal/ui/modals/xref"
	"github.com/rabarbra/exex/internal/ui/view"
	"github.com/rabarbra/exex/internal/ui/views/hexraw"
	infoview "github.com/rabarbra/exex/internal/ui/views/info"
	"github.com/rabarbra/exex/internal/ui/views/libs"
	"github.com/rabarbra/exex/internal/ui/views/relocs"
	"github.com/rabarbra/exex/internal/ui/views/sections"
	"github.com/rabarbra/exex/internal/ui/views/sources"
	"github.com/rabarbra/exex/internal/ui/views/strs"
	"github.com/rabarbra/exex/internal/ui/views/symbols"
)

// mode identifies the active top-level view.
type mode int

const (
	modeInfo mode = iota
	modeSections
	modeSymbols
	modeDisasm
	modeHex
	modeLibs
	modeRaw
	modeStrings
	modeSources
	modeRelocs
)

// defaultDisasmMaxBytes bounds each decoded disassembly window by default.
const defaultDisasmMaxBytes = 2 << 20

// String returns the tab label for a mode.
func (m mode) String() string {
	switch m {
	case modeInfo:
		return "Info"
	case modeSections:
		return "Sections"
	case modeSymbols:
		return "Symbols"
	case modeDisasm:
		return "Disasm"
	case modeHex:
		return "Hex"
	case modeLibs:
		return "Libs"
	case modeRaw:
		return "Raw"
	case modeStrings:
		return "Strings"
	case modeSources:
		return "Sources"
	case modeRelocs:
		return "Relocs"
	}
	return "?"
}

// layoutState tracks terminal dimensions and the header viewport.
type layoutState struct {
	width, height int
}

// clearSymbolNameCaches drops caches whose layout depends on how symbol names
// render. Disasm instruction heights bake in the wrapped height of the "<name>:"
// label and the address annotations, so they must be recomputed when names change
// form — the background demangle finishing, or the global argument-abbreviation
// toggle. (Hex/raw and the disasm annotations themselves render live; the asm
// colour cache is keyed by raw instruction text, which carries no symbol name.)
func (m *Model) clearSymbolNameCaches() {
	m.disasmHeightCache = nil
	m.relocs.DropCaches() // reloc bind targets render demangled/abbreviated names
}

// clearAllViewCaches drops all row caches affected by global layout toggles.
func (m *Model) clearAllViewCaches() {
	m.symbols.DropCaches()
	m.sections.DropCaches()
	m.strs.DropCaches()
	m.srcLineHeightCache = nil
}

// clearColorCaches drops every cache whose entries bake in theme colours, so a
// theme change is reflected on the next render. (Height/column caches depend only
// on geometry, not colour, so they're left intact.)
func (m *Model) clearColorCaches() {
	m.viewStylesCache = nil
	m.modalStylesCache = nil
	m.clearAllViewCaches()
	m.disasmAsmCache = nil
	m.asmHL = nil
	m.sourceAsmRowCache = nil
	m.relocs.DropCaches()
	m.info.DropCaches() // restyle the Info page on the next render
}

// disasmState holds the currently loaded decode window only. The first window
// is loaded lazily on first open; later jumps replace it with a bounded span
// around the requested address so large binaries never expand into a whole-image
// instruction slice.
type disasmState struct {
	disasmInst          []disasm.Inst
	disasmBuilt         bool
	disasmDecoding      bool // background decode in flight
	disasmMaxBytes      int
	disasmSearchWorkers int
	disasmPendingAddr   uint64
	disasmInitAddr      uint64
	disasmTarget        string // configured landing/redirect strategy
	disasmPositioned    bool
	disasmCur           int
	disasmTop           int
	disasmPosLo         int
	disasmPosHi         int
	disasmSvc           *explorer.DisasmService
	showSource          bool
	sourceFirst         bool
	rightScroll         int // extra scroll offset for the follower (right) pane; 0 = auto-follow
	srcVP               viewport.Model
	srcHighlighter      *syntax.Highlighter
	sourceAsmRowCache   layout.RowMemo[sourceAsmRowCacheKey, string]
	disasmAsmCache      layout.RowMemo[disasmAsmCacheKey, string]
	// asmHL highlights instruction text. Which implementation it is depends on the
	// build tag (Chroma or the lite scanner); the shell only holds the interface.
	// Rebuilt, not mutated, when the theme changes.
	asmHL asmhl.Highlighter
	// disasmHeightCache memoizes per-instruction rendered height (it otherwise
	// re-renders each instruction to count rows, which the scroll math calls
	// dozens of times per wheel tick). Reset whenever disasmInst is replaced.
	disasmHeightCache layout.RowMemo[disasmHeightKey, int]
	// execSecStarts maps each executable section's start address to its name, so
	// the disasm scroller's per-row section-separator check is an O(1) lookup
	// instead of a scan over all sections. Built once (sections are immutable).
	execSecStarts map[uint64]string
}

// disasmHeightKey identifies a cached instruction height for one layout.
type disasmHeightKey struct {
	i    int
	w    int
	wrap bool
}

// sourceAsmRowCacheKey identifies a cached source/assembly mapping row.
type sourceAsmRowCacheKey struct {
	i    int
	w    int
	file string
	line int
}

// disasmAsmCacheKey identifies one highlighted instruction/comment string.
type disasmAsmCacheKey struct {
	text string
	addr uint64
	cls  disasm.InstClass
}

// historyState stores disassembly navigation history.
type historyState struct {
	// Last `historyCap` disasm jump targets. historyPos indicates where in that
	// ring we are; left arrow steps back, right arrow steps forward.
	history    []uint64
	historyPos int
}

// sourcePaneState stores the source-first disasm pane state. The Sources file
// list itself lives in views/sources.State; the split pane stays in the shell
// because it drives the disasm window and syntax highlighter.
type sourcePaneState struct {
	srcFile            string // open source file ("" = no source-first pane)
	srcCur             int    // 1-based current line in the open file
	srcTop             int
	srcCodeLines       map[int]bool // lines in srcFile that have machine code
	srcCodeLineCache   map[string]map[int]bool
	srcColumnCache     map[sourceLineCacheKey][]int
	srcLineHeightCache map[sourceLineHeightKey]int
	srcMatches         []srcMatch // last cross-source grep
	srcMatchIdx        int
	srcSearchAll       bool // scope of the next search in this view
}

// sourceLineCacheKey identifies cached line-column metadata.
type sourceLineCacheKey struct {
	file string
	line int
}

// sourceLineHeightKey identifies a cached wrapped source-line height. Source
// content is immutable once loaded, so width is the only layout input.
type sourceLineHeightKey struct {
	file string
	line int
	w    int
}

// interactionState stores cross-view input and viewport state.
type interactionState struct {
	// Global long-line wrap toggle (the `w` key). Views default to truncating to
	// preserve table geometry; turning wrap on lets them show full rows.
	wrap bool

	// treeCollapseDefault starts each view's tree fully collapsed the first time
	// it is built (config behavior.tree_collapsed).
	treeCollapseDefault bool

	// Mouse double-click tracking (for follow-on-double-click in disasm).
	lastClickY  int
	lastClickAt time.Time

	wheelSuppressUntil time.Time // drop continuing momentum after a mode change
	viewportDetached   bool      // mouse wheel scrolled the viewport without moving the caret

	// Wheel coalescing: a burst of wheel events (trackpad momentum) accumulates
	// into pendingWheel and is applied at most once per wheelCoalesceInterval via
	// a tick, so the flood of events drains cheaply instead of running an
	// expensive scroll+render per event and blocking clicks/keys behind it.
	pendingWheel int
	wheelTicking bool

	// Held-key coalescing: a held navigation key (j/k, [/], PgUp/PgDn) repeats
	// faster than a heavy view can render. Repeats accumulate into pendingKeyN
	// and are applied in one batch per keyCoalesceInterval, so the key-repeat
	// flood drains cheaply instead of rendering (and possibly re-decoding) per
	// event and blocking all other input behind it.
	pendingKey  string
	pendingKeyN int
	keyTicking  bool

	// Last top row/offset actually rendered for shell-owned scrollable views. Wheel
	// input starts from these screen snapshots so queued key/mouse events cannot
	// snap the first wheel step back to the caret-derived top.
	renderedDisasmTop int
	renderedSrcTop    int

	// pageRows is the active view's page size (items per screen) recorded at the
	// last render, so pgup/pgdown ([ / ]) advance by exactly one screen instead
	// of overshooting on chrome rows or wrapped multi-line entries.
	pageRows int

	// View output memoization. Bubble Tea calls View() after every message, so a
	// burst of wheel events that only accumulate (without changing what's shown)
	// would each recompute the whole screen. viewDirty defaults to true every
	// Update; the few no-op paths (wheel coalescing) clear it so View() can reuse
	// the last output instead of rebuilding it.
	viewCache string
	viewDirty bool
}

// setMode is the single place for mode-transition side effects. In particular,
// it suppresses ongoing momentum-wheel events so stale input from the previous
// view cannot scroll the newly selected one.
func (m *Model) setMode(md mode) {
	if m.mode == md {
		return
	}
	m.mode = md
	m.viewportDetached = false
	m.wheelSuppressUntil = time.Now().Add(wheelQuietInterval)
}

// gotoState stores modal state for address/symbol navigation.
type gotoState struct {
}

// jumpState stores what the shell keeps for the "open caret position in another
// view" overlay: the caret it was opened for. The overlay's own state (rows,
// selection) lives on m.jump (internal/ui/modals/jumpto).
type jumpState struct {
	jumpCaret caret
}

// findState stores the "Find from here" flow: a seed picker (candidate searches
// derived from the caret) feeding a global value search whose results — disasm
// operand references, data-word occurrences, string matches and reloc targets —
// are listed in one modal, tagged and filterable by the view they belong to.
// findState holds what the shell keeps for the global value search: the async
// bookkeeping for the per-source scans. The two overlays it drives — the
// free-text prompt and the results list — live in internal/ui/modals/findquery
// and internal/ui/modals/findresults.
type findState struct {
	findSeq    int
	findCancel chan struct{}
	// findQueryCase mirrors the prompt's case-sensitivity toggle, so a query typed
	// there is interpreted the same way the prompt showed it.
	findQueryCase bool
}

// searchState stores modal and async state for view searches.
// searchState holds what the shell keeps for the in-view search: the last query
// (so n/N can repeat it) and the async disasm-scan bookkeeping. The prompt and
// its toggles live on m.search (internal/ui/modals/search).
type searchState struct {
	searchQuery      string
	searchSeq        int
	searchCancel     chan struct{}
	searchRunning    bool
	searchCancelable bool
	searchResults    disasmSearchCache
	searchCursorMode int
	searchCursorAddr uint64
}

// settingsState holds the overlay geometry the shell still tracks. The settings
// popup's own state (selection, scroll, row→field map) lives on m.settings.
type settingsState struct {
	// modalListRow is the content row (within whichever overlay modal is open)
	// where its scrollable list/fields begin, set by that modal's render so a mouse
	// click can be mapped to an item. Only one modal is open at a time.
	modalListRow int
}

// statusState stores the footer status message.
type statusState struct {
	status      string
	statusError bool
	lastCopy    string // last text sent to the clipboard (test seam; see copyToClipboard)
	keyLog      bool   // EXEX_KEYLOG=1: echo each decoded keypress to the footer
}

// keyState stores resolved key bindings and aliases.
type keyState struct {
	keys keyMap
	// keyAlias maps user-configured per-view keys (copy/next/prev) to their
	// canonical tokens so the per-view handlers stay simple.
	keyAlias       map[string]string
	searchKeyAlias map[string]string
}

// Model is the root Bubble Tea model.
type Model struct {
	file  *binfile.File
	dis   disasm.Disassembler
	cfg   config.Config
	theme Theme

	// Cross-file exploration: fileStack holds the models we opened *from* (a
	// dependency / archive member / fat-arch slice each replace the whole model),
	// so Back can return to them with their state intact; fileLabel is this file's
	// breadcrumb name.
	fileStack []*Model
	fileLabel string

	mode mode

	// viewStylesCache is the lazily-built style/closure vocabulary shared with
	// the view packages (see viewStyles). Dropped on theme or settings changes.
	viewStylesCache *view.Styles
	// modalStylesCache is the same for the modal packages (see modalStyles).
	modalStylesCache *modal.Styles

	layoutState
	info     infoview.State
	sections sections.State
	symbols  symbols.State
	disasmState

	// demangledNames caches the background ComputeDemangled result so the
	// demangle setting can be toggled live without recomputing.
	demangledNames []string
	historyState
	byteViews hexraw.State
	libs      libs.State
	relocs    relocs.State
	strs      strs.State
	sources   sources.State
	sourcePaneState
	interactionState
	gotoState
	jumpState
	findState
	searchState
	settingsState
	xrefState
	syscallState
	cpufeatState
	// cpufeat is the CPU-features overlay (internal/ui/modals/cpufeat). Modals are
	// migrating to their own packages behind modal.Modal; cpufeatState above keeps
	// only the async bookkeeping for its background scan.
	cpufeat cpufeatmodal.State
	// settings is the preferences overlay (internal/ui/modals/settings); what a
	// change *means* stays in the shell (see settings.go).
	settings settingsmodal.State
	// jump is the "open caret position in…" overlay (internal/ui/modals/jumpto).
	jump jumptomodal.State
	// find is the "Find from here" seed picker (internal/ui/modals/findto).
	find findtomodal.State
	// palette is the "Jump to" command palette (internal/ui/modals/palette).
	palette palettemodal.State
	// findQuery is the free-text search prompt (internal/ui/modals/findquery).
	findQueryModal findquerymodal.State
	// findResults is the global-search results overlay (internal/ui/modals/findresults).
	findResults findresultsmodal.State
	// help is the keybinding cheat-sheet overlay (internal/ui/modals/help).
	help helpmodal.State
	// header is the raw container-header overlay (internal/ui/modals/rawheader).
	header rawheadermodal.State
	// search is the in-view search prompt (internal/ui/modals/search).
	search searchmodal.State
	// syscalls is the system-calls results overlay (internal/ui/modals/syscalls).
	syscalls syscallsmodal.State
	// xref is the cross-references results overlay (internal/ui/modals/xref).
	xref xrefmodal.State
	archiveState
	statusState
	keyState
}

// Options contains application-owned dependencies and policy values used to
// construct a UI model. Omitted options keep built-in defaults.
type Options struct {
	Config *config.Config
	// Goto is an optional startup target (an address like "0x1000" or a symbol
	// name) navigated to once the model is built, overriding the default view.
	Goto string
	// SearchString, when set, searches the printable strings on startup: a single
	// match opens the Hex (or Raw) view at it, several open the Strings view
	// filtered by it.
	SearchString string
}
