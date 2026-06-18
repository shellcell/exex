package ui

import (
	"time"

	"charm.land/bubbles/v2/textinput"
	"charm.land/bubbles/v2/viewport"
	"charm.land/lipgloss/v2"
	"github.com/alecthomas/chroma/v2"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/config"
	"github.com/rabarbra/exex/internal/disasm"
	"github.com/rabarbra/exex/internal/explorer"
	"github.com/rabarbra/exex/internal/syntax"
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
	}
	return "?"
}

// layoutState tracks terminal dimensions and the header viewport.
type layoutState struct {
	width, height int
	headerVP      viewport.Model
}

// sectionsState stores list/filter state for the Sections view.
type sectionsState struct {
	sections           []binfile.Section
	sectionsFilter     textinput.Model
	sectionsFiltered   []int // indices into sections
	sectionsCur        int
	sectionsTop        int
	sectionRowCache    map[rowCacheKey]string
	sectionHeightCache map[rowCacheKey]int
}

// rowCacheKey identifies a rendered table-row variant. The Sections, Symbols
// and Strings views all cache rows by the same coordinates: the item index plus
// every layout input that changes how a row renders.
type rowCacheKey struct {
	i     int
	width int
	addrW int
	wrap  bool
}

// symbolsState stores list/filter state for the Symbols view.
type symbolsState struct {
	symbolsFilter     textinput.Model
	symbolsFiltered   []int // indices into file.Symbols (sorted by name)
	symbolsCur        int
	symbolsTop        int
	symbolsKind       binfile.SymKind
	symbolsKindOn     bool
	symbolsLib        string // when set, show only imports bound to this library
	symbolRowCache    map[rowCacheKey][]string
	symbolHeightCache map[rowCacheKey]int
}

// clearSymbolCaches drops cached symbol rows and heights.
func (m *Model) clearSymbolCaches() {
	m.symbolRowCache = nil
	m.symbolHeightCache = nil
}

// clearSectionCaches drops cached section rows and heights.
func (m *Model) clearSectionCaches() {
	m.sectionRowCache = nil
	m.sectionHeightCache = nil
}

// clearStringCaches drops cached string rows and heights.
func (m *Model) clearStringCaches() {
	m.stringRowCache = nil
	m.stringHeightCache = nil
}

// clearAllViewCaches drops all row caches affected by global layout toggles.
func (m *Model) clearAllViewCaches() {
	m.clearSymbolCaches()
	m.clearSectionCaches()
	m.clearStringCaches()
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
	sourceAsmRowCache   map[sourceAsmRowCacheKey]string
	disasmAsmCache      map[disasmAsmCacheKey]string
	disasmTokenStyles   map[chroma.TokenType]lipgloss.Style
	// disasmHeightCache memoizes per-instruction rendered height (it otherwise
	// re-renders each instruction to count rows, which the scroll math calls
	// dozens of times per wheel tick). Reset whenever disasmInst is replaced.
	disasmHeightCache map[disasmHeightKey]int
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

// hexState stores cursor and viewport state for the mapped hex view.
type hexState struct {
	hexImg       *binfile.Image
	hexCur       int // byte position into hexImg.Data
	hexTop       int // first row's byte position
	hexPinnedTop int // section start pinned by jump/search until wheel scroll
	hexPinned    bool
}

// rawState stores cursor and viewport state for the raw file view.
type rawState struct {
	rawData      []byte
	rawCur       int
	rawTop       int
	rawPinnedTop int // section start pinned by jump/search until wheel scroll
	rawPinned    bool
}

// libsState stores cursor and viewport state for the Libraries view.
type libsState struct {
	libsCur int
	libsTop int
}

// stringsState stores list and cache state for printable strings.
type stringsState struct {
	stringsList       []binfile.StringEntry
	stringsCur        int
	stringsTop        int
	stringRowCache    map[rowCacheKey]string
	stringHeightCache map[rowCacheKey]int
}

// sourcesState stores file-list and open-file state for the Sources view.
type sourcesState struct {
	sourcesFiles     []string
	sourcesFilter    textinput.Model
	sourcesFiltered  []int
	sourcesCur       int
	sourcesTop       int
	srcFile          string // open source file ("" = showing the file list)
	srcCur           int    // 1-based current line in the open file
	srcTop           int
	srcCodeLines     map[int]bool // lines in srcFile that have machine code
	srcCodeLineCache map[string]map[int]bool
	srcColumnCache   map[sourceLineCacheKey][]int
	srcMatches       []srcMatch // last cross-source grep
	srcMatchIdx      int
	srcSearchAll     bool // scope of the next search in this view
}

// sourceLineCacheKey identifies cached line-column metadata.
type sourceLineCacheKey struct {
	file string
	line int
}

// interactionState stores cross-view input and viewport state.
type interactionState struct {
	// Global long-line wrap toggle (the `w` key). Views default to truncating to
	// preserve table geometry; turning wrap on lets them show full rows.
	wrap bool

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

	// Last top row/offset actually rendered for each scrollable view. Wheel input
	// starts from these screen snapshots so queued key/mouse events cannot snap
	// the first wheel step back to the caret-derived top.
	renderedSectionsTop int
	renderedSymbolsTop  int
	renderedDisasmTop   int
	renderedHexTop      int
	renderedRawTop      int
	renderedStringsTop  int
	renderedSourcesTop  int
	renderedLibsTop     int
	renderedSrcTop      int

	// helpActive toggles the keybinding cheat-sheet overlay.
	helpActive bool

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
	gotoInput   textinput.Model
	gotoActive  bool
	gotoResults []gotoTarget
	gotoSel     int
	gotoTop     int // scroll offset into gotoResults
}

// searchState stores modal and async state for view searches.
type searchState struct {
	searchInput      textinput.Model
	searchActive     bool
	searchQuery      string
	searchSeq        int
	searchRunning    bool
	searchCancelable bool
	searchResults    disasmSearchCache
	searchCursorMode int
	searchMode       searchMode
	searchCursorAddr uint64
	searchForward    bool
	searchFromCursor bool
}

// statusState stores the footer status message.
type statusState struct {
	status      string
	statusError bool
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

	mode mode

	layoutState
	sectionsState
	symbolsState
	disasmState
	historyState
	hexState
	rawState
	libsState
	stringsState
	sourcesState
	interactionState
	gotoState
	searchState
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
}
