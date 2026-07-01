package ui

import (
	"time"

	"charm.land/bubbles/v2/textinput"
	"charm.land/bubbles/v2/viewport"
	"charm.land/lipgloss/v2"

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
	}
	return "?"
}

// layoutState tracks terminal dimensions and the header viewport.
type layoutState struct {
	width, height int
	headerVP      viewport.Model
}

// sectionsState stores list/filter state for the Sections view, which toggles
// between the section table and the coarser segment (memory-region) table.
type sectionsState struct {
	sections           []binfile.Section
	segments           []binfile.Segment
	showSegments       bool // the `t` toggle: list segments instead of sections
	sectionsFilter     textinput.Model
	sectionsFiltered   []int // indices into the active slice (sections or segments)
	sectionsCur        int
	sectionsTop        int
	sectionsSort       sectionSort // sort field for the (filtered) list
	sectionsSortDesc   bool        // reverse the active sort
	sectionsTypeOn     bool        // type-name column filter active
	sectionsType       string      // the type name it restricts to
	sectionsTypes      []string    // distinct type names, for cycling
	sectionsFlagsOn    bool        // flags column filter active
	sectionsFlags      string      // the flag string it restricts to
	sectionsFlagsList  []string    // distinct flag strings, for cycling
	sectionRowCache    rowMemo[rowCacheKey, string]
	sectionHeightCache rowMemo[rowCacheKey, int]
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

// rowMemo is a lazily-allocated memo cache for rendered rows (or their heights),
// keyed by K. It centralises the "nil-check → lookup → build → store" pattern the
// list/disasm renderers repeated by hand, so a renderer can't forget to allocate
// or to populate the cache, and invalidation is a single clear(). The zero value
// (nil map) is ready to use.
type rowMemo[K comparable, V any] map[K]V

// get returns the cached value for key, building and caching it on a miss.
func (m *rowMemo[K, V]) get(key K, build func() V) V {
	if *m == nil {
		*m = make(rowMemo[K, V])
	} else if v, ok := (*m)[key]; ok {
		return v
	}
	v := build()
	(*m)[key] = v
	return v
}

// clear drops all cached entries (next get rebuilds).
func (m *rowMemo[K, V]) clear() { *m = nil }

// symbolsState stores list/filter state for the Symbols view.
type symbolsState struct {
	symbolsFilter       textinput.Model
	symbolsFiltered     []int // indices into file.Symbols (sorted by name)
	symbolsCur          int
	symbolsTop          int
	symbolsKind         binfile.SymKind
	symbolsKindOn       bool
	symbolsBind         binfile.SymBind
	symbolsBindOn       bool
	symbolsScope        symbolScope     // all / internal (defined here) / imported (from libs)
	symbolsSort         symbolSort      // view order: name / address / size
	symbolsSortDesc     bool            // reverse the active sort (descending)
	symbolsLib          string          // when set, show only imports bound to this library
	symbolsTree         bool            // group names into a collapsible namespace tree (name sort)
	symbolsAbbrev       bool            // global: render "(…)"/"<…>" contents as "..."
	symbolsAbbrevExcept map[string]bool // per-row overrides inverting symbolsAbbrev
	symbolsCollapsed    map[string]bool // collapsed tree node paths (persist across rebuilds)
	symbolsCollapsedAlt map[string]bool // pre-filter collapse state, saved while a search filter is active
	symbolsFiltering    bool            // whether a search filter is currently narrowing the tree
	symbolsRoots        []*treeNode     // built tree; cached so collapse toggles only re-flatten
	symbolsRows         []treeRow       // flattened visible rows (tree nodes + leaves), nav/render unit
	symbolsReady        bool            // rows/tree have been built at least once
	symbolsTreeInit     bool            // collapse-default applied once
	symbolsByDisplay    []int           // all symbol indices sorted by Display(); built lazily
	demangledNames      []string        // cached ComputeDemangled result, for the live demangle toggle
	symbolFacets        []facetHit      // clickable toggle buttons on the status line (x ranges)
	symbolRowCache      rowMemo[rowCacheKey, []string]
	symbolHeightCache   rowMemo[rowCacheKey, int]
}

// facetKind identifies a clickable toggle button on the symbols status line.
type facetKind int

const (
	facetType facetKind = iota
	facetScope
	facetSort
	facetSortDir
	facetBind
	facetTree
	facetAbbrev
)

// facetHit is the screen-column span [start,end) of one clickable toggle button.
type facetHit struct {
	start, end int
	kind       facetKind
}

// clearSymbolCaches drops cached symbol rows and heights.
func (m *Model) clearSymbolCaches() {
	m.symbolRowCache = nil
	m.symbolHeightCache = nil
}

// clearSymbolNameCaches drops caches whose layout depends on how symbol names
// render. Disasm instruction heights bake in the wrapped height of the "<name>:"
// label and the address annotations, so they must be recomputed when names change
// form — the background demangle finishing, or the global argument-abbreviation
// toggle. (Hex/raw and the disasm annotations themselves render live; the asm
// colour cache is keyed by raw instruction text, which carries no symbol name.)
func (m *Model) clearSymbolNameCaches() {
	m.disasmHeightCache = nil
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
	m.srcLineHeightCache = nil
}

// clearColorCaches drops every cache whose entries bake in theme colours, so a
// theme change is reflected on the next render. (Height/column caches depend only
// on geometry, not colour, so they're left intact.)
func (m *Model) clearColorCaches() {
	m.clearAllViewCaches()
	m.disasmAsmCache = nil
	m.disasmTokenStyles = nil
	m.sourceAsmRowCache = nil
	m.relocRowCache = nil
	m.infoBody = "" // restyle the Info page on the next render
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
	sourceAsmRowCache   rowMemo[sourceAsmRowCacheKey, string]
	disasmAsmCache      rowMemo[disasmAsmCacheKey, string]
	// disasmTokenStyles caches Chroma token-type → style (default build only); it
	// is keyed by int(chroma.TokenType) so the model stays chroma-free for `lite`.
	disasmTokenStyles map[int]lipgloss.Style
	// disasmHeightCache memoizes per-instruction rendered height (it otherwise
	// re-renders each instruction to count rows, which the scroll math calls
	// dozens of times per wheel tick). Reset whenever disasmInst is replaced.
	disasmHeightCache rowMemo[disasmHeightKey, int]
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
	// rawSecByOff is the file-backed sections sorted by file offset, so the raw
	// view's per-row section lookups binary-search instead of scanning every
	// section. Built once (sections are immutable).
	rawSecByOff []*binfile.Section
}

// libsState stores cursor and viewport state for the Libraries view.
type libsState struct {
	libsCur       int
	libsTop       int
	libsTree      bool            // show needed libraries as a path tree
	libsCollapsed map[string]bool // collapsed directory paths
	libsRows      []treeRow       // flattened visible rows (dirs + libs)
	libsTreeInit  bool
	libsAvail     availFilter // availability filter: all / on-disk / in cache
	libsAvailKind map[string]availKind
	libsFilter    textinput.Model // name search (the `/` filter)
	libsSortDesc  bool            // reverse the (name) sort
}

// relocsState stores cursor, filter and cache state for the Relocations view.
type relocsState struct {
	relocCur      int             // cursor in the relocation table
	relocTop      int             // viewport top of the relocation table
	relocFilter   textinput.Model // symbol/type/section search (the `/` filter)
	relocFiltered []int           // indices into file.Relocations() after the filter
	relocSort     relocSortField  // sort field for the relocation table
	relocSortDesc bool            // reverse the relocation sort
	relocTypeOn   bool            // type-name facet filter active
	relocType     string          // the relocation type it restricts to
	relocTypes    []string        // distinct types, for cycling
	relocSecOn    bool            // section facet filter active
	relocSec      string          // the section it restricts to
	relocSecs     []string        // distinct sections, for cycling
	relocRowCache rowMemo[rowCacheKey, string]
}

// stringsState stores list, filter and cache state for printable strings.
type stringsState struct {
	stringsList       []binfile.StringEntry
	stringsFilter     textinput.Model
	stringsFiltered   []int // indices into stringsList
	stringsCur        int   // index into stringsFiltered
	stringsTop        int
	stringsSections   []string   // distinct owning-section names, for the section filter
	stringsSecOn      bool       // section filter active
	stringsSec        string     // the section name the filter restricts to
	stringsSort       stringSort // sort field for the (filtered) list
	stringsSortDesc   bool       // reverse the active sort
	stringsCompact    bool       // flow strings inline (· separated, no columns) vs the table
	stringsPathsOnly  bool       // show only path-like strings (filesystem paths / URLs)
	stringRowCache    rowMemo[rowCacheKey, string]
	stringHeightCache rowMemo[rowCacheKey, int]
}

// sourcesState stores file-list and open-file state for the Sources view.
type sourcesState struct {
	sourcesFiles       []string
	sourcesFilter      textinput.Model
	sourcesFiltered    []int
	sourcesCur         int
	sourcesTop         int
	sourcesTree        bool            // show the file list as a directory tree
	sourcesAvail       availFilter     // availability filter: all / present / missing
	sourcesSort        sourceSort      // flat-list order: project-first or name
	sourcesSortDesc    bool            // reverse the active sort
	sourcesCollapsed   map[string]bool // collapsed directory paths
	sourcesRows        []treeRow       // flattened visible rows (dirs + files)
	sourcesTreeInit    bool
	srcFile            string // open source file ("" = showing the file list)
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

	// hexNumeric switches the hex/raw views' trailing column from ASCII (default)
	// to the numeric interpretation selected by hexInterp. `t` toggles ascii vs
	// numeric; shift+t cycles the interpretation. The pointer-sized hex
	// interpretation resolves each word to the symbol/section it points at.
	hexNumeric bool
	hexInterp  int // index into hexInterps; -1 until initialised to the pointer width

	// hexInspect replaces the hex/raw banner with a data inspector that decodes
	// the bytes under the cursor as int/uint of every width, float, char and
	// pointer (the `i` key). It updates live as the cursor moves.
	hexInspect bool

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

	// pageRows is the active view's page size (items per screen) recorded at the
	// last render, so pgup/pgdown ([ / ]) advance by exactly one screen instead
	// of overshooting on chrome rows or wrapped multi-line entries.
	pageRows int

	// helpActive toggles the keybinding cheat-sheet overlay; helpScroll is its
	// vertical scroll offset when it is taller than the terminal.
	helpActive bool
	helpScroll int

	// headerActive toggles the raw container-header overlay (ELF e_*, Mach-O
	// mach_header + load commands, PE headers); headerScroll is its scroll offset.
	headerActive bool
	headerScroll int

	// infoBody caches the Info view's styled body (static per width/theme/arch);
	// infoBodyW is the width it was built for. Cleared on a theme change.
	infoBody  string
	infoBodyW int

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
	gotoInput    textinput.Model
	gotoActive   bool
	gotoResults  []gotoTarget
	gotoSel      int
	gotoTop      int       // scroll offset into gotoResults
	gotoScope    gotoScope // what the palette searches (all / symbols / sections / …)
	gotoAddrPhys bool      // interpret a typed address as physical (LMA), resolving to virtual
}

// searchState stores modal and async state for view searches.
type searchState struct {
	searchInput      textinput.Model
	searchActive     bool
	searchQuery      string
	searchSeq        int
	searchCancel     chan struct{}
	searchRunning    bool
	searchCancelable bool
	searchResults    disasmSearchCache
	searchCursorMode int
	searchMode       searchMode
	searchCursorAddr uint64
	searchForward    bool
	searchFromCursor bool
}

// settingsState stores state for the on-the-fly settings popup.
type settingsState struct {
	settingsActive bool
	settingsCur    int // selected field index (0..settingsFieldCount-1)
	settingsTop    int // first visible field when the list is taller than the window
	// settingsLineFields maps each rendered list line (from modalListRow) to its
	// field index, or -1 for a group header / blank separator. Rebuilt every render
	// so a mouse click lands on the right field despite the interspersed headers.
	settingsLineFields []int
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

	layoutState
	sectionsState
	symbolsState
	disasmState
	historyState
	hexState
	rawState
	libsState
	relocsState
	stringsState
	sourcesState
	interactionState
	gotoState
	searchState
	settingsState
	xrefState
	syscallState
	cpufeatState
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
