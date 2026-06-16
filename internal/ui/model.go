package ui

import (
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/config"
	"github.com/rabarbra/exex/internal/disasm"
	"github.com/rabarbra/exex/internal/explorer"
	"github.com/rabarbra/exex/internal/syntax"
)

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

const defaultDisasmMaxBytes = 2 << 20

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

type layoutState struct {
	width, height int
	headerVP      viewport.Model
}

type sectionsState struct {
	sections         []binfile.Section
	sectionsFilter   textinput.Model
	sectionsFiltered []int // indices into sections
	sectionsCur      int
	sectionsTop      int
}

type symbolsState struct {
	symbolsFilter   textinput.Model
	symbolsFiltered []int // indices into file.Symbols (sorted by name)
	symbolsCur      int
	symbolsTop      int
	symbolsKind     binfile.SymKind
	symbolsKindOn   bool
	symbolsLib      string // when set, show only imports bound to this library
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
}

type historyState struct {
	// Last `historyCap` disasm jump targets. historyPos indicates where in that
	// ring we are; left arrow steps back, right arrow steps forward.
	history    []uint64
	historyPos int
}

type hexState struct {
	hexImg *binfile.Image
	hexCur int // byte position into hexImg.Data
	hexTop int // first row's byte position (multiple of bytesPerHexRow)
}

type rawState struct {
	rawData []byte
	rawCur  int
	rawTop  int
}

type libsState struct {
	libsCur int
	libsTop int
}

type stringsState struct {
	stringsList []binfile.StringEntry
	stringsCur  int
	stringsTop  int
}

type sourcesState struct {
	sourcesFiles    []string
	sourcesFilter   textinput.Model
	sourcesFiltered []int
	sourcesCur      int
	sourcesTop      int
	srcFile         string // open source file ("" = showing the file list)
	srcCur          int    // 1-based current line in the open file
	srcTop          int
	srcCodeLines    map[int]bool // lines in srcFile that have machine code
	srcMatches      []srcMatch   // last cross-source grep
	srcMatchIdx     int
	srcSearchAll    bool // scope of the next search in this view
}

type interactionState struct {
	// Global long-line wrap toggle (the `w` key). Views default to truncating to
	// preserve table geometry; turning wrap on lets them show full rows.
	wrap bool

	// Mouse double-click tracking (for follow-on-double-click in disasm).
	lastClickY  int
	lastClickAt time.Time

	// helpActive toggles the keybinding cheat-sheet overlay.
	helpActive bool
}

type gotoState struct {
	gotoInput   textinput.Model
	gotoActive  bool
	gotoResults []gotoTarget
	gotoSel     int
	gotoTop     int // scroll offset into gotoResults
}

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

type statusState struct {
	status      string
	statusError bool
}

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
}
