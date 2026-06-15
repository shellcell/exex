// Package ui implements the Bubble Tea TUI for exex.
package ui

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/atotto/clipboard"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/config"
	"github.com/rabarbra/exex/internal/disasm"
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

// Model is the root Bubble Tea model.
type Model struct {
	file *binfile.File
	dis  disasm.Disassembler

	mode mode

	width, height int

	// Header view.
	headerVP viewport.Model

	// Sections view.
	sections         []binfile.Section
	sectionsFilter   textinput.Model
	sectionsFiltered []int // indices into sections
	sectionsCur      int
	sectionsTop      int

	// Symbols view.
	symbolsFilter   textinput.Model
	symbolsFiltered []int // indices into file.Symbols (sorted by name)
	symbolsCur      int
	symbolsTop      int
	symbolsKind     binfile.SymKind
	symbolsKindOn   bool

	// Disasm view. disasmInst holds the currently loaded decode window only. The
	// first window is loaded lazily on first open; later jumps replace it with a
	// bounded span around the requested address so large binaries never expand
	// into a whole-image instruction slice.
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
	disasmCacheMu       sync.RWMutex
	disasmCache         map[disasmCacheKey]disasmCacheEntry
	disasmCacheOrder    []disasmCacheKey
	showSource          bool
	sourceFirst         bool
	srcVP               viewport.Model
	srcHL               map[string][]string // filename → per-line syntax-highlighted source

	// Navigation history for the disasm view: the last `historyCap` jump
	// targets, with `historyPos` indicating where in that ring we are. Left
	// arrow steps back, right arrow steps forward.
	history    []uint64
	historyPos int

	// Hex view (virtual-address): a continuous dump of every mapped section,
	// addressed by virtual address via hexImg.
	hexImg *binfile.Image
	hexCur int // byte position into hexImg.Data
	hexTop int // first row's byte position (multiple of bytesPerHexRow)

	// Raw view: the entire file dumped by file offset.
	rawData []byte
	rawCur  int
	rawTop  int

	// Libs view.
	libsCur int
	libsTop int

	// Strings view.
	stringsList []binfile.StringEntry
	stringsCur  int
	stringsTop  int

	// Sources view (DWARF only): a file list that opens into a source pane with
	// the mapped disassembly beside it.
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
	srcAsmLeft      bool // Sources open-file: disasm on the left, source on the right

	// Per-view long-line wrapping toggles. Views default to truncating to preserve
	// table geometry; the toggle lets source-heavy views show full rows when desired.
	wrap bool // global long-line wrap toggle (applies to every view)

	// Mouse double-click tracking (for follow-on-double-click in disasm).
	lastClickY  int
	lastClickAt time.Time

	// Go-to-address modal, with a live result list that updates as you type.
	gotoInput   textinput.Model
	gotoActive  bool
	gotoResults []gotoTarget
	gotoSel     int
	gotoTop     int // scroll offset into gotoResults

	// Search prompt (hex / raw / disasm), with last query remembered for n/N.
	searchInput      textinput.Model
	searchActive     bool
	searchQuery      string
	searchSeq        int
	searchRunning    bool
	searchCancelable bool
	searchResults    disasmSearchCache
	searchCursorMode int
	searchMode       int
	searchCursorAddr uint64
	searchForward    bool
	searchFromCursor bool

	// Transient status message displayed in the footer.
	status      string
	statusError bool

	// User-configurable keymap for the top-level dispatch.
	keys keyMap
	// keyAlias maps user-configured per-view keys (copy/next/prev) to their
	// canonical tokens so the per-view handlers stay simple.
	keyAlias       map[string]string
	searchKeyAlias map[string]string

	// helpActive toggles the keybinding cheat-sheet overlay.
	helpActive bool
}

func New(f *binfile.File) (*Model, error) {
	d, err := disasm.For(f.Arch())
	if err != nil {
		// Don't fail — the user can still browse header/sections/symbols.
		d = nil
	}

	// Load user config and overlay it before constructing styles/keymap.
	// A missing config file is fine (zero Config); a malformed one surfaces.
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	ApplyColors(cfg.Colors)
	keys := defaultKeyMap()
	keys.applyConfig(cfg.Keys)

	// Per-view copy/next/prev keys are configurable as aliases onto canonical
	// tokens the per-view handlers understand.
	keyAlias := map[string]string{}
	addAlias := func(ks config.StringOrSlice, canonical string) {
		for _, k := range ks {
			if k != "" {
				keyAlias[k] = canonical
			}
		}
	}
	addAlias(cfg.Keys.CopyAddress, "a")
	addAlias(cfg.Keys.CopySymbol, "s")
	addAlias(cfg.Keys.Next, "]")
	addAlias(cfg.Keys.Prev, "[")
	addAlias(cfg.Keys.CopyPath, "c")
	addAlias(cfg.Keys.OpenDisasm, "d")
	addAlias(cfg.Keys.Wrap, "w")
	addAlias(cfg.Keys.FilterType, "t")
	searchKeyAlias := map[string]string{}
	addSearchAlias := func(ks config.StringOrSlice, canonical string) {
		for _, k := range ks {
			if k != "" {
				searchKeyAlias[k] = canonical
			}
		}
	}
	addSearchAlias(cfg.Keys.SearchMode, "ctrl+m")
	addSearchAlias(cfg.Keys.SearchDirection, "ctrl+r")
	addSearchAlias(cfg.Keys.SearchOrigin, "ctrl+o")

	filter := textinput.New()
	filter.Placeholder = "type to filter…"
	filter.Prompt = "/ "
	filter.CharLimit = 256

	secFilter := textinput.New()
	secFilter.Placeholder = "type to filter…"
	secFilter.Prompt = "/ "
	secFilter.CharLimit = 256

	srcFilter := textinput.New()
	srcFilter.Placeholder = "type to filter…"
	srcFilter.Prompt = "/ "
	srcFilter.CharLimit = 256

	gotoInput := textinput.New()
	gotoInput.Placeholder = "0x401000 or symbol name"
	gotoInput.Prompt = "→ "
	gotoInput.CharLimit = 256

	searchInput := textinput.New()
	searchInput.Placeholder = "hex bytes (de ad be ef) or text"
	searchInput.Prompt = "/ "
	searchInput.CharLimit = 256

	m := &Model{
		file:                f,
		dis:                 d,
		mode:                modeInfo,
		disasmMaxBytes:      defaultDisasmMaxBytes,
		disasmSearchWorkers: 0,
		disasmCache:         map[disasmCacheKey]disasmCacheEntry{},
		sections:            f.Sections,
		sourcesFilter:       srcFilter,
		symbolsFilter:       filter,
		sectionsFilter:      secFilter,
		gotoInput:           gotoInput,
		searchInput:         searchInput,
		searchForward:       true,
		searchFromCursor:    true,
		showSource:          true,
		keys:                keys,
		keyAlias:            keyAlias,
		searchKeyAlias:      searchKeyAlias,
	}
	m.headerVP = viewport.New(0, 0)
	m.srcVP = viewport.New(0, 0)
	m.recomputeSymbols()
	m.recomputeSections()

	// The disassembly is decoded lazily on first open (it can be large); record
	// where the cursor should land — a guaranteed-executable address chosen by
	// the configured strategy (lowest executable address by default).
	m.disasmTarget = cfg.Behavior.DefaultDisasmTarget
	if m.disasmTarget == "" {
		m.disasmTarget = "lowest"
	}
	if cfg.Behavior.DisasmMaxBytes > 0 {
		m.disasmMaxBytes = cfg.Behavior.DisasmMaxBytes
	}
	if cfg.Behavior.DisasmSearchWorkers > 0 {
		m.disasmSearchWorkers = cfg.Behavior.DisasmSearchWorkers
	}
	m.disasmInitAddr = f.DefaultExecAddr(m.disasmTarget)

	// Open the configured default view (info when unset).
	m.switchMode(parseDefaultView(cfg.Behavior.DefaultView))
	return m, nil
}

// parseDefaultView maps a config view name to a mode, defaulting to Info.
func parseDefaultView(name string) mode {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "sections":
		return modeSections
	case "symbols":
		return modeSymbols
	case "disasm":
		return modeDisasm
	case "hex":
		return modeHex
	case "libs":
		return modeLibs
	case "raw":
		return modeRaw
	case "strings":
		return modeStrings
	case "sources":
		return modeSources
	}
	return modeInfo
}

func (m *Model) Init() tea.Cmd {
	// If the configured default view is Disasm, switchMode already flagged a
	// decode; kick it off here (New can't return a Cmd).
	if m.disasmDecoding && !m.disasmBuilt && m.dis != nil {
		return m.decodeDisasmCmd(m.disasmPendingAddr)
	}
	return nil
}

func (m *Model) setStatus(s string, isError bool) {
	m.status = s
	m.statusError = isError
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		bodyH := m.bodyHeight()
		m.headerVP.Width = m.width
		m.headerVP.Height = bodyH
		m.srcVP.Width = m.width / 2
		m.srcVP.Height = bodyH
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)

	case tea.MouseMsg:
		return m.handleMouse(msg)

	case disasmReadyMsg:
		// Ignore late delivery if a synchronous jump already loaded a newer span.
		if !m.disasmDecoding || msg.addr != m.disasmPendingAddr {
			return m, nil
		}
		m.disasmInst = msg.insts
		m.disasmPosLo = msg.posLo
		m.disasmPosHi = msg.posHi
		m.disasmBuilt = true
		m.disasmDecoding = false
		m.disasmPendingAddr = 0
		if len(m.disasmInst) == 0 {
			m.setStatus("no executable code to disassemble", true)
			return m, nil
		}
		if !m.disasmPositioned && m.disasmInitAddr != 0 {
			m.loadDisasmAt(m.disasmInitAddr)
		}
		return m, nil

	case disasmSearchProgressMsg:
		if !m.searchRunning || msg.seq != m.searchSeq {
			return m, nil
		}
		m.cacheDisasmSearchHits(msg.found, msg.forward)
		m.noteDisasmSearchCoverage(msg.scannedLo, msg.scannedHi)
		if msg.done {
			m.searchRunning = false
			m.searchCancelable = false
			if msg.hit != nil {
				m.setDisasmWindow(msg.hit.win, msg.hit.insts)
				m.disasmCur = msg.hit.idx
				m.disasmTop = msg.hit.idx
				m.disasmPositioned = true
				m.mode = modeDisasm
				m.searchCursorMode = searchCursorAtMatch
				m.searchCursorAddr = msg.hit.addr
				m.setStatus("match: "+strings.TrimSpace(msg.hit.text), false)
				return m, m.prefetchDisasmAroundCmd(msg.hit.addr)
			} else {
				if msg.next.forward {
					m.searchResults.forwardExhausted = true
					m.searchCursorMode = searchCursorAfterEnd
				} else {
					m.searchResults.backwardExhausted = true
					m.searchCursorMode = searchCursorBeforeStart
				}
				m.searchCursorAddr = 0
				m.setStatus("not found: "+m.searchQuery, true)
			}
			return m, nil
		}
		m.setStatus(msg.status, false)
		return m, m.searchDisasmStepCmd(msg.next)

	case disasmPrefetchMsg:
		return m, nil
	}
	return m, nil
}

func (m *Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	// The help overlay swallows the next keypress to dismiss itself.
	if m.helpActive {
		m.helpActive = false
		return m, nil
	}
	if m.searchRunning && key == "esc" {
		m.cancelSearch("search cancelled")
		return m, nil
	}

	// Modals own input while active.
	if m.gotoActive {
		switch key {
		case "esc":
			m.closeGoto()
			return m, nil
		case "up":
			if m.gotoSel > 0 {
				m.gotoSel--
			}
			return m, nil
		case "down":
			if m.gotoSel < len(m.gotoResults)-1 {
				m.gotoSel++
			}
			return m, nil
		case "enter":
			m.activateGoto()
			m.closeGoto()
			return m, nil
		}
		var cmd tea.Cmd
		m.gotoInput, cmd = m.gotoInput.Update(msg)
		m.recomputeGoto()
		return m, cmd
	}

	if m.searchActive {
		if c, ok := m.searchKeyAlias[key]; ok {
			key = c
		}
		switch key {
		case "esc":
			m.searchActive = false
			m.searchInput.Blur()
			return m, nil
		case "ctrl+r":
			m.searchForward = !m.searchForward
			return m, nil
		case "ctrl+o":
			m.searchFromCursor = !m.searchFromCursor
			return m, nil
		case "enter":
			m.searchQuery = strings.TrimSpace(m.searchInput.Value())
			m.searchActive = false
			m.searchInput.Blur()
			return m, m.runSearchFromPrompt()
		}
		var cmd tea.Cmd
		m.searchInput, cmd = m.searchInput.Update(msg)
		return m, cmd
	}

	// Filter input in symbols view captures typing keys.
	if m.mode == modeSymbols && m.symbolsFilter.Focused() {
		switch key {
		case "esc":
			m.symbolsFilter.Blur()
			return m, nil
		case "enter":
			m.symbolsFilter.Blur()
			return m, nil
		case "up", "down", "pgup", "pgdown", "home", "end":
			// Let navigation keys fall through.
		default:
			var cmd tea.Cmd
			m.symbolsFilter, cmd = m.symbolsFilter.Update(msg)
			m.recomputeSymbols()
			return m, cmd
		}
	}

	// Filter input in sections view captures typing keys.
	if m.mode == modeSections && m.sectionsFilter.Focused() {
		switch key {
		case "esc", "enter":
			m.sectionsFilter.Blur()
			return m, nil
		case "up", "down", "pgup", "pgdown", "home", "end":
			// Let navigation keys fall through.
		default:
			var cmd tea.Cmd
			m.sectionsFilter, cmd = m.sectionsFilter.Update(msg)
			m.recomputeSections()
			return m, cmd
		}
	}

	// Filter input in the sources file list captures typing keys.
	if m.mode == modeSources && m.srcFile == "" && m.sourcesFilter.Focused() {
		switch key {
		case "esc", "enter":
			m.sourcesFilter.Blur()
			return m, nil
		case "up", "down", "pgup", "pgdown", "home", "end":
			// Let navigation keys fall through.
		default:
			var cmd tea.Cmd
			m.sourcesFilter, cmd = m.sourcesFilter.Update(msg)
			m.recomputeSourceFiles()
			return m, cmd
		}
	}

	// '?' toggles the keybinding cheat-sheet (after modal/filter capture, so it
	// still types into inputs).
	if key == "?" {
		m.helpActive = true
		return m, nil
	}

	switch m.keys[key] {
	case actionQuit:
		return m, tea.Quit
	case actionViewInfo:
		return m, m.switchMode(modeInfo)
	case actionViewSections:
		return m, m.switchMode(modeSections)
	case actionViewSymbols:
		return m, m.switchMode(modeSymbols)
	case actionViewDisasm:
		return m, m.switchMode(modeDisasm)
	case actionViewHex:
		return m, m.switchMode(modeHex)
	case actionViewLibs:
		return m, m.switchMode(modeLibs)
	case actionViewRaw:
		return m, m.switchMode(modeRaw)
	case actionViewStrings:
		return m, m.switchMode(modeStrings)
	case actionViewSources:
		return m, m.switchMode(modeSources)
	case actionGoto:
		m.gotoActive = true
		m.gotoInput.Focus()
		m.recomputeGoto()
		return m, nil
	case actionToggleSource:
		switch m.mode {
		case modeDisasm:
			switch {
			case !m.showSource:
				m.showSource = true
				m.sourceFirst = false
			case !m.sourceFirst && m.ensureSourceForDisasmCursor():
				m.sourceFirst = true
			default:
				m.showSource = !m.showSource
				m.sourceFirst = false
			}
		case modeSources:
			// Swap which pane (source / disasm) is primary on the left.
			if m.srcFile != "" {
				m.srcAsmLeft = !m.srcAsmLeft
			}
		}
		return m, nil
	}

	// macOS keyboards often lack Home/End and dedicated PgUp/PgDn; accept the
	// emacs-style ctrl+a / ctrl+e as begin/end and Cmd+Up / Cmd+Down as page
	// up / page down (modals and filter inputs were handled above, so this only
	// affects view navigation).
	switch key {
	case "ctrl+a":
		key = "home"
	case "ctrl+e":
		key = "end"
	case "cmd+up", "super+up", "alt+up":
		key = "pgup"
	case "cmd+down", "super+down", "alt+down":
		key = "pgdown"
	}
	// Apply user key aliases (copy/next/prev) onto canonical tokens.
	if c, ok := m.keyAlias[key]; ok {
		key = c
	}

	switch m.mode {
	case modeSections:
		return m.updateSections(key)
	case modeSymbols:
		return m.updateSymbols(key)
	case modeDisasm:
		return m.updateDisasm(key)
	case modeHex:
		return m.updateHex(key)
	case modeRaw:
		return m.updateRaw(key)
	case modeStrings:
		return m.updateStrings(key)
	case modeSources:
		return m.updateSources(key)
	case modeLibs:
		return m.updateLibs(key)
	case modeInfo:
		return m.updateInfo(msg, key)
	}
	return m, nil
}

// copyToClipboard puts text on the system clipboard and reports success or
// failure to the user via the status footer.
func (m *Model) copyToClipboard(text, what string) {
	if err := clipboard.WriteAll(text); err != nil {
		m.setStatus(fmt.Sprintf("clipboard: %v", err), true)
		return
	}
	m.setStatus(fmt.Sprintf("copied %s: %s", what, text), false)
}

// gotoTarget is one selectable entry in the goto modal: either a symbol or a
// bare parsed address.
type gotoTarget struct {
	label string
	addr  uint64
	sym   binfile.Symbol
	isSym bool
}

// gotoMaxResults bounds how many matches we keep (the list scrolls);
// gotoVisible is how many rows the modal shows at once.
const (
	gotoMaxResults = 500
	gotoVisible    = 10
)

// recomputeGoto rebuilds the modal's result list from the current input. A
// parseable address is always offered first; symbols are matched (raw name and
// demangled name) and ranked exact → prefix → substring.
func (m *Model) recomputeGoto() {
	m.gotoResults = m.gotoResults[:0]
	m.gotoSel = 0
	m.gotoTop = 0
	val := strings.TrimSpace(m.gotoInput.Value())
	if val == "" {
		return
	}
	if a, err := parseAddr(val); err == nil {
		m.gotoResults = append(m.gotoResults, gotoTarget{label: "address", addr: a})
	}

	needle := strings.ToLower(val)
	type ranked struct {
		t    gotoTarget
		rank int
	}
	var matches []ranked
	for _, s := range m.file.Symbols {
		if s.Addr == 0 {
			continue
		}
		name, dem := strings.ToLower(s.Name), strings.ToLower(s.Demangled)
		hit := strings.Contains(name, needle) || (dem != "" && strings.Contains(dem, needle))
		if !hit {
			continue
		}
		rank := 2
		switch {
		case name == needle || dem == needle:
			rank = 0
		case strings.HasPrefix(name, needle) || strings.HasPrefix(dem, needle):
			rank = 1
		}
		matches = append(matches, ranked{gotoTarget{label: s.Display(), addr: s.Addr, sym: s, isSym: true}, rank})
	}
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].rank != matches[j].rank {
			return matches[i].rank < matches[j].rank
		}
		return matches[i].t.label < matches[j].t.label
	})
	for _, mt := range matches {
		if len(m.gotoResults) >= gotoMaxResults {
			break
		}
		m.gotoResults = append(m.gotoResults, mt.t)
	}
}

// activateGoto acts on the highlighted result, falling back to a bare address
// parse when there are no results.
func (m *Model) activateGoto() {
	addr, ok := m.gotoSelectionAddr()
	if !ok {
		m.setStatus("nothing to go to", true)
		return
	}
	// In the Sources view, goto navigates by source: resolve the target to its
	// source file:line and open it there.
	if m.mode == modeSources {
		m.openSourceForAddr(addr)
		return
	}
	if m.gotoSel >= 0 && m.gotoSel < len(m.gotoResults) && m.gotoResults[m.gotoSel].isSym {
		m.openSymbol(m.gotoResults[m.gotoSel].sym)
		return
	}
	m.gotoAddr(addr)
}

// gotoSelectionAddr returns the address of the highlighted result, falling back
// to a bare address typed into the prompt.
func (m *Model) gotoSelectionAddr() (uint64, bool) {
	if m.gotoSel >= 0 && m.gotoSel < len(m.gotoResults) {
		t := m.gotoResults[m.gotoSel]
		if t.isSym {
			return t.sym.Addr, true
		}
		return t.addr, true
	}
	if a, err := parseAddr(strings.TrimSpace(m.gotoInput.Value())); err == nil {
		return a, true
	}
	return 0, false
}

// openSourceForAddr opens the Sources view at the source location that addr
// maps to.
func (m *Model) openSourceForAddr(addr uint64) {
	file, line := m.file.LookupAddr(addr)
	if file == "" {
		m.setStatus(fmt.Sprintf("no source mapping for 0x%x", addr), true)
		return
	}
	m.ensureSources()
	m.openSourceFile(file, line)
}

func (m *Model) closeGoto() {
	m.gotoActive = false
	m.gotoInput.Blur()
	m.gotoInput.SetValue("")
	m.gotoResults = m.gotoResults[:0]
	m.gotoSel = 0
	m.gotoTop = 0
}

// gotoAddr jumps to a virtual address: disasm if it lands in executable code,
// otherwise the hex view if it lands in any mapped section.
func (m *Model) gotoAddr(addr uint64) {
	if _, ok := m.file.ExecImage().PosForAddr(addr); ok && m.dis != nil {
		m.loadDisasmAt(addr)
		return
	}
	if _, ok := m.file.VAImage().PosForAddr(addr); ok {
		m.openHexAt(addr)
		return
	}
	m.openRawAt(addr)
	m.setStatus(fmt.Sprintf("0x%x is not mapped; showing raw offset", addr), false)
}

func parseAddr(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return strconv.ParseUint(s[2:], 16, 64)
	}
	// Heuristic: any [a-f] means hex.
	for _, r := range s {
		if r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' {
			return strconv.ParseUint(s, 16, 64)
		}
	}
	return strconv.ParseUint(s, 10, 64)
}

// View renders the screen.
func (m *Model) View() string {
	if m.width == 0 || m.height == 0 {
		return "initializing…"
	}
	parts := []string{m.renderTabs()}
	body := ""
	switch m.mode {
	case modeInfo:
		body = m.renderInfo()
	case modeSections:
		body = m.renderSections()
	case modeSymbols:
		body = m.renderSymbols()
	case modeDisasm:
		body = m.renderDisasm()
	case modeHex:
		body = m.renderHex()
	case modeRaw:
		body = m.renderRaw()
	case modeStrings:
		body = m.renderStrings()
	case modeSources:
		body = m.renderSources()
	case modeLibs:
		body = m.renderLibs()
	}
	parts = append(parts, body, m.renderFooter())
	out := lipgloss.JoinVertical(lipgloss.Left, parts...)
	switch {
	case m.helpActive:
		out = m.overlayCenter(out, m.renderHelpModal())
	case m.gotoActive:
		out = m.overlayCenter(out, m.renderGotoModal())
	case m.searchActive:
		out = m.overlayCenter(out, m.renderSearchModal())
	}
	return out
}

// renderHelpModal lists the keybindings, grouped by scope.
func (m *Model) renderHelpModal() string {
	row := func(keys, desc string) string {
		return "  " + headerKey.Render(padKey(keys, 14)) + " " + desc
	}
	lines := []string{
		titleStyle.Render(" Keybindings "),
		"",
		headerKey.Render("Global"),
		row("1–9", "switch view"),
		row("g", "go to address / symbol (live list)"),
		row("q / ctrl+c", "quit"),
		row("? / any key", "close this help"),
		"",
		headerKey.Render("Lists (sections / symbols / strings / libs)"),
		row("↑/↓ j/k", "move    ·  PgUp/PgDn page"),
		row("Home/End", "begin/end  (also ctrl+a / ctrl+e)"),
		row("/", "filter (sections, symbols)"),
		row("Enter", "open / jump"),
		row("a / s", "copy address / name"),
		row("w", "toggle long-line wrap"),
		"",
		headerKey.Render("Sections"),
		row("Enter", "open section in Hex"),
		row("d", "disassemble executable section"),
		"",
		headerKey.Render("Symbols"),
		row("t", "cycle symbol type filter"),
		"",
		headerKey.Render("Disassembly"),
		row("↑/↓", "scroll    ·  ←/→ history back/forward"),
		row("[ / ]", "previous / next symbol"),
		row("Enter / dbl-click", "follow address"),
		row("/ , n/N", "search · next/prev match"),
		row("Tab", "toggle source pane"),
		"",
		headerKey.Render("Hex / Raw"),
		row("↑/↓/←/→", "move byte cursor"),
		row("d", "disassemble executable address"),
		row("[ / ]", "previous / next non-zero byte"),
		row("/ , n/N", "search (hex bytes, \"text\", 0x…)"),
		"",
		headerKey.Render("Sources (DWARF)"),
		row("Enter", "open file  ·  in file: jump to disasm"),
		row("[ / ]", "previous / next mapped line"),
		row("Tab", "swap source / disasm panes"),
		row("/ , ^F", "find in file · grep all sources"),
		row("c", "copy source path"),
		row("g", "go to a symbol's source"),
		"",
		footerStyle.Render("  Mouse: wheel scrolls · click selects · click tabs · double-click follows"),
	}
	return modalStyle.Render(strings.Join(lines, "\n"))
}

// overlayCenter draws a pre-rendered modal centred over bg.
func (m *Model) overlayCenter(bg, modal string) string {
	mw := lipgloss.Width(modal)
	mh := lipgloss.Height(modal)
	return overlay(bg, modal, (m.width-mw)/2, (m.height-mh)/2)
}

func (m *Model) renderGotoModal() string {
	var sb strings.Builder
	sb.WriteString("Go to address or symbol\n\n")
	sb.WriteString(m.gotoInput.View())
	sb.WriteString("\n")
	if len(m.gotoResults) == 0 {
		sb.WriteString("\n" + footerStyle.Render("type an address or symbol name") + "\n")
	} else {
		sb.WriteString("\n")
		addrW := m.file.AddrHexWidth()
		// Scroll the window so the selection stays visible.
		if m.gotoSel < m.gotoTop {
			m.gotoTop = m.gotoSel
		} else if m.gotoSel >= m.gotoTop+gotoVisible {
			m.gotoTop = m.gotoSel - gotoVisible + 1
		}
		end := m.gotoTop + gotoVisible
		if end > len(m.gotoResults) {
			end = len(m.gotoResults)
		}
		rowW := min(max(72, m.width-14), 120)
		labelW := rowW - addrW - 6
		for i := m.gotoTop; i < end; i++ {
			t := m.gotoResults[i]
			line := fmt.Sprintf(" 0x%0*x  %s", addrW, t.addr, truncateMiddle(t.label, labelW))
			line = padRight(line, rowW)
			if i == m.gotoSel {
				line = tableSelStyle.Render(line)
			}
			sb.WriteString(line + "\n")
		}
	}
	count := ""
	if n := len(m.gotoResults); n > 0 {
		count = fmt.Sprintf("  (%d/%d)", m.gotoSel+1, n)
	}
	sb.WriteString("\n" + footerStyle.Render("↑/↓ select · Enter jump · Esc cancel"+count))
	return modalStyle.Render(sb.String())
}

func (m *Model) renderSearchModal() string {
	hint := "Search this view"
	switch m.mode {
	case modeDisasm:
		hint = "Search instruction text / symbol"
	case modeHex, modeRaw:
		hint = "Search hex bytes (de ad be ef), \"text\", or 0x…"
	case modeSources:
		if m.srcSearchAll {
			hint = "Search across all source files"
		} else {
			hint = "Search in this source file"
		}
	}
	// Switch strip (content row searchSwitchLine) — clickable; geometry shared
	// with handleSearchPopupClick via searchSwitches().
	var segs []string
	for _, sw := range m.searchSwitches() {
		segs = append(segs, switchStyle.Render(sw.label))
	}
	switches := strings.Join(segs, searchSwitchSep)
	body := hint + "\n\n" + m.searchInput.View() + "\n\n" + switches + "\n" +
		footerStyle.Render("click a switch · Ctrl+M mode · Ctrl+R direction · Ctrl+O origin · Enter find · Esc cancel")
	return modalStyle.Render(body)
}

// tabItems is the ordered tab strip, shared by renderTabs (drawing) and
// tabHitTest (mouse mapping) so the two never drift apart.
var tabItems = []struct {
	label string
	mode  mode
}{
	{"1·Info", modeInfo},
	{"2·Sections", modeSections},
	{"3·Symbols", modeSymbols},
	{"4·Disasm", modeDisasm},
	{"5·Hex", modeHex},
	{"6·Libs", modeLibs},
	{"7·Raw", modeRaw},
	{"8·Strings", modeStrings},
	{"9·Sources", modeSources},
}

func (m *Model) tabSegment(label string, active bool) string {
	if active {
		return activeTabStyle.Render(label)
	}
	return tabStyle.Render(label)
}

// tabLead is the non-clickable prefix of the tab row: the tool name and a chip
// showing the detected container format (so the UI is honest that it isn't
// ELF-only). Shared by renderTabs and tabHitTest so their geometry matches.
func (m *Model) tabLead() []string {
	return []string{
		titleStyle.Render(" exex "),
		tabStyle.Render(string(m.file.Format)),
	}
}

func (m *Model) renderTabs() string {
	segs := m.tabLead()
	for _, t := range tabItems {
		segs = append(segs, m.tabSegment(t.label, m.mode == t.mode))
	}
	row := lipgloss.JoinHorizontal(lipgloss.Left, segs...)
	// Clamp to width: a too-wide tab strip would wrap and push the whole body
	// down a row (and the status line off-screen).
	return padRight(row, m.width)
}

// tabHitTest maps an x column on the tab row to the tab the user clicked.
func (m *Model) tabHitTest(x int) (mode, bool) {
	pos := 0
	for _, s := range m.tabLead() {
		pos += lipgloss.Width(s)
	}
	for _, t := range tabItems {
		w := lipgloss.Width(m.tabSegment(t.label, m.mode == t.mode))
		if x >= pos && x < pos+w {
			return t.mode, true
		}
		pos += w
	}
	return 0, false
}

// switchMode changes the active view, building the lazy state a view needs
// before it can render. Shared by the keyboard dispatch and tab clicks. It may
// return a Cmd (the background disasm decode).
func (m *Model) switchMode(md mode) tea.Cmd {
	switch md {
	case modeDisasm:
		if m.dis == nil {
			m.setStatus("no disassembler for this architecture", true)
			return nil
		}
		m.mode = modeDisasm
		if !m.disasmBuilt {
			// Decode the initial window in the background; later jumps decode a
			// fresh bounded span synchronously so targeted navigation lands
			// immediately.
			if !m.disasmDecoding {
				m.disasmDecoding = true
				m.disasmPendingAddr = m.disasmInitAddr
				return m.decodeDisasmCmd(m.disasmInitAddr)
			}
			return nil
		}
		// Already decoded: land on the entry the first time in.
		if !m.disasmPositioned && m.disasmInitAddr != 0 {
			m.loadDisasmAt(m.disasmInitAddr)
		}
		return nil
	case modeHex:
		m.ensureHex()
	case modeRaw:
		m.ensureRaw()
	case modeStrings:
		m.ensureStrings()
	case modeSources:
		m.ensureSources()
	}
	m.mode = md
	return nil
}

func (m *Model) renderFooter() string {
	// Footers stay short; the full cheat-sheet lives behind '?'.
	var help string
	switch m.mode {
	case modeInfo:
		help = "Enter disasm entry · g goto · ? help · q quit"
	case modeStrings:
		help = "Enter jump · / search · g goto · ? help · q quit"
	case modeSections:
		help = "Enter open · / filter · g goto · ? help · q quit"
	case modeSymbols:
		help = "Enter jump · / filter · g goto · ? help · q quit"
	case modeDisasm:
		help = "Enter follow · [ ] sym · ←/→ history · / search · g goto · ? help · q quit"
		if m.searchRunning {
			help = "Esc cancel search · [ ] sym · ←/→ history · / search · g goto · ? help · q quit"
		}
	case modeHex:
		help = "[ ] non-zero · / search · a/s copy · g goto · ? help · q quit"
	case modeRaw:
		help = "[ ] non-zero · / search · a/s copy · g goto · ? help · q quit"
	case modeSources:
		switch {
		case m.srcFile == "":
			help = "Enter open · / filter · ^F grep all · g goto · ? help · q quit"
		case m.srcAsmLeft:
			help = "↑/↓ instr · [ ] sym · Tab source · Enter follow · / find · esc back · ? help · q quit"
		default:
			help = "↑/↓ line · [ ] mapped · Tab disasm · Enter disasm · / find · esc back · ? help · q quit"
		}
	case modeLibs:
		help = "↑/↓ move · ? help · q quit"
	}
	left := footerStyle.Render(help)
	right := ""
	if m.status != "" {
		st := infoStyle
		if m.statusError {
			st = errorStyle
		}
		right = st.Render(m.status)
	}
	gap := m.width - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 1 {
		gap = 1
	}
	return padRight(left+strings.Repeat(" ", gap)+right, m.width)
}

// bodyHeight is the number of rows available between tabs and footer.
func (m *Model) bodyHeight() int {
	if m.height <= 2 {
		return 1
	}
	return m.height - 2
}

// ---- helpers ----

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// bytesHex renders up to maxN bytes as space-separated, per-byte-coloured hex.
// The output is padded with plain spaces to a fixed visible width so columns
// line up regardless of how many bytes the instruction occupied. Uses the
// precomputed byteHex table to avoid re-rendering ANSI codes on every byte.
func bytesHex(b []byte, maxN int) string {
	if len(b) > maxN {
		b = b[:maxN]
	}
	var sb strings.Builder
	for i, x := range b {
		if i > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(byteHex[x])
	}
	visible := len(b)*3 - 1
	if len(b) == 0 {
		visible = 0
	}
	want := maxN*3 - 1
	if visible < want {
		sb.WriteString(strings.Repeat(" ", want-visible))
	}
	return sb.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

func truncateMiddle(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if lipgloss.Width(stripANSI(s)) <= n {
		return s
	}
	if n <= 3 {
		return truncateANSI(s, n)
	}
	plain := stripANSI(s)
	left := (n - 1) / 2
	right := n - 1 - left
	if len(plain) <= n {
		return plain
	}
	return plain[:left] + "…" + plain[len(plain)-right:]
}

func wrapStatus(on bool) string {
	if on {
		return "wrap: on"
	}
	return "wrap: off"
}

// colorPathByPrefix renders display in a single colour chosen from keyPath's
// directory prefix, so paths sharing a directory share a colour. keyPath is the
// full path (used only for the colour key); display is what's drawn — which may
// be a middle-truncated form of the same path.
func colorPathByPrefix(keyPath, display string) string {
	if display == "" {
		return display
	}
	key := keyPath
	if i := strings.LastIndexByte(keyPath, '/'); i > 0 {
		key = keyPath[:i] // the directory
	}
	return pathPrefixStyle(key).Render(display)
}

func pathPrefixStyle(prefix string) lipgloss.Style {
	colors := []lipgloss.Color{"75", "114", "141", "173", "214", "213", "84", "39"}
	h := 0
	for i := 0; i < len(prefix); i++ {
		h = h*33 + int(prefix[i])
	}
	if h < 0 {
		h = -h
	}
	return lipgloss.NewStyle().Foreground(colors[h%len(colors)])
}

// padRight pads s to exactly w visible columns, truncating when it's longer so
// an over-wide line (e.g. a long demangled symbol) can't wrap and shove the
// layout down behind the status line.
func padRight(s string, w int) string {
	pw := lipgloss.Width(stripANSI(s))
	switch {
	case pw == w:
		return s
	case pw > w:
		// Truncate (width-aware) and pad any remainder — a wide rune straddling
		// the boundary can leave the result a cell short.
		s = truncateANSI(s, w)
		if d := w - lipgloss.Width(stripANSI(s)); d > 0 {
			s += strings.Repeat(" ", d)
		}
		return s
	default:
		return s + strings.Repeat(" ", w-pw)
	}
}

func padBody(s string, w, h int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > h {
		lines = lines[:h]
	}
	// Clamp every line to exactly w columns so nothing wraps and shoves the
	// layout (and the status line) down.
	for i, l := range lines {
		if lipgloss.Width(stripANSI(l)) != w {
			lines[i] = padRight(l, w)
		}
	}
	for len(lines) < h {
		lines = append(lines, strings.Repeat(" ", w))
	}
	return strings.Join(lines, "\n")
}

func padBodyRows(lines []string, w, h int) string {
	if len(lines) > h {
		lines = lines[:h]
	}
	for i, l := range lines {
		lines[i] = padRight(l, w)
	}
	for len(lines) < h {
		lines = append(lines, strings.Repeat(" ", w))
	}
	return strings.Join(lines, "\n")
}

func renderLineRows(line string, w int, wrap bool) []string {
	return renderLineRowsIndented(line, w, wrap, 0)
}

func renderLineRowsIndented(line string, w int, wrap bool, indent int) []string {
	if !wrap {
		return []string{padRight(line, w)}
	}
	if indent < 0 {
		indent = 0
	}
	if indent >= w {
		indent = max(0, w-1)
	}
	wrapped := ansi.Wrap(line, w, " \t/.-_:")
	rows := strings.Split(strings.TrimRight(wrapped, "\n"), "\n")
	if len(rows) == 0 {
		return []string{strings.Repeat(" ", w)}
	}
	for i := 0; i < len(rows); i++ {
		if lipgloss.Width(stripANSI(rows[i])) <= w {
			continue
		}
		hard := ansi.Wrap(rows[i], w, "")
		parts := strings.Split(strings.TrimRight(hard, "\n"), "\n")
		rows = append(rows[:i], append(parts, rows[i+1:]...)...)
		i += len(parts) - 1
	}
	if indent > 0 {
		prefix := strings.Repeat(" ", indent)
		contW := max(1, w-indent)
		indented := rows[:1]
		for _, row := range rows[1:] {
			cont := strings.TrimLeft(row, " ")
			if lipgloss.Width(stripANSI(cont)) > contW {
				cont = ansi.Wrap(cont, contW, " \t/.-_:")
			}
			parts := strings.Split(strings.TrimRight(cont, "\n"), "\n")
			if len(parts) == 0 {
				parts = []string{""}
			}
			for _, part := range parts {
				indented = append(indented, prefix+part)
			}
		}
		rows = indented
	}
	for i, row := range rows {
		rows[i] = padRight(row, w)
	}
	return rows
}

func appendRenderedRows(lines *[]string, line string, w int, wrap bool, limit int) bool {
	return appendRenderedRowsIndented(lines, line, w, wrap, 0, limit)
}

func appendRenderedRowsIndented(lines *[]string, line string, w int, wrap bool, indent int, limit int) bool {
	for _, row := range renderLineRowsIndented(line, w, wrap, indent) {
		if len(*lines) >= limit {
			return false
		}
		*lines = append(*lines, row)
	}
	return len(*lines) < limit
}

func ensureVisualTop(cur int, top *int, n, visible int, rowHeight func(int) int) {
	if n <= 0 {
		*top = 0
		return
	}
	if cur < 0 {
		cur = 0
	}
	if cur >= n {
		cur = n - 1
	}
	if *top < 0 || cur < *top {
		*top = cur
	}
	if *top >= n {
		*top = n - 1
	}
	for *top < cur && visualRowsBetween(*top, cur, rowHeight)+rowHeight(cur) > visible {
		*top++
	}
}

func visualRowsBetween(start, end int, rowHeight func(int) int) int {
	rows := 0
	for i := start; i < end; i++ {
		rows += max(1, rowHeight(i))
	}
	return rows
}

func visualItemAtRow(top, n, row int, rowHeight func(int) int) (int, bool) {
	if row < 0 {
		return 0, false
	}
	pos := 0
	for i := top; i < n; i++ {
		h := max(1, rowHeight(i))
		if row >= pos && row < pos+h {
			return i, true
		}
		pos += h
	}
	return 0, false
}

// overlay places fg over bg at column x, row y. Both are pre-rendered strings.
// It is ANSI- and width-aware: the background to the left and right of the
// modal keeps its colours and lines up correctly even when those lines contain
// styled or multi-byte content (e.g. the disasm source-pane border).
func overlay(bg, fg string, x, y int) string {
	if x < 0 {
		x = 0
	}
	if y < 0 {
		y = 0
	}
	bgLines := strings.Split(bg, "\n")
	fgLines := strings.Split(fg, "\n")
	for i, fl := range fgLines {
		row := y + i
		if row >= len(bgLines) {
			break
		}
		bgLine := bgLines[row]
		fw := ansi.StringWidth(fl)

		// Left slice: the first x cells of the background, padded if short.
		left := ansi.Truncate(bgLine, x, "")
		if w := ansi.StringWidth(left); w < x {
			left += strings.Repeat(" ", x-w)
		}
		// Right slice: the background beyond the modal, with its style preserved.
		right := ansi.TruncateLeft(bgLine, x+fw, "")

		bgLines[row] = left + "\x1b[0m" + fl + "\x1b[0m" + right
	}
	return strings.Join(bgLines, "\n")
}

// stripANSI removes ANSI escape sequences for width math. Cheap and good enough
// for our render strings, which only carry simple SGR codes from lipgloss.
func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && (s[j] < 0x40 || s[j] > 0x7e) {
				j++
			}
			if j < len(s) {
				j++
			}
			i = j - 1
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// fitANSIWidth keeps a styled string intact when it fits within w visible
// columns, and falls back to a plain truncation when it doesn't — so a single
// over-long source line can't break the side-by-side layout while normal-width
// lines retain their syntax colours.
func fitANSIWidth(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if lipgloss.Width(stripANSI(s)) <= w {
		return s
	}
	return truncateANSI(s, w)
}

// truncateANSI naively truncates while keeping the trailing SGR reset.
func truncateANSI(s string, w int) string {
	if w <= 0 {
		return ""
	}
	// ansi.Truncate is width- and escape-aware (and never splits a multi-byte
	// rune, unlike a naive byte slice), so it's safe for styled / Unicode text.
	return ansi.Truncate(s, w, "")
}
