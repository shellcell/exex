package ui

import (
	"os"
	"strings"

	"charm.land/bubbles/v2/textinput"
	"charm.land/bubbles/v2/viewport"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/config"
	"github.com/rabarbra/exex/internal/disasm"
	"github.com/rabarbra/exex/internal/explorer"
	"github.com/rabarbra/exex/internal/syntax"
)

// New constructs a Bubble Tea model for a loaded binary.
func New(f *binfile.File, opts ...Options) (*Model, error) {
	d, err := disasm.For(f.Arch())
	if err != nil {
		// Don't fail — the user can still browse header/sections/symbols.
		d = nil
	}

	var cfg config.Config
	if len(opts) > 0 && opts[0].Config != nil {
		cfg = *opts[0].Config
	}

	filter := newPromptInput("type to filter…", "/ ")
	secFilter := newPromptInput("type to filter…", "/ ")
	srcFilter := newPromptInput("type to filter…", "/ ")
	strFilter := newPromptInput("type to filter…", "/ ")
	libFilter := newPromptInput("type to filter…", "/ ")
	relocFilter := newPromptInput("symbol · type · section", "/ ")
	gotoInput := newPromptInput("0x401000 or symbol name", "→ ")
	searchInput := newPromptInput("hex bytes (de ad be ef) or text", "/ ")
	sysFilter := newPromptInput("name · #num · symbol", "/ ")

	m := &Model{
		file:  f,
		dis:   d,
		cfg:   cfg,
		theme: NewTheme(cfg),
		mode:  modeInfo,
		layoutState: layoutState{
			headerVP: viewport.New(),
		},
		sectionsState: sectionsState{
			sections:       f.Sections,
			segments:       f.Segments,
			sectionsFilter: secFilter,
		},
		symbolsState: symbolsState{
			symbolsFilter: filter,
			symbolsTree:   cfg.Behavior.TreeSymbols,
			symbolsAbbrev: cfg.Behavior.AbbrevArgs,
		},
		disasmState: disasmState{
			disasmMaxBytes:      defaultDisasmMaxBytes,
			disasmSearchWorkers: 0,
			showSource:          true,
			srcVP:               viewport.New(),
			srcHighlighter:      syntax.NewHighlighter(sourceSyntaxTheme(cfg)),
		},
		stringsState: stringsState{
			stringsFilter: strFilter,
		},
		sourcesState: sourcesState{
			sourcesFilter: srcFilter,
			sourcesTree:   cfg.Behavior.TreeSources,
		},
		libsState: libsState{
			libsTree:   cfg.Behavior.TreeLibs,
			libsFilter: libFilter,
		},
		relocsState: relocsState{
			relocFilter: relocFilter,
		},
		gotoState: gotoState{
			gotoInput: gotoInput,
		},
		searchState: searchState{
			searchInput:      searchInput,
			searchForward:    true,
			searchFromCursor: true,
		},
		syscallState: syscallState{
			syscallFilter: sysFilter,
		},
		interactionState: interactionState{
			wrap:                cfg.Behavior.DefaultWrap,
			treeCollapseDefault: cfg.Behavior.TreeCollapsed,
			hexInterp:           -1, // resolved to the pointer-width hex on first use
		},
		keyState: newKeyState(cfg.Keys),
	}
	m.keyLog = os.Getenv("EXEX_KEYLOG") == "1"
	m.buildSectionFacets()
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
	// Narrow 64-bit addresses to 8 digits when they all fit in 32 bits, if asked.
	f.SetCompactAddr(cfg.Behavior.CompactAddresses)
	// Relocatable object files (and archive members) usually have no executable
	// section in the normal image; default them to disasm-all so their code shows.
	if d != nil && !f.HasExecCode() {
		f.SetDisasmAll(true)
	}
	m.disasmSvc = explorer.NewDisasmService(f, d, m.disasmMaxBytes, m.disasmSearchWorkers)
	m.disasmInitAddr = explorer.DefaultExecAddr(f, m.disasmTarget)

	// Open the configured default view (info when unset).
	m.switchMode(parseDefaultView(cfg.Behavior.DefaultView))

	// Startup CLI navigation overrides the default view.
	if len(opts) > 0 {
		if strings.TrimSpace(opts[0].Goto) != "" {
			m.gotoTargetString(opts[0].Goto)
		}
		if strings.TrimSpace(opts[0].SearchString) != "" {
			m.openStringSearch(opts[0].SearchString)
		}
	}
	return m, nil
}

// newPromptInput returns a consistently configured modal/filter input.
func newPromptInput(placeholder, prompt string) textinput.Model {
	in := textinput.New()
	in.Placeholder = placeholder
	in.Prompt = prompt
	in.CharLimit = 256
	return in
}

// newKeyState combines default key bindings with user-provided aliases.
func newKeyState(cfg config.Keys) keyState {
	keys := defaultKeyMap()
	keys.applyConfig(cfg)

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
	addAlias(cfg.CopyAddress, "A")
	addAlias(cfg.CopySymbol, "S")
	addAlias(cfg.CopyPath, "S")
	addAlias(cfg.CopyPointer, "P")
	addAlias(cfg.CopyFunction, "C")
	addAlias(cfg.CopyLine, "L")
	addAlias(cfg.Next, "]")
	addAlias(cfg.Prev, "[")
	addAlias(cfg.OpenDisasm, "d")
	addAlias(cfg.JumpHex, "h")
	addAlias(cfg.JumpRaw, "m")
	addAlias(cfg.Wrap, "w")
	addAlias(cfg.Sort, "s")
	addAlias(cfg.SortReverse, "r")
	addAlias(cfg.FilterType, "ctrl+t")
	addAlias(cfg.FilterScope, "ctrl+s")
	addAlias(cfg.FilterBind, "ctrl+b")
	addAlias(cfg.FilterSection, "ctrl+s")
	addAlias(cfg.FilterFlags, "ctrl+f")
	addAlias(cfg.FilterAvail, "ctrl+p")
	addAlias(cfg.ToggleMode, "t")
	addAlias(cfg.AbbrevArgs, "e")
	addAlias(cfg.Inspector, "i")
	addAlias(cfg.Xref, "x")
	addAlias(cfg.OpenPrimary, "o")
	// Tree expand/collapse aliases onto the canonical keys the list views handle.
	addAlias(cfg.TreeExpand, "right")
	addAlias(cfg.TreeCollapse, "left")
	addAlias(cfg.TreeExpandAll, "+")
	addAlias(cfg.TreeCollapseAll, "-")

	searchKeyAlias := map[string]string{}
	addSearchAlias := func(ks config.StringOrSlice, canonical string) {
		for _, k := range ks {
			if k != "" {
				searchKeyAlias[k] = canonical
			}
		}
	}
	addSearchAlias(cfg.SearchMode, "ctrl+t")
	addSearchAlias(cfg.SearchDirection, "ctrl+r")
	addSearchAlias(cfg.SearchOrigin, "ctrl+o")

	return keyState{
		keys:           keys,
		keyAlias:       keyAlias,
		searchKeyAlias: searchKeyAlias,
	}
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
