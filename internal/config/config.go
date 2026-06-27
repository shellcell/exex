// Package config loads user customisation for exex: colour palette
// and top-level keybindings. The schema is YAML; the file lives at
// $XDG_CONFIG_HOME/exex/config.yaml (falling back to
// $HOME/.config/exex/config.yaml). Missing fields keep their
// built-in defaults, so a user can override a single entry without copying
// the whole schema.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config is the on-disk schema.
type Config struct {
	// Theme selects a built-in colour preset applied before the `colors`
	// overrides below: one of "nord" (default), "dark", "solarized-dark",
	// "solarized-light". Empty keeps the built-in Nord palette. Individual
	// `colors` entries always win over the preset.
	Theme    string   `yaml:"theme"`
	Colors   Colors   `yaml:"colors"`
	Keys     Keys     `yaml:"keys"`
	Behavior Behavior `yaml:"behavior"`
}

// Behavior holds non-visual preferences.
type Behavior struct {
	// View to open on startup: one of info, sections, symbols, disasm, hex,
	// raw, strings, libs, sources. Empty keeps the default (info).
	DefaultView string `yaml:"default_view"`
	// Where the disasm view lands by default, and where it redirects when asked
	// to show a non-executable address: one of entry, main, start, text, lowest.
	// Empty keeps the default (entry). Unresolvable choices fall back down the
	// list automatically.
	DefaultDisasmTarget string `yaml:"default_disasm_target"`
	// Maximum executable bytes to decode into disassembly at once. Empty/zero
	// keeps the built-in default (5 MiB). Global disasm navigation and search
	// slide this window through the executable image with overlap.
	DisasmMaxBytes int `yaml:"disasm_max_bytes"`
	// Number of parallel workers used by background disassembly search. Empty/
	// zero keeps the adaptive default.
	DisasmSearchWorkers int `yaml:"disasm_search_workers"`
	// Background tints the view/pane area with the theme's background colour.
	// Off by default (the UI uses the terminal background).
	Background bool `yaml:"background"`
	// DefaultWrap starts long-line wrapping enabled. The `w` key still toggles it
	// for the current session.
	DefaultWrap bool `yaml:"default_wrap"`
	// TreeSymbols/TreeSources/TreeLibs open that view as a collapsible
	// namespace/path tree instead of a flat list/table. The `f` key toggles each
	// for the current session.
	TreeSymbols bool `yaml:"tree_symbols"`
	TreeSources bool `yaml:"tree_sources"`
	TreeLibs    bool `yaml:"tree_libs"`
	// TreeCollapsed starts every tree fully collapsed (top-level groups only); the
	// `+`/`−` keys expand/collapse all for the session.
	TreeCollapsed bool `yaml:"tree_collapsed"`
	// AbbrevArgs starts the symbols view with "(…)"/"<…>" contents shown as "..."
	// (template arguments and parameter lists hidden). `d` toggles all and `.`
	// toggles the row under the cursor for the session.
	AbbrevArgs bool `yaml:"abbrev_args"`
	// The three disasm/hex display toggles below are stored in the negative sense
	// ("hide"/"spaced") so the zero value reproduces the historical default — a
	// bool can't tell "absent" from "false", and Save writes every field
	// explicitly. The settings modal presents them in the positive sense.
	//
	// HideDisasmBytes drops the raw instruction-byte column in the disasm view
	// (like objdump --no-show-raw-insn), reclaiming width for the code/source.
	HideDisasmBytes bool `yaml:"hide_disasm_bytes"`
	// HideAnnotations drops the symbol/target annotations in the disasm and hex
	// views.
	HideAnnotations bool `yaml:"hide_annotations"`
	// SpacedDisasmBytes separates instruction bytes with spaces ("01 00 00 14")
	// instead of the compact form ("01000014"), matching the `-o disasm` dump.
	SpacedDisasmBytes bool `yaml:"spaced_disasm_bytes"`
}

// Colors lists every visual element the user can re-skin. Empty strings mean
// "keep the default" — set only what you want to change.
//
// Color values use lipgloss syntax: either a #RRGGBB hex string ("#ff80c0")
// or an ANSI 256-colour index ("203"). See
// https://www.ditig.com/256-colors-cheat-sheet for the index palette.
//
// Names are intentionally verbose: each one says **where the colour appears**,
// so you can pick something specific without cross-referencing source.
type Colors struct {
	// ---- Disassembly: per-instruction-class mnemonic colour ---------------
	// Picked when the decoded mnemonic is `call`, `bl`, `jal`, etc.
	InstructionCall string `yaml:"instruction_call"`
	// Picked for `ret`, `iret`, etc.
	InstructionRet string `yaml:"instruction_ret"`
	// Unconditional jumps: `jmp`, `b`, `j` pseudo, ARM64 `br`.
	InstructionJumpUnconditional string `yaml:"instruction_jump_unconditional"`
	// Conditional jumps: `je`, `jne`, `b.eq`, `beq`/`bne`/etc.
	InstructionJumpConditional string `yaml:"instruction_jump_conditional"`
	// Syscall family: `syscall`, `sysenter`, `int`, `svc`, `ecall`, `brk`.
	InstructionSyscall string `yaml:"instruction_syscall"`
	// `nop` and friends.
	InstructionNop string `yaml:"instruction_nop"`
	// Default mnemonic colour for everything else.
	InstructionMnemonicDefault string `yaml:"instruction_mnemonic_default"`

	// ---- Disassembly: operand tokens (built-in highlighter) ---------------
	// Registers (rax, x0, %rdi, sp, …) in instruction operands.
	AsmRegister string `yaml:"asm_register"`
	// Immediate/numeric literals in operands ($0x10, #4, 0x20).
	AsmImmediate string `yaml:"asm_immediate"`
	// Move/load/store-family mnemonics in the built-in highlighter.
	AsmMove string `yaml:"asm_move"`
	// Arithmetic/logic/compare-family mnemonics in the built-in highlighter.
	AsmArith string `yaml:"asm_arith"`

	// ---- Disassembly: address columns + operand links ---------------------
	// The "0x401234" address column at the start of each disasm row.
	AddressColumn string `yaml:"address_column"`
	// Address operands that point inside the *current* symbol — local jumps,
	// loop heads, fall-through targets.
	AddressLinkIntraFunction string `yaml:"address_link_intra_function"`
	// Address operands that point into *another* symbol in this binary —
	// calls into other functions, PLT stubs, indirect references.
	AddressLinkInterFunction string `yaml:"address_link_inter_function"`

	// ---- Sticky "current symbol" banner above the disasm scroller --------
	StickySymbolBannerFG string `yaml:"sticky_symbol_banner_fg"`
	StickySymbolBannerBG string `yaml:"sticky_symbol_banner_bg"`

	// ---- Symbol-table view: row colour by ELF symbol type ----------------
	// STT_FUNC: actual functions.
	SymbolFunction string `yaml:"symbol_function"`
	// STT_OBJECT: data symbols (globals, statics).
	SymbolDataObject string `yaml:"symbol_data_object"`
	// STT_FILE: source filenames embedded by the compiler.
	SymbolSourceFile string `yaml:"symbol_source_file"`
	// STT_SECTION: symbols that name a whole section.
	SymbolSection string `yaml:"symbol_section"`
	// STT_TLS: thread-local-storage symbols.
	SymbolTLS string `yaml:"symbol_tls"`
	// STT_COMMON: uninitialised common-block symbols.
	SymbolCommon string `yaml:"symbol_common"`
	// STT_NOTYPE and unrecognised types.
	SymbolOther string `yaml:"symbol_other"`

	// ---- Section-table view: row colour by section semantics -------------
	// Executable code (SHF_EXECINSTR): .text, .plt, .init, …
	SectionExecutableCode string `yaml:"section_executable_code"`
	// Writable data (SHF_WRITE & SHF_ALLOC): .data, .bss, .got, …
	SectionWritableData string `yaml:"section_writable_data"`
	// Read-only allocated data (SHF_ALLOC only): .rodata, .interp, …
	SectionReadonlyData string `yaml:"section_readonly_data"`
	// Thread-local storage sections.
	SectionTLS string `yaml:"section_tls"`
	// .debug_*, .zdebug_* — DWARF and friends.
	SectionDebugInfo string `yaml:"section_debug_info"`
	// .note.* — build-id, ABI tag, GNU notes.
	SectionNote string `yaml:"section_note"`
	// SHT_SYMTAB/DYNSYM/STRTAB — symbol/string tables.
	SectionSymbolTable string `yaml:"section_symbol_table"`
	// SHT_DYNAMIC/HASH/GNU_*VERSION* — dynamic linking metadata.
	SectionDynamicLinking string `yaml:"section_dynamic_linking"`
	// SHT_REL/RELA — relocations.
	SectionRelocations string `yaml:"section_relocations"`

	// ---- Source pane: syntax-highlighting theme -------------------------
	// Name of a chroma style used to highlight the disasm view's source pane
	// (e.g. "monokai", "github-dark", "nord", "dracula", "catppuccin-mocha").
	// Unset follows the selected built-in theme where possible, otherwise keeps
	// the built-in default. Unknown names fall back gracefully.
	SyntaxTheme string `yaml:"syntax_theme"`

	// ---- Source pane: position + mapping highlight ----------------------
	// The current source line (cursor position) in the source pane.
	SourceCurrentLineFG string `yaml:"source_current_line_fg"`
	SourceCurrentLineBG string `yaml:"source_current_line_bg"`
	// A disasm address that maps to the current source line (when it has no
	// distinct column caret to colour it).
	SourceMappedFG string `yaml:"source_mapped_fg"`
	// Source lines that carry machine code, and addresses that map to some other
	// source line (the prominent "has code" colour).
	SourceCodeLineFG string `yaml:"source_code_line_fg"`
	// Unmapped lines / dimmed gutter text.
	SourceUnmappedFG string `yaml:"source_unmapped_fg"`
	// Palette cycled for the source↔disasm column-correlation highlight (carets,
	// column numbers, and the addresses mapping to each column). Empty keeps the
	// built-in palette.
	ColumnPalette []string `yaml:"column_palette"`

	// ---- View body: background for all view/pane content ------------------
	// The area between the tab strip and footer, including split panes.
	ViewBG string `yaml:"view_bg"`

	// ---- Window chrome: title, tab strip, footer ------------------------
	TitleFG     string `yaml:"title_fg"`
	TitleBG     string `yaml:"title_bg"`
	TabFG       string `yaml:"tab_fg"`
	TabActiveFG string `yaml:"tab_active_fg"`
	TabActiveBG string `yaml:"tab_active_bg"`
	FooterFG    string `yaml:"footer_fg"`
	// The "Key:" labels on the Info page and library/section headers.
	HeaderKeyFG string `yaml:"header_key_fg"`

	// ---- Tables (Sections / Symbols / Strings) --------------------------
	TableHeaderFG   string `yaml:"table_header_fg"`
	TableHeaderBG   string `yaml:"table_header_bg"`
	TableRowFG      string `yaml:"table_row_fg"`
	TableSelectedFG string `yaml:"table_selected_fg"`
	TableSelectedBG string `yaml:"table_selected_bg"`

	// ---- Shared accents -------------------------------------------------
	// Bold symbol names (entry symbol, libraries).
	SymbolNameFG string `yaml:"symbol_name_fg"`
	// The centred "==== .section ====" banner in the hex/raw views.
	SectionBannerFG string `yaml:"section_banner_fg"`

	// ---- Modal overlays + search switches -------------------------------
	ModalBorderFG  string `yaml:"modal_border_fg"`
	SearchSwitchFG string `yaml:"search_switch_fg"`
	SearchSwitchBG string `yaml:"search_switch_bg"`

	// ---- Help overlay ---------------------------------------------------
	HelpKeyFG  string `yaml:"help_key_fg"`
	HelpDescFG string `yaml:"help_desc_fg"`
	HelpHeadFG string `yaml:"help_head_fg"`

	// ---- Tree views (symbols/sources/libs collapsible groups) -----------
	TreeNodeFG string `yaml:"tree_node_fg"`

	// ---- Status footer messages -----------------------------------------
	StatusErrorFG string `yaml:"status_error_fg"`
	StatusInfoFG  string `yaml:"status_info_fg"`
	// Used for partial/weak hardening flags on the Info page.
	StatusWarnFG string `yaml:"status_warn_fg"`

	// ---- File-path colouring (Libraries / Sources views) ----------------
	// Palette cycled to colour paths by their directory prefix (paths sharing a
	// directory share a colour). Any number of entries; empty keeps the built-in
	// palette.
	PathPalette []string `yaml:"path_palette"`

	// ---- Hex / Raw byte colouring ---------------------------------------
	// Colour of pointer-sized words in the pointer-decode view (the `p` toggle)
	// that resolve to a mapped address. The word under the cursor (the one Enter
	// follows) uses the address-link colour instead; plain data keeps the
	// immediate/number colour.
	HexPointerFG string `yaml:"hex_pointer_fg"`
	// The per-byte colour ramp used by the hex and raw views. Must be exactly
	// 18 colours when set, applied as: [0]=0x00, [1..16]=high-nibble buckets
	// for 0x01..0xFE, [17]=0xFF. A shorter/empty list keeps the built-in ramp.
	HexBytePalette []string `yaml:"hex_byte_palette"`
}

// Keys binds string actions to one or more keys. Any entry can be a single
// key (`quit: q`) or a YAML sequence (`quit: [q, ctrl+c]`). Unset entries
// fall back to defaults.
//
// Action names describe *what the key does*; the default value is shown in
// parentheses next to each field's documentation. The keystroke format
// matches what Bubble Tea's tea.KeyMsg.String() returns ("ctrl+c", "tab",
// "enter", "left", "pgdown", letter/digit literals).
type Keys struct {
	// Exit the program. (default: q, ctrl+c)
	Quit StringOrSlice `yaml:"quit"`
	// Open the goto-address / goto-symbol modal. (default: g)
	Goto StringOrSlice `yaml:"goto"`
	// Switch to the Info view. (default: 1)
	ViewInfo StringOrSlice `yaml:"view_info"`
	// Switch to the Sections view. (default: 2)
	ViewSections StringOrSlice `yaml:"view_sections"`
	// Switch to the Symbols view. (default: 3)
	ViewSymbols StringOrSlice `yaml:"view_symbols"`
	// Switch to the Disasm view. (default: 4)
	ViewDisasm StringOrSlice `yaml:"view_disasm"`
	// Switch to the Hex view. (default: 5)
	ViewHex StringOrSlice `yaml:"view_hex"`
	// Switch to the Libs view. (default: 6)
	ViewLibs StringOrSlice `yaml:"view_libs"`
	// Switch to the Raw (file-offset) hex view. (default: 7)
	ViewRaw StringOrSlice `yaml:"view_raw"`
	// Switch to the Strings view. (default: 8)
	ViewStrings StringOrSlice `yaml:"view_strings"`
	// Switch to the Sources view (DWARF only). (default: 9)
	ViewSources StringOrSlice `yaml:"view_sources"`
	// Toggle the side-by-side source pane in Disasm. (default: tab)
	ToggleSource StringOrSlice `yaml:"toggle_source"`
	// Copy current address. (default: a)
	CopyAddress StringOrSlice `yaml:"copy_address"`
	// Copy current symbol name. (default: s)
	CopySymbol StringOrSlice `yaml:"copy_symbol"`
	// Next item: next symbol (disasm) / next non-zero byte (hex/raw). (default: ])
	Next StringOrSlice `yaml:"next"`
	// Previous item: prev symbol (disasm) / prev non-zero byte (hex/raw). (default: [)
	Prev StringOrSlice `yaml:"prev"`
	// Copy current path (sources/libs). (default: c)
	CopyPath StringOrSlice `yaml:"copy_path"`
	// Open selected address/section in disassembly when executable. (default: d)
	OpenDisasm StringOrSlice `yaml:"open_disasm"`
	// Toggle wrapping of long rows/lines. (default: w)
	Wrap StringOrSlice `yaml:"wrap"`
	// Cycle a view-specific type filter. (default: t)
	FilterType StringOrSlice `yaml:"filter_type"`
	// Cycle search popup mode (auto/text/hex where supported). (default: ctrl+t)
	SearchMode StringOrSlice `yaml:"search_mode"`
	// Toggle search popup direction. (default: ctrl+r)
	SearchDirection StringOrSlice `yaml:"search_direction"`
	// Toggle search popup origin. (default: ctrl+o)
	SearchOrigin StringOrSlice `yaml:"search_origin"`
	// Open the settings popup. (default: ,)
	Settings StringOrSlice `yaml:"settings"`
	// Tree views (symbols/sources/libs): expand / collapse the current group one
	// level. (defaults: right and left)
	TreeExpand   StringOrSlice `yaml:"tree_expand"`
	TreeCollapse StringOrSlice `yaml:"tree_collapse"`
	// Tree views: expand / collapse every group. (defaults: + and -)
	TreeExpandAll   StringOrSlice `yaml:"tree_expand_all"`
	TreeCollapseAll StringOrSlice `yaml:"tree_collapse_all"`
	// Copy the pointer-sized word under the cursor (hex/raw). (default: shift+p)
	CopyPointer StringOrSlice `yaml:"copy_pointer"`
	// Copy the disassembly of the current function (disasm). (default: shift+c)
	CopyFunction StringOrSlice `yaml:"copy_function"`
	// Copy the full current row, every column (all row views). (default: shift+l)
	CopyLine StringOrSlice `yaml:"copy_line"`
	// Go to the address under the cursor in the Hex view. (default: h)
	JumpHex StringOrSlice `yaml:"jump_hex"`
	// Go to the address under the cursor in the Raw view. (default: m)
	JumpRaw StringOrSlice `yaml:"jump_raw"`
	// Cycle the sort field (sections, symbols). (default: s)
	Sort StringOrSlice `yaml:"sort"`
	// Reverse the current sort order. (default: r)
	SortReverse StringOrSlice `yaml:"sort_reverse"`
	// Cycle the scope filter (symbols). (default: alt+s)
	FilterScope StringOrSlice `yaml:"filter_scope"`
	// Cycle the bind filter (symbols). (default: alt+b)
	FilterBind StringOrSlice `yaml:"filter_bind"`
	// Cycle the section filter (strings). (default: alt+s)
	FilterSection StringOrSlice `yaml:"filter_section"`
	// Cycle the flags filter (sections). (default: alt+f)
	FilterFlags StringOrSlice `yaml:"filter_flags"`
	// Cycle the availability filter (libs, sources). (default: alt+a)
	FilterAvail StringOrSlice `yaml:"filter_avail"`
	// Toggle the view's mode: tree/flat, sections/segments, ascii/pointers.
	// (default: t)
	ToggleMode StringOrSlice `yaml:"toggle_mode"`
	// Collapse/expand argument & template lists in symbol names. (default: e)
	AbbrevArgs StringOrSlice `yaml:"abbrev_args"`
	// Toggle the data inspector (hex, raw). (default: i)
	Inspector StringOrSlice `yaml:"inspector"`
	// Find cross-references to the cursor address (disasm). (default: x)
	Xref StringOrSlice `yaml:"xref"`
	// Open the selected library as primary / source in disasm. (default: o)
	OpenPrimary StringOrSlice `yaml:"open_primary"`
}

// StringOrSlice accepts either a YAML scalar ("q") or a sequence (["q",
// "ctrl+c"]) and normalises to a []string. Empty means "use default".
type StringOrSlice []string

// UnmarshalYAML satisfies yaml.v3's Unmarshaler interface.
func (s *StringOrSlice) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		var str string
		if err := value.Decode(&str); err != nil {
			return err
		}
		*s = []string{str}
	case yaml.SequenceNode:
		var arr []string
		if err := value.Decode(&arr); err != nil {
			return err
		}
		*s = arr
	default:
		return fmt.Errorf("expected scalar or sequence, got node kind %d", value.Kind)
	}
	return nil
}

// Default returns a zero Config — meaning "use built-in defaults everywhere".
// The ui package layers user values on top of its compiled-in defaults.
func Default() *Config { return &Config{} }

// Path returns the resolved config file path, regardless of whether it exists.
// Honours XDG_CONFIG_HOME with $HOME/.config as the fallback.
func Path() string {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "exex", "config.yaml")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "exex", "config.yaml")
}

// Save persists the live settings the in-app settings popup manages — theme,
// the background toggle, default wrap and the default view — to the config file
// at Path(), creating it (and its directory) if needed. It edits the YAML in place via
// nodes, so any other keys and comments already in the file are preserved.
// Returns the written path; a read-only location yields an error (the caller can
// keep the values in memory for the session).
func Save(theme string, beh Behavior) (string, error) {
	p := Path()
	if p == "" {
		return "", errors.New("no config path available")
	}
	var doc yaml.Node
	if data, err := os.ReadFile(p); err == nil {
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return "", fmt.Errorf("parse %s: %w", p, err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("read %s: %w", p, err)
	}

	root := yamlDocRoot(&doc)
	yamlSetScalar(root, "theme", theme, "!!str")
	node := yamlChildMap(root, "behavior")
	yamlBool := func(key string, v bool) {
		s := "false"
		if v {
			s = "true"
		}
		yamlSetScalar(node, key, s, "!!bool")
	}
	yamlBool("background", beh.Background)
	yamlBool("default_wrap", beh.DefaultWrap)
	yamlSetScalar(node, "default_view", beh.DefaultView, "!!str")
	yamlBool("tree_symbols", beh.TreeSymbols)
	yamlBool("tree_sources", beh.TreeSources)
	yamlBool("tree_libs", beh.TreeLibs)
	yamlBool("tree_collapsed", beh.TreeCollapsed)
	yamlBool("abbrev_args", beh.AbbrevArgs)
	yamlBool("hide_disasm_bytes", beh.HideDisasmBytes)
	yamlBool("hide_annotations", beh.HideAnnotations)
	yamlBool("spaced_disasm_bytes", beh.SpacedDisasmBytes)

	out, err := yaml.Marshal(&doc)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(p, out, 0o644); err != nil {
		return "", err
	}
	return p, nil
}

// yamlDocRoot returns the top-level mapping node, initialising an empty document.
func yamlDocRoot(doc *yaml.Node) *yaml.Node {
	if len(doc.Content) == 0 {
		m := &yaml.Node{Kind: yaml.MappingNode}
		doc.Kind = yaml.DocumentNode
		doc.Content = []*yaml.Node{m}
		return m
	}
	return doc.Content[0]
}

// yamlFindKey returns the index of key's value node within a mapping's Content.
func yamlFindKey(m *yaml.Node, key string) (int, bool) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return i + 1, true
		}
	}
	return 0, false
}

// yamlSetScalar sets or replaces key=val (with the given tag) in a mapping.
func yamlSetScalar(m *yaml.Node, key, val, tag string) {
	if vi, ok := yamlFindKey(m, key); ok {
		v := m.Content[vi]
		v.Kind, v.Tag, v.Value, v.Content = yaml.ScalarNode, tag, val, nil
		return
	}
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Value: key},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: val})
}

// yamlChildMap returns key's mapping node within m, creating it if needed.
func yamlChildMap(m *yaml.Node, key string) *yaml.Node {
	if vi, ok := yamlFindKey(m, key); ok {
		v := m.Content[vi]
		if v.Kind != yaml.MappingNode {
			v.Kind, v.Tag, v.Content = yaml.MappingNode, "!!map", nil
		}
		return v
	}
	child := &yaml.Node{Kind: yaml.MappingNode}
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: key}, child)
	return child
}

// Load reads and parses the config file. A missing file is not an error: it
// returns a zero Config (i.e. "use all defaults"). A malformed file IS an
// error so the user finds out about typos instead of silently getting the
// default for a key they tried to override.
func Load() (*Config, error) {
	p := Path()
	if p == "" {
		return Default(), nil
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Default(), nil
		}
		return nil, fmt.Errorf("read %s: %w", p, err)
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", p, err)
	}
	return &c, nil
}
