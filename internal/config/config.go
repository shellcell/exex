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
	Colors   Colors   `yaml:"colors"`
	Keys     Keys     `yaml:"keys"`
	Behavior Behavior `yaml:"behavior"`
}

// Behavior holds non-visual preferences.
type Behavior struct {
	// View to open on startup: one of info, sections, symbols, disasm, hex,
	// libs, raw, strings. Empty keeps the default (info).
	DefaultView string `yaml:"default_view"`
	// Where the disasm view lands by default, and where it redirects when asked
	// to show a non-executable address: one of entry, main, start, text, lowest.
	// Empty keeps the default (entry). Unresolvable choices fall back down the
	// list automatically.
	DefaultDisasmTarget string `yaml:"default_disasm_target"`
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
	// Unset keeps the built-in default. Unknown names fall back gracefully.
	SyntaxTheme string `yaml:"syntax_theme"`
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
