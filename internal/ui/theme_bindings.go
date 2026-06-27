package ui

// Single source of truth for the scalar (foreground/background) colour roles.
//
// Each role appears exactly once here, binding three things that used to be kept
// in sync by hand across DefaultTheme / ApplyColors / deriveColors:
//   - key:    the config.Colors YAML key the user overrides it with,
//   - target: which Theme style it tints (and whether fg or bg),
//   - derive: how it's computed from a Chroma palette.
//
// ApplyColors and deriveColors both just range over this table. (DefaultTheme
// still owns the built-in defaults, since those styles also carry non-colour
// attributes like Bold/Border.) Palette roles (path/column/hex) and the modal
// border live outside the table because they aren't a simple fg/bg on one style.

import (
	"reflect"
	"strings"

	"charm.land/lipgloss/v2"

	"github.com/rabarbra/exex/internal/config"
	"github.com/rabarbra/exex/internal/theme"
)

// derived holds a palette plus the handful of composite colours the role
// derivations reuse, computed once per theme.
type derived struct {
	p                              theme.Palette
	header, barFG, barBG, selectBG string
	primary                        string
}

func newDerived(p theme.Palette) derived {
	return derived{
		p:        p,
		header:   firstNonEmpty(p.Keyword, p.Type, p.Foreground, p.Function),
		barBG:    firstNonEmpty(p.Comment, p.Background, p.Number, p.Type, p.Keyword),
		barFG:    firstNonEmpty(p.Foreground, p.Background, p.Name, p.Function),
		selectBG: firstNonEmpty(p.Keyword, p.Type, p.Function, p.Number),
		primary:  firstNonEmpty(p.Function, p.Keyword, p.Foreground),
	}
}

type colorBinding struct {
	key    string                       // config.Colors YAML key
	def    string                       // built-in default colour
	target func(*Theme) *lipgloss.Style // style this role tints
	bg     bool                         // apply to Background instead of Foreground
	derive func(d derived) string       // colour from a Chroma palette
}

var colorBindings = []colorBinding{
	// Disasm: instruction classes.
	{"instruction_call", "39", func(t *Theme) *lipgloss.Style { return &t.classCallStyle }, false, func(d derived) string { return d.p.Function }},
	{"instruction_ret", "203", func(t *Theme) *lipgloss.Style { return &t.classRetStyle }, false, func(d derived) string { return d.p.Error }},
	{"instruction_jump_unconditional", "220", func(t *Theme) *lipgloss.Style { return &t.classJumpUncStyle }, false, func(d derived) string { return d.p.Number }},
	{"instruction_jump_conditional", "213", func(t *Theme) *lipgloss.Style { return &t.classJumpCndStyle }, false, func(d derived) string { return d.p.Keyword }},
	{"instruction_syscall", "84", func(t *Theme) *lipgloss.Style { return &t.classSyscallStyle }, false, func(d derived) string { return d.p.String }},
	{"instruction_nop", "240", func(t *Theme) *lipgloss.Style { return &t.classNopStyle }, false, func(d derived) string { return d.p.Comment }},
	{"instruction_mnemonic_default", "117", func(t *Theme) *lipgloss.Style { return &t.mnemonicStyle }, false, func(d derived) string { return d.p.Keyword }},
	// Disasm: address column + operand links + operand tokens.
	{"address_column", "245", func(t *Theme) *lipgloss.Style { return &t.addrStyle }, false, func(d derived) string { return d.p.Comment }},
	{"address_link_intra_function", "85", func(t *Theme) *lipgloss.Style { return &t.linkAddrIntraStyle }, false, func(d derived) string { return d.p.String }},
	{"address_link_inter_function", "51", func(t *Theme) *lipgloss.Style { return &t.linkAddrInterStyle }, false, func(d derived) string { return d.p.Type }},
	{"asm_register", "152", func(t *Theme) *lipgloss.Style { return &t.asmRegisterStyle }, false, func(d derived) string { return d.p.Name }},
	{"asm_immediate", "215", func(t *Theme) *lipgloss.Style { return &t.asmNumberStyle }, false, func(d derived) string { return d.p.Number }},
	{"asm_move", "80", func(t *Theme) *lipgloss.Style { return &t.asmMoveStyle }, false, func(d derived) string { return d.p.Type }},
	{"asm_arith", "176", func(t *Theme) *lipgloss.Style { return &t.asmArithStyle }, false, func(d derived) string { return d.p.Operator }},
	{"hex_pointer_fg", "75", func(t *Theme) *lipgloss.Style { return &t.hexPointerStyle }, false, func(d derived) string { return d.p.Function }},
	// Sticky symbol banner (fg + bg).
	{"sticky_symbol_banner_fg", "231", func(t *Theme) *lipgloss.Style { return &t.stickySymStyle }, false, func(d derived) string { return d.barFG }},
	{"sticky_symbol_banner_bg", "236", func(t *Theme) *lipgloss.Style { return &t.stickySymStyle }, true, func(d derived) string { return d.barBG }},
	// Symbol-table rows.
	{"symbol_function", "84", func(t *Theme) *lipgloss.Style { return &t.symFuncStyle }, false, func(d derived) string { return d.p.Function }},
	{"symbol_data_object", "75", func(t *Theme) *lipgloss.Style { return &t.symObjectStyle }, false, func(d derived) string { return d.p.Name }},
	{"symbol_source_file", "245", func(t *Theme) *lipgloss.Style { return &t.symFileStyle }, false, func(d derived) string { return d.p.Comment }},
	{"symbol_section", "213", func(t *Theme) *lipgloss.Style { return &t.symSectionStyle }, false, func(d derived) string { return d.p.Keyword }},
	{"symbol_tls", "177", func(t *Theme) *lipgloss.Style { return &t.symTLSStyle }, false, func(d derived) string { return d.p.Type }},
	{"symbol_common", "215", func(t *Theme) *lipgloss.Style { return &t.symCommonStyle }, false, func(d derived) string { return d.p.Number }},
	{"symbol_other", "250", func(t *Theme) *lipgloss.Style { return &t.symOtherStyle }, false, func(d derived) string { return d.p.Foreground }},
	// Section-table rows.
	{"section_executable_code", "84", func(t *Theme) *lipgloss.Style { return &t.secTextStyle }, false, func(d derived) string { return d.p.Function }},
	{"section_writable_data", "75", func(t *Theme) *lipgloss.Style { return &t.secDataStyle }, false, func(d derived) string { return d.p.Name }},
	{"section_readonly_data", "117", func(t *Theme) *lipgloss.Style { return &t.secRodataStyle }, false, func(d derived) string { return d.p.String }},
	{"section_tls", "177", func(t *Theme) *lipgloss.Style { return &t.secTLSStyle }, false, func(d derived) string { return d.p.Type }},
	{"section_debug_info", "240", func(t *Theme) *lipgloss.Style { return &t.secDebugStyle }, false, func(d derived) string { return d.p.Comment }},
	{"section_note", "245", func(t *Theme) *lipgloss.Style { return &t.secNoteStyle }, false, func(d derived) string { return d.p.Comment }},
	{"section_symbol_table", "213", func(t *Theme) *lipgloss.Style { return &t.secSymtabStyle }, false, func(d derived) string { return d.p.Keyword }},
	{"section_dynamic_linking", "141", func(t *Theme) *lipgloss.Style { return &t.secDynamicStyle }, false, func(d derived) string { return d.p.Type }},
	{"section_relocations", "173", func(t *Theme) *lipgloss.Style { return &t.secRelocStyle }, false, func(d derived) string { return d.p.Number }},
	// Source pane.
	{"source_current_line_fg", "231", func(t *Theme) *lipgloss.Style { return &t.srcCurLineStyle }, false, func(d derived) string { return d.p.Background }},
	{"source_current_line_bg", "63", func(t *Theme) *lipgloss.Style { return &t.srcCurLineStyle }, true, func(d derived) string { return d.selectBG }},
	{"source_mapped_fg", "153", func(t *Theme) *lipgloss.Style { return &t.srcMappedStyle }, false, func(d derived) string { return d.p.String }},
	{"source_unmapped_fg", "240", func(t *Theme) *lipgloss.Style { return &t.srcShadowStyle }, false, func(d derived) string { return d.p.Comment }},
	{"source_code_line_fg", "252", func(t *Theme) *lipgloss.Style { return &t.whiteStyle }, false, func(d derived) string { return d.p.Foreground }},
	// Window chrome.
	{"title_fg", "231", func(t *Theme) *lipgloss.Style { return &t.titleStyle }, false, func(d derived) string { return d.p.Background }},
	{"title_bg", "66", func(t *Theme) *lipgloss.Style { return &t.titleStyle }, true, func(d derived) string { return d.p.Function }},
	{"tab_fg", "245", func(t *Theme) *lipgloss.Style { return &t.tabStyle }, false, func(d derived) string { return d.p.Comment }},
	{"tab_active_fg", "231", func(t *Theme) *lipgloss.Style { return &t.activeTabStyle }, false, func(d derived) string { return d.p.Background }},
	{"tab_active_bg", "63", func(t *Theme) *lipgloss.Style { return &t.activeTabStyle }, true, func(d derived) string { return d.selectBG }},
	{"footer_fg", "245", func(t *Theme) *lipgloss.Style { return &t.footerStyle }, false, func(d derived) string { return d.p.Comment }},
	{"header_key_fg", "75", func(t *Theme) *lipgloss.Style { return &t.headerKey }, false, func(d derived) string { return d.header }},
	// Tables.
	{"table_header_fg", "231", func(t *Theme) *lipgloss.Style { return &t.tableHeaderStyle }, false, func(d derived) string { return d.barFG }},
	{"table_header_bg", "236", func(t *Theme) *lipgloss.Style { return &t.tableHeaderStyle }, true, func(d derived) string { return d.barBG }},
	{"table_row_fg", "252", func(t *Theme) *lipgloss.Style { return &t.tableRowStyle }, false, func(d derived) string { return d.p.Foreground }},
	{"table_selected_fg", "231", func(t *Theme) *lipgloss.Style { return &t.tableSelStyle }, false, func(d derived) string { return d.p.Background }},
	{"table_selected_bg", "63", func(t *Theme) *lipgloss.Style { return &t.tableSelStyle }, true, func(d derived) string { return d.selectBG }},
	// Shared accents.
	{"symbol_name_fg", "214", func(t *Theme) *lipgloss.Style { return &t.symbolNameStyle }, false, func(d derived) string { return d.primary }},
	{"section_banner_fg", "214", func(t *Theme) *lipgloss.Style { return &t.sectionStyle }, false, func(d derived) string { return d.primary }},
	// Search switches.
	{"search_switch_fg", "231", func(t *Theme) *lipgloss.Style { return &t.switchStyle }, false, func(d derived) string { return d.p.Background }},
	{"search_switch_bg", "238", func(t *Theme) *lipgloss.Style { return &t.switchStyle }, true, func(d derived) string { return d.selectBG }},
	// Help overlay.
	{"help_key_fg", "214", func(t *Theme) *lipgloss.Style { return &t.helpKeyStyle }, false, func(d derived) string { return d.primary }},
	{"help_desc_fg", "252", func(t *Theme) *lipgloss.Style { return &t.helpDescStyle }, false, func(d derived) string { return d.p.Foreground }},
	{"help_head_fg", "117", func(t *Theme) *lipgloss.Style { return &t.helpHeadStyle }, false, func(d derived) string { return d.header }},
	{"tree_node_fg", "75", func(t *Theme) *lipgloss.Style { return &t.treeNodeStyle }, false, func(d derived) string { return d.p.Name }},
	// Status footer.
	{"status_error_fg", "203", func(t *Theme) *lipgloss.Style { return &t.errorStyle }, false, func(d derived) string { return d.p.Error }},
	{"status_info_fg", "114", func(t *Theme) *lipgloss.Style { return &t.infoStyle }, false, func(d derived) string { return d.p.String }},
	{"status_warn_fg", "214", func(t *Theme) *lipgloss.Style { return &t.warnStyle }, false, func(d derived) string { return d.p.Number }},
	// View body background (no built-in default; opt-in only).
	{"view_bg", "", func(t *Theme) *lipgloss.Style { return &t.viewStyle }, true, func(d derived) string { return d.p.Background }},
}

// applyDefaults paints every binding's built-in default colour onto t. Styles
// keep whatever non-colour attributes (Bold/Border/…) they were created with.
func (t *Theme) applyDefaults() {
	for _, b := range colorBindings {
		b.apply(t, b.def)
	}
	t.deriveDisasmSel()
}

// applyColorString sets a role's colour on its target style (fg or bg).
func (b colorBinding) apply(t *Theme, color string) {
	if color == "" {
		return
	}
	s := b.target(t)
	if b.bg {
		*s = s.Background(lipgloss.Color(color))
	} else {
		*s = s.Foreground(lipgloss.Color(color))
	}
}

// --- config.Colors reflection by YAML key (built once) ---------------------

var colorFieldIndex = func() map[string]int {
	m := map[string]int{}
	rt := reflect.TypeOf(config.Colors{})
	for i := 0; i < rt.NumField(); i++ {
		if rt.Field(i).Type.Kind() != reflect.String {
			continue
		}
		key := strings.Split(rt.Field(i).Tag.Get("yaml"), ",")[0]
		if key != "" {
			m[key] = i
		}
	}
	return m
}()

func configColor(c config.Colors, key string) string {
	if i, ok := colorFieldIndex[key]; ok {
		return reflect.ValueOf(c).Field(i).String()
	}
	return ""
}

func setConfigColor(c *config.Colors, key, val string) {
	if i, ok := colorFieldIndex[key]; ok {
		reflect.ValueOf(c).Elem().Field(i).SetString(val)
	}
}
