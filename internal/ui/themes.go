package ui

// Built-in colour presets. A preset is just a config.Colors overlay applied on
// top of the default dark palette (see NewTheme), so adding a theme is purely a
// matter of listing colours — no second Theme literal to keep in sync.
//
// The Solarized values are Ethan Schoonover's canonical palette
// (https://ethanschoonover.com/solarized): exact hexes, not eyeballed, so the
// presets stay faithful without a terminal to preview them in.

import (
	"strings"

	"github.com/rabarbra/exex/internal/config"
	"github.com/rabarbra/exex/internal/theme"
)

// Solarized base tones + accents.
const (
	solBase03  = "#002b36" // darkest background
	solBase02  = "#073642" // background highlights
	solBase01  = "#6d8289" // comments / secondary content
	solBase00  = "#657b83" // body text (light bg)
	solBase0   = "#839496" // body text (dark bg)
	solBase1   = "#93a1a1" // emphasised text (dark bg)
	solBase2   = "#eee8d5" // background highlights (light bg)
	solBase3   = "#fdf6e3" // lightest background
	solYellow  = "#b58900"
	solOrange  = "#cb4b16"
	solRed     = "#dc322f"
	solMagenta = "#d33682"
	solViolet  = "#6c71c5"
	solBlue    = "#268bd2"
	solCyan    = "#2aa198"
	solGreen   = "#859900"
)

// Nord palette (https://www.nordtheme.com): Polar Night, Snow Storm, Frost,
// Aurora — canonical hexes.
const (
	nord0  = "#2e3440" // polar night (bg)
	nord1  = "#3b4252"
	nord2  = "#434c5e"
	nord3  = "#79808f" // muted / comments
	nord4  = "#d8dee9" // snow storm (body text)
	nord5  = "#e5e9f0"
	nord6  = "#eceff4" // brightest text
	nord7  = "#8fbcbb" // frost
	nord8  = "#88c0d0"
	nord9  = "#81a1c1"
	nord10 = "#5e81ac"
	nord11 = "#bf616a" // aurora red
	nord12 = "#d08770" // orange
	nord13 = "#ebcb8b" // yellow
	nord14 = "#a3be8c" // green
	nord15 = "#b48ead" // purple
)

const defaultThemeName = "nord"

func effectiveThemeName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return defaultThemeName
	}
	return name
}

// presetColors returns the colour overlay for a named theme. The three built-in
// names use hand-tuned palettes; any other name is matched against Chroma's
// style set (74 of them — dracula, monokai, github-dark, …) and derived into a
// full UI palette. An empty name is resolved before this function; unknown names
// keep the built-in dark defaults.
func presetColors(name string) config.Colors {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "dark":
		return config.Colors{}
	case "solarized-dark":
		c := solarized(solBase0, solBase1, solBase01, solBase02, solBase2, solBase3)
		c.SyntaxTheme = "solarized-dark"
		c.ViewBG = solBase03
		return c
	case "solarized-light":
		// Swap the content/background tones for a light terminal.
		c := solarized(solBase00, solBase01, solBase1, solBase2, solBase02, solBase03)
		c.SyntaxTheme = "solarized-light"
		c.ViewBG = solBase3
		return c
	case "nord":
		c := nord()
		c.SyntaxTheme = "nord"
		c.ViewBG = nord0
		return c
	}
	if p, ok := theme.PaletteFor(strings.TrimSpace(name)); ok {
		return deriveColors(strings.TrimSpace(name), p)
	}
	return config.Colors{}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// nonEmpty returns the non-empty values, preserving order.
func nonEmpty(vals ...string) []string {
	out := vals[:0:0]
	for _, v := range vals {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func paletteWithout(exclude string, vals ...string) []string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		if v != "" && !strings.EqualFold(v, exclude) {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nonEmpty(vals...)
	}
	return out
}

// deriveColors maps a Chroma palette onto every UI colour role, so any Chroma
// style themes the whole UI consistently. The scalar fg/bg roles come from the
// single colorBindings table; the few non-fg/bg roles are set below. `colors:`
// entries still override all of these.
func deriveColors(name string, p theme.Palette) config.Colors {
	d := newDerived(p)
	var c config.Colors
	for _, b := range colorBindings {
		setConfigColor(&c, b.key, b.derive(d))
	}
	c.SyntaxTheme = name // the Chroma source highlighter follows the same style
	c.ModalBorderFG = d.primary
	c.ColumnPalette = paletteWithout(d.header, p.Error, p.Number, p.String, p.Function, p.Type, p.Name, p.Operator)
	c.PathPalette = nonEmpty(p.Function, p.String, p.Number, p.Type, p.Keyword, p.Name)
	c.HexBytePalette = deriveHexRamp(p)
	return c
}

// deriveHexRamp builds the 18-entry hex byte ramp from a palette: 0x00 dim,
// 0xFF bright, the rest cycling through the accent colours.
func deriveHexRamp(p theme.Palette) []string {
	accents := nonEmpty(p.Error, p.Number, p.Function, p.String, p.Type, p.Name, p.Keyword, p.Operator)
	if len(accents) == 0 {
		return nil
	}
	ramp := make([]string, 18)
	ramp[0] = p.Comment
	for i := 1; i <= 16; i++ {
		ramp[i] = accents[(i-1)%len(accents)]
	}
	ramp[17] = p.Foreground
	for i := range ramp {
		if ramp[i] == "" {
			ramp[i] = p.Foreground
		}
	}
	return ramp
}

// nord maps the UI onto the Nord palette: Frost blues for structure/links,
// Aurora for instruction classes and status, Snow Storm for text.
func nord() config.Colors {
	return config.Colors{
		InstructionCall:              nord8,
		InstructionRet:               nord11,
		InstructionJumpUnconditional: nord13,
		InstructionJumpConditional:   nord15,
		InstructionSyscall:           nord14,
		InstructionNop:               nord3,
		InstructionMnemonicDefault:   nord4,
		AddressColumn:                nord3,
		AddressLinkIntraFunction:     nord7,
		AddressLinkInterFunction:     nord8,
		AsmRegister:                  nord8,
		AsmImmediate:                 nord12,
		AsmMove:                      nord7,
		AsmArith:                     nord15,
		StickySymbolBannerFG:         nord6,
		StickySymbolBannerBG:         nord1,
		SymbolFunction:               nord14,
		SymbolDataObject:             nord9,
		SymbolSourceFile:             nord3,
		SymbolSection:                nord15,
		SymbolTLS:                    nord10,
		SymbolCommon:                 nord12,
		SymbolOther:                  nord4,
		SectionExecutableCode:        nord14,
		SectionWritableData:          nord9,
		SectionReadonlyData:          nord8,
		SectionTLS:                   nord10,
		SectionDebugInfo:             nord3,
		SectionNote:                  nord3,
		SectionSymbolTable:           nord15,
		SectionDynamicLinking:        nord10,
		SectionRelocations:           nord12,
		SourceCurrentLineFG:          nord6,
		SourceCurrentLineBG:          nord10,
		SourceMappedFG:               nord8,
		SourceCodeLineFG:             nord6,
		SourceUnmappedFG:             nord3,
		ColumnPalette:                []string{nord11, nord13, nord14, nord15, nord7, nord12, nord10, nord5},
		TitleFG:                      nord6,
		TitleBG:                      nord10,
		TabFG:                        nord3,
		TabActiveFG:                  nord6,
		TabActiveBG:                  nord10,
		FooterFG:                     nord3,
		HeaderKeyFG:                  nord9,
		TreeNodeFG:                   nord9,
		TableHeaderFG:                nord6,
		TableHeaderBG:                nord1,
		TableRowFG:                   nord4,
		TableSelectedFG:              nord6,
		TableSelectedBG:              nord10,
		SymbolNameFG:                 nord13,
		SectionBannerFG:              nord13,
		ModalBorderFG:                nord8,
		SearchSwitchFG:               nord6,
		SearchSwitchBG:               nord2,
		HelpKeyFG:                    nord13,
		HelpDescFG:                   nord4,
		HelpHeadFG:                   nord8,
		StatusErrorFG:                nord11,
		StatusInfoFG:                 nord14,
		StatusWarnFG:                 nord13,
		HexBytePalette: []string{
			nord3,
			nord11, nord12, nord12, nord13, nord13,
			nord14, nord14, nord7, nord8, nord9,
			nord9, nord10, nord15, nord15, nord11,
			nord11, nord6,
		},
		PathPalette: []string{nord8, nord14, nord13, nord15, nord7},
	}
}

// solarized builds a Colors overlay from the four tone roles that flip between
// the light and dark variants: body text, emphasised text, muted text, the
// panel-highlight background, plus the high/low contrast extremes used for
// selected-row foregrounds and banner backgrounds.
func solarized(body, emph, muted, panelBG, contrastFG, edgeBG string) config.Colors {
	return config.Colors{
		// Disassembly: instruction classes.
		InstructionCall:              solBlue,
		InstructionRet:               solRed,
		InstructionJumpUnconditional: solYellow,
		InstructionJumpConditional:   solMagenta,
		InstructionSyscall:           solGreen,
		InstructionNop:               muted,
		InstructionMnemonicDefault:   body,
		// Disassembly: addresses + operand links + operand tokens.
		AddressColumn:            muted,
		AddressLinkIntraFunction: solCyan,
		AddressLinkInterFunction: solBlue,
		AsmRegister:              solCyan,
		AsmImmediate:             solOrange,
		AsmMove:                  solCyan,
		AsmArith:                 solViolet,
		// Sticky symbol banner.
		StickySymbolBannerFG: contrastFG,
		StickySymbolBannerBG: panelBG,
		// Symbol table.
		SymbolFunction:   solGreen,
		SymbolDataObject: solBlue,
		SymbolSourceFile: muted,
		SymbolSection:    solMagenta,
		SymbolTLS:        solViolet,
		SymbolCommon:     solOrange,
		SymbolOther:      body,
		// Section table.
		SectionExecutableCode: solGreen,
		SectionWritableData:   solBlue,
		SectionReadonlyData:   solCyan,
		SectionTLS:            solViolet,
		SectionDebugInfo:      muted,
		SectionNote:           muted,
		SectionSymbolTable:    solMagenta,
		SectionDynamicLinking: solViolet,
		SectionRelocations:    solOrange,
		// Source pane.
		SourceCurrentLineFG: contrastFG,
		SourceCurrentLineBG: solBlue,
		SourceMappedFG:      solCyan,
		SourceCodeLineFG:    emph,
		SourceUnmappedFG:    muted,
		ColumnPalette:       []string{solRed, solYellow, solGreen, solBlue, solMagenta, solCyan, solOrange, solViolet},
		// Chrome.
		TitleFG:     contrastFG,
		TitleBG:     solBlue,
		TabFG:       muted,
		TabActiveFG: contrastFG,
		TabActiveBG: solBlue,
		FooterFG:    muted,
		HeaderKeyFG: emph,
		TreeNodeFG:  solBlue,
		// Tables.
		TableHeaderFG:   contrastFG,
		TableHeaderBG:   panelBG,
		TableRowFG:      body,
		TableSelectedFG: contrastFG,
		TableSelectedBG: solBlue,
		// Shared accents.
		SymbolNameFG:    solYellow,
		SectionBannerFG: solYellow,
		// Modal + search switches.
		ModalBorderFG:  solBlue,
		SearchSwitchFG: contrastFG,
		SearchSwitchBG: panelBG,
		// Help.
		HelpKeyFG:  solYellow,
		HelpDescFG: body,
		HelpHeadFG: emph,
		// Status.
		StatusErrorFG: solRed,
		StatusInfoFG:  solGreen,
		StatusWarnFG:  solYellow,
		// Hex byte ramp: 0x00 muted, rainbow through the accents, 0xFF brightest.
		HexBytePalette: []string{
			muted,
			solRed, solOrange, solOrange, solYellow, solYellow,
			solGreen, solGreen, solCyan, solCyan, solBlue,
			solBlue, solViolet, solViolet, solMagenta, solMagenta,
			solRed, edgeBG,
		},
		// Path-prefix palette: a few accents so whole subtrees share a colour.
		PathPalette: []string{solBlue, solGreen, solYellow, solViolet, solCyan},
	}
}
