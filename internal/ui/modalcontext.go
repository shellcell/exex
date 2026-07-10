package ui

// The modal contract lives in internal/ui/modal (modal.Context + modal.Host), so
// a modal can depend on it without importing ui. This file is the shell side: it
// builds a modal.Context from the Model's Theme and geometry, and makes Model
// satisfy modal.Host.
//
// It mirrors viewcontext.go, which does the same for the top-level views.

import (
	"github.com/rabarbra/exex/internal/ui/modal"
	findquerymodal "github.com/rabarbra/exex/internal/ui/modals/findquery"
	findresultsmodal "github.com/rabarbra/exex/internal/ui/modals/findresults"
	findtomodal "github.com/rabarbra/exex/internal/ui/modals/findto"
	jumptomodal "github.com/rabarbra/exex/internal/ui/modals/jumpto"
	palettemodal "github.com/rabarbra/exex/internal/ui/modals/palette"
	searchmodal "github.com/rabarbra/exex/internal/ui/modals/search"
	settingsmodal "github.com/rabarbra/exex/internal/ui/modals/settings"
	"github.com/rabarbra/exex/internal/ui/view"
)

// The shell is the Host for every contract; assert it here so a change to any of
// them fails at this file rather than at a distant call site. A modal that needs
// more than modal.Host declares its own, embedding it (settings.Host).
var (
	_ modal.Host            = (*Model)(nil)
	_ view.Host             = (*Model)(nil)
	_ settingsmodal.Host    = (*Model)(nil)
	_ jumptomodal.Host      = (*Model)(nil)
	_ findtomodal.Host      = (*Model)(nil)
	_ palettemodal.Host     = (*Model)(nil)
	_ findquerymodal.Host   = (*Model)(nil)
	_ findresultsmodal.Host = (*Model)(nil)
	_ searchmodal.Host      = (*Model)(nil)
)

// modalContext snapshots the current model state for the open overlay. Unlike
// viewContext it carries the full terminal height, because an overlay is centred
// on the screen rather than laid out inside the view body.
func (m *Model) modalContext() modal.Context {
	return modal.Context{
		File:   m.file,
		Width:  m.width,
		Height: m.height,
		Styles: m.modalStyles(),
	}
}

// modalStyles returns the cached modal style vocabulary, building it on first
// use. Dropped by clearColorCaches on a theme change, like viewStyles.
func (m *Model) modalStyles() *modal.Styles {
	if m.modalStylesCache != nil {
		return m.modalStylesCache
	}
	t := m.theme
	m.modalStylesCache = &modal.Styles{
		Title: t.modalTitle,
		// lipgloss's Render is variadic; the contract wants a plain func(string).
		Frame:        func(s string) string { return t.modalStyle.Render(s) },
		Hint:         t.modalHint,
		SelStyle:     t.tableSelStyle,
		InfoStyle:    t.infoStyle,
		WarnStyle:    t.warnStyle,
		ShadowStyle:  t.srcShadowStyle,
		HeadingStyle: t.symbolNameStyle,
		AddrStyle:    t.addrStyle,
		KeyStyle:     t.helpKeyStyle,
		AccentStyle:  t.headerKey,
		RowStyle:     t.tableRowStyle,
		ErrorStyle:   t.errorStyle,
		SymbolStyle:  t.styleForSymbol,
		DescStyle:    t.helpDescStyle,
		HeadStyle:    t.helpHeadStyle,
		SwitchStyle:  t.switchStyle,
	}
	return m.modalStylesCache
}

// Model satisfies modal.Host. SetStatus is already provided for view.Host.
func (m *Model) LoadDisasmAt(addr uint64) { m.loadDisasmAt(addr) }
