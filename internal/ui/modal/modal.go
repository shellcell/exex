// Package modal is the neutral contract between the exex TUI shell (package ui)
// and the overlay modals, mirroring what package view is for the top-level views.
// A modal depends only on this package (plus layout and binfile), never on ui, so
// modals can live in their own packages without an import cycle.
//
//   - Context is a per-frame snapshot of the render inputs a modal needs. Unlike
//     view.Context it carries the full terminal Height, because an overlay is
//     centred on the screen rather than laid out inside the view body.
//   - Host is the small set of mutating actions a modal triggers on the shell.
//
// There is deliberately no Modal interface; see the note further down.
package modal

import (
	"strings"

	"charm.land/lipgloss/v2"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/ui/layout"
)

// Context is a per-frame snapshot of the inputs a modal renders from. It is
// passed by value, so the style vocabulary hangs off the embedded *Styles the
// shell builds once per theme change.
type Context struct {
	File   *binfile.File
	Width  int // terminal width
	Height int // terminal height
	*Styles
}

// Styles is the modal style vocabulary. The shell's full Theme stays private to
// it; a modal that needs another style adds a field here.
type Styles struct {
	// Title renders a modal's title bar, Hint its dim footer line, and Frame
	// wraps finished content in the modal's border and padding. They are
	// functions rather than lipgloss.Style values because the shell composes each
	// from more than one style.
	Title func(string) string
	Frame func(string) string
	Hint  func(string) string

	SelStyle     lipgloss.Style // the selected (cursor) row
	InfoStyle    lipgloss.Style // positive values / primary list text
	WarnStyle    lipgloss.Style // warning badges
	ErrorStyle   lipgloss.Style // error / danger badges
	ShadowStyle  lipgloss.Style // dim / secondary text
	HeadingStyle lipgloss.Style // group headings / symbol names
	AddrStyle    lipgloss.Style // addresses and offsets
	KeyStyle     lipgloss.Style // shortcut digits / key badges
	AccentStyle  lipgloss.Style // row markers and other small accents
	RowStyle     lipgloss.Style // ordinary list text
	DescStyle    lipgloss.Style // descriptive text beside a key or label
	SwitchStyle  lipgloss.Style // the value pill of a clickable toggle
	HeadStyle    lipgloss.Style // section headers inside a scrollable overlay

	// SymbolStyle colours a symbol row by its kind and binding, exactly as the
	// Symbols view does, so a symbol looks the same wherever it is listed. It is a
	// function because the theme's colour tables stay private to the shell.
	SymbolStyle func(binfile.SymKind, binfile.SymBind) lipgloss.Style
}

// ListWidth is the content width of a modal's list rows.
func (c Context) ListWidth() int { return layout.Clamp(c.Width-8, 40, 120) }

// AddrHexWidth is the hex digit count addresses are padded to for this binary.
func (c Context) AddrHexWidth() int { return c.File.AddrHexWidth() }

// Host is the base set of mutating actions any modal may trigger on the shell.
//
// A modal that needs more declares its own Host embedding this one, rather than
// this interface growing into the union of every modal's needs. The settings
// modal, for instance, needs to read and cycle setting values, which only it
// cares about.
type Host interface {
	SetStatus(msg string, isErr bool)
	// LoadDisasmAt moves the disassembly view to addr, recording history.
	LoadDisasmAt(addr uint64)
}

// There is deliberately no shared Modal interface, for the same reason package
// view has no View interface: the modals' Render and Update signatures genuinely
// differ (settings must read its values from its own Host; cpufeat needs none),
// so a common interface could only be bought by widening Host into a union type.
// The shell dispatches through the one modalOrder table instead, which is what
// actually keeps render, keys and mouse from disagreeing. Each modal follows the
// same conventional shape:
//
//	Active() bool
//	Close()
//	Render(ctx Context, …) string   // records ListRow for the mouse hit-test
//	List() (sel *int, top, n int, wrap, ok bool)
//	ListRow() int
//	ClickRow(listRow int) bool      // maps a clicked row to a selection
//	Update(…, key string) tea.Cmd
//	Activate(…) tea.Cmd             // Enter / double-click

// CenterLine horizontally centres a (possibly styled) line within width w,
// truncating instead when it is already too wide.
func CenterLine(s string, w int) string {
	sw := lipgloss.Width(s)
	if sw >= w {
		return layout.FitANSIWidth(s, w)
	}
	left := (w - sw) / 2
	return strings.Repeat(" ", left) + s + strings.Repeat(" ", w-sw-left)
}

// ClickIndex maps a clicked content row to a plain list's selection, reporting
// whether it hit an item. Modals whose rows correspond 1:1 to list items use it;
// settings, whose rows interleave group headers, maps rows itself.
func ClickIndex(sel *int, top, n, listRow int) bool {
	if idx := top + listRow; idx >= 0 && idx < n {
		*sel = idx
		return true
	}
	return false
}
