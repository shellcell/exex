// Package view is the neutral contract between the exex TUI shell (package ui)
// and the individual views. A view depends only on this package (plus layout and
// binfile), never on ui, so views can live in their own packages without an
// import cycle:
//
//   - Context is a per-frame snapshot of the render inputs a view needs, with the
//     shared presentation helpers (table header, empty states, scroll top) as
//     methods. The shell builds it each frame from its Theme and geometry.
//   - Host is the small set of mutating actions a view triggers on the shell
//     (status line, cross-view navigation, clipboard, wrap toggle). The shell
//     satisfies it.
//   - RowCacheKey is the shared key type for a view's per-row render memo.
package view

import (
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/ui/layout"
)

// Context is a per-frame snapshot of the inputs a view renders from, plus the
// presentation helpers that depend only on those inputs.
//
// Context is passed by value through every view helper, often per visible row,
// so it must stay small: the per-frame scalars live directly on it and the
// stable style/closure vocabulary hangs off the embedded *Styles, which the
// shell builds once and reuses until the theme or a display setting changes.
type Context struct {
	File     *binfile.File
	Width    int
	BodyH    int  // body height available to the view
	Wrap     bool // global long-line wrap toggle
	Detached bool // viewport scrolled independently of the cursor

	TreeCollapseDefault bool // the "start trees collapsed" setting

	*Styles // the cached style/closure vocabulary (see Styles)
}

// Styles is the stable part of a Context: the exported style vocabulary, the
// theme-derived classifier closures, and the display settings that only change
// through the settings modal. The shell's full Theme stays private to it; a
// view that needs another style adds a field here. One Styles is shared by
// every frame until the shell invalidates it (theme/settings change), keeping
// the by-value Context copies cheap (~13 KB of lipgloss.Style lives here, not
// on Context).
type Styles struct {
	// Row-rendering styles shared by the table views.
	HeaderStyle lipgloss.Style // the table header line background
	AddrStyle   lipgloss.Style // address / offset columns
	RowStyle    lipgloss.Style // ordinary table cell text
	SelStyle    lipgloss.Style // the selected (cursor) row
	SymStyle    lipgloss.Style // symbol / target names
	ShadowStyle lipgloss.Style // dim / secondary text
	FooterStyle lipgloss.Style // the filter / status row
	KeyStyle    lipgloss.Style // key hints in footers / clickable facet chips
	TreeStyle   lipgloss.Style // collapsible group rows in the name trees
	LabelStyle  lipgloss.Style // "Key:" labels in header blocks
	PanelStyle  lipgloss.Style // bordered overview panels
	NumberStyle lipgloss.Style // numeric values in overview text
	HeadStyle   lipgloss.Style // section headers in overview/help text
	InfoStyle   lipgloss.Style // positive status badges
	WarnStyle   lipgloss.Style // warning status badges
	ErrorStyle  lipgloss.Style // error/status-danger badges
	StickyStyle lipgloss.Style // sticky title/banner rows
	BannerStyle lipgloss.Style // section separator banners
	PtrStyle    lipgloss.Style // mapped pointer words in hex/raw
	LinkStyle   lipgloss.Style // active/followable pointer words

	DisassemblerName string // empty when this architecture has no decoder
	HexBytesPerRow   int
	HideAnnotations  bool
	ByteHex          *[256]string
	ByteASCII        *[256]string

	// Classifying styles the shell derives from its full theme; kept as
	// functions so the theme's colour tables stay private to it.
	SectionStyle func(*binfile.Section) lipgloss.Style                 // row colour by section type/flags
	SegmentStyle func(exec, write bool) lipgloss.Style                 // row colour by segment perms
	SymbolStyle  func(binfile.SymKind, binfile.SymBind) lipgloss.Style // row colour by symbol kind/bind

	// SectionAtOffset resolves the section whose file bytes cover a file
	// offset, via the shell's offset-sorted index (nil when unmapped).
	SectionAtOffset func(off uint64) *binfile.Section

	// PathStyle renders display in a colour chosen from keyPath's directory
	// prefix, so paths sharing a directory share a colour (theme-derived).
	PathStyle func(keyPath, display string) string
	// SymbolDisplay returns the shell-wide display spelling for a symbol name.
	SymbolDisplay func(binfile.Symbol) string
	// TargetAnnotation labels a mapped address with a symbol or section name.
	TargetAnnotation func(addr uint64) string
	// LMANote formats a section's physical/load address as a banner suffix.
	LMANote func(phys uint64) string
	// AddrForOffset maps a raw file offset to its virtual address, when allocated.
	AddrForOffset func(off uint64) (uint64, bool)

	// CanDisasmAt reports whether addr can be decoded by the current shell.
	CanDisasmAt func(addr uint64) bool
}

// AvailFilter is the availability lens applied to the Sources and Libs lists.
type AvailFilter uint8

const (
	AvailAll     AvailFilter = iota // show everything
	AvailPresent                    // sources: file on disk; libs: openable on disk
	AvailMissing                    // sources: not found on disk
	AvailCache                      // libs: served from the dyld shared cache
)

// AvailLabel is the short status-line label for an availability filter.
func AvailLabel(f AvailFilter) string {
	switch f {
	case AvailPresent:
		return "present"
	case AvailMissing:
		return "missing"
	case AvailCache:
		return "cache"
	default:
		return "all"
	}
}

// TableHeader renders a full-width, middle-truncated table header line.
func (c Context) TableHeader(s string) string {
	line := layout.PadRight(layout.FitANSIWidth(layout.TruncateMiddle(s, c.Width), c.Width), c.Width)
	return layout.RenderStyle(line, c.Width, c.HeaderStyle)
}

// PlaceCentred renders msg as a dim, centred block within the view width × h.
func (c Context) PlaceCentred(msg string, h int) string {
	w := layout.Clamp(c.Width-4, 1, 60)
	styled := c.ShadowStyle.Width(w).Align(lipgloss.Center).Render(msg)
	return lipgloss.Place(c.Width, max(1, h), lipgloss.Center, lipgloss.Center, styled)
}

// EmptyBody centres a dim message in the whole body area (no table chrome).
func (c Context) EmptyBody(msg string) string {
	return c.PlaceCentred(msg, c.BodyH)
}

// EmptyList keeps the leading rows (filter / column header) and centres a dim
// message in the body below them, so a fully-filtered table reads clearly.
func (c Context) EmptyList(msg string, leading ...string) string {
	rows := append(leading, strings.Split(c.PlaceCentred(msg, c.BodyH-len(leading)), "\n")...)
	return layout.PadBodyRows(rows, c.Width, c.BodyH)
}

// TreeNodeRow renders a collapsible group row: indent + arrow + coloured label +
// dim "(count)". Group nodes use the tree-node colour (not the leaf colours); a
// selected node is shown in reverse video of that colour (a coloured cursor cue),
// rather than the full-width white selection bar that leaf rows get. leftPad is
// the view's leading margin ("" for symbols, " " for sources/libs).
func (c Context) TreeNodeRow(depth int, label string, count int, collapsed, selected bool, leftPad string) string {
	indent := strings.Repeat(" ", depth*layout.TreeIndent)
	arrow := "▾ "
	if collapsed {
		arrow = "▸ "
	}
	style := c.TreeStyle
	if selected {
		style = style.Reverse(true)
	}
	cnt := ""
	if collapsed {
		cnt = fmt.Sprintf("  (%d)", max(count, 0)) // show the hidden-leaf count
	}
	avail := c.Width - len(leftPad) - len(indent) - 2 - ansi.StringWidth(cnt)
	if avail < 1 {
		avail = 1
	}
	return leftPad + indent + style.Render(arrow+layout.TruncateMiddle(label, avail)) + c.ShadowStyle.Render(cnt)
}

// VisualTop returns the row to anchor at the top for a variable-height list,
// honouring a detached (independent-scroll) viewport.
func (c Context) VisualTop(cur, top, n, visible int, rowHeight func(int) int) int {
	if c.Detached {
		return layout.ViewportTop(top, n, visible, rowHeight)
	}
	return layout.VisualTop(cur, top, n, visible, rowHeight)
}

// Host is the set of mutating actions a view triggers on the shell.
type Host interface {
	SetStatus(msg string, isErr bool)
	JumpHexAtAddr(addr uint64)
	JumpDisasmAtAddr(addr uint64)
	JumpRawAtAddr(addr uint64)
	OpenHexAt(addr uint64)
	OpenRawAt(off uint64)
	// OpenSymbol routes a symbol to the most useful view (disasm for functions,
	// hex otherwise), with the disasm-capability fallback logic in the shell.
	OpenSymbol(sym binfile.Symbol)
	// GotoAddr routes a mapped pointer/address to disasm or hex like the global
	// goto command does.
	GotoAddr(addr uint64)
	// OpenSymbolsForLib switches to the Symbols view filtered to the imports
	// bound to lib (the Libs view's Enter action).
	OpenSymbolsForLib(lib string)
	// OpenSourceFile switches to the Disasm view in source-first mode at file:1
	// (the Sources view's Enter/o action).
	OpenSourceFile(file string)
	// SymbolNamesChanged tells the shell that symbol display names changed form
	// (e.g. the argument-abbreviation toggle), so caches that bake in name
	// widths (disasm labels/annotations) must be dropped.
	SymbolNamesChanged()
	CopyToClipboard(text, label string)
	ToggleWrap()
	ListPage() int
	SetPageRows(n int)
}

// RowCacheKey identifies a rendered table-row variant: the item index plus every
// layout input that changes how a row renders.
type RowCacheKey struct {
	I     int
	Width int
	AddrW int
	Wrap  bool
}
