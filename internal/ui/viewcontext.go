package ui

// The view contract lives in internal/ui/view (view.Context + view.Host), so a
// view can depend on it without importing ui. This file is the shell side: it
// builds a view.Context from the Model's Theme and geometry each frame, and makes
// Model satisfy view.Host.

import (
	"charm.land/lipgloss/v2"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/ui/view"
)

// viewContext snapshots the current model state for the active view. The
// returned Context is a few machine words (the style vocabulary hangs off the
// cached *view.Styles), so views can pass it by value per row for free.
func (m *Model) viewContext() view.Context {
	return view.Context{
		File:                m.file,
		Width:               m.width,
		BodyH:               m.bodyHeight(),
		Wrap:                m.wrap,
		Detached:            m.viewportDetached,
		TreeCollapseDefault: m.treeCollapseDefault,
		Styles:              m.viewStyles(),
	}
}

// viewContextPtr returns the frame snapshot on the heap, for the hexraw view
// whose render path takes *view.Context.
func (m *Model) viewContextPtr() *view.Context {
	ctx := m.viewContext()
	return &ctx
}

// viewStyles returns the cached style/closure vocabulary, building it on first
// use. Dropped (set nil) by clearColorCaches on a theme change and by the
// settings modal when a display setting it bakes in changes.
func (m *Model) viewStyles() *view.Styles {
	if m.viewStylesCache != nil {
		return m.viewStylesCache
	}
	disName := ""
	if m.dis != nil {
		disName = m.dis.Name()
	}
	m.viewStylesCache = &view.Styles{
		HeaderStyle: m.theme.tableHeaderStyle,
		AddrStyle:   m.theme.addrStyle,
		RowStyle:    m.theme.tableRowStyle,
		SelStyle:    m.theme.tableSelStyle,
		SymStyle:    m.theme.symbolNameStyle,
		ShadowStyle: m.theme.srcShadowStyle,
		FooterStyle: m.theme.footerStyle,
		KeyStyle:    m.theme.helpKeyStyle,
		TreeStyle:   m.theme.treeNodeStyle,
		LabelStyle:  m.theme.headerKey,
		PanelStyle:  m.theme.panelStyle,
		NumberStyle: m.theme.asmNumberStyle,
		HeadStyle:   m.theme.helpHeadStyle,
		InfoStyle:   m.theme.infoStyle,
		WarnStyle:   m.theme.warnStyle,
		ErrorStyle:  m.theme.errorStyle,
		StickyStyle: m.theme.stickySymStyle,
		BannerStyle: m.theme.sectionStyle,
		PtrStyle:    m.theme.hexPointerStyle,
		LinkStyle:   m.theme.linkAddrInterStyle,

		DisassemblerName: disName,
		HexBytesPerRow:   m.cfg.Behavior.HexBytesPerRow,
		HideAnnotations:  m.cfg.Behavior.HideAnnotations,
		ByteHex:          &byteHex,
		ByteASCII:        &byteASCII,

		// Bound as m-capturing closures, not method values: a method value on the
		// Theme field would copy the whole (large) Theme to the heap per call. They
		// read m at call time, so the cached Styles never goes stale through them.
		SectionStyle: func(s *binfile.Section) lipgloss.Style { return m.theme.styleForSection(s) },
		SegmentStyle: func(exec, write bool) lipgloss.Style { return m.theme.styleForSegment(exec, write) },
		SymbolStyle: func(k binfile.SymKind, b binfile.SymBind) lipgloss.Style {
			return m.theme.styleForSymbol(k, b)
		},
		SectionAtOffset:  m.sectionAtOffset,
		PathStyle:        func(keyPath, display string) string { return m.theme.colorPathByPrefix(keyPath, display) },
		SymbolDisplay:    func(sym binfile.Symbol) string { return m.displaySymbolName(sym) },
		TargetAnnotation: func(addr uint64) string { return m.targetAnnotation(addr) },
		LMANote:          func(phys uint64) string { return m.lmaNote(phys) },
		AddrForOffset:    func(off uint64) (uint64, bool) { return m.addrForOffset(off) },
		CanDisasmAt:      func(addr uint64) bool { return m.canDisasmAt(addr) },
	}
	return m.viewStylesCache
}

// Model satisfies view.Host via thin exported wrappers over its existing methods,
// so views call a stable interface while the internals keep their names.
func (m *Model) SetStatus(msg string, isErr bool)   { m.setStatus(msg, isErr) }
func (m *Model) JumpHexAtAddr(addr uint64)          { m.jumpHexAtAddr(addr) }
func (m *Model) JumpDisasmAtAddr(addr uint64)       { m.jumpDisasmAtAddr(addr) }
func (m *Model) JumpRawAtAddr(addr uint64)          { m.jumpRawAtAddr(addr) }
func (m *Model) OpenHexAt(addr uint64)              { m.openHexAt(addr) }
func (m *Model) OpenRawAt(off uint64)               { m.openRawAt(off) }
func (m *Model) OpenSymbol(sym binfile.Symbol)      { m.openSymbol(sym) }
func (m *Model) GotoAddr(addr uint64)               { m.gotoAddr(addr) }
func (m *Model) OpenSymbolsForLib(lib string)       { m.openSymbolsForLib(lib) }
func (m *Model) OpenSourceFile(file string)         { m.openSourceFileInDisasm(file, 1) }
func (m *Model) SymbolNamesChanged()                { m.clearSymbolNameCaches() }
func (m *Model) CopyToClipboard(text, label string) { m.copyToClipboard(text, label) }
func (m *Model) ToggleWrap()                        { m.toggleWrap() }
func (m *Model) ListPage() int                      { return m.listPage() }
func (m *Model) SetPageRows(n int)                  { m.pageRows = n }
