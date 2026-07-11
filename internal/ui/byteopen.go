package ui

import "github.com/rabarbra/exex/internal/binfile"

// Shell-side byte-view routing shared across views. The Hex/Raw rendering and
// cursor mechanics live in internal/ui/views/hexraw; these helpers only perform
// cross-view opens and offset/address lookup that require the shell model.

// openHexAt switches to the virtual-address Hex view and seeks addr.
func (m *Model) openHexAt(addr uint64) {
	if m.byteViews.PositionHexAt(m.viewContextPtr(), m, addr) {
		m.setMode(modeHex)
	}
}

// openRawAt switches to the raw file view and seeks file offset off.
func (m *Model) openRawAt(off uint64) {
	m.byteViews.PositionRawAt(m.viewContextPtr(), off)
	m.setMode(modeRaw)
}

// sectionAtOffset resolves the section whose file bytes cover off.
func (m *Model) sectionAtOffset(off uint64) *binfile.Section {
	return m.byteViews.SectionAtOffset(m.file, off)
}
