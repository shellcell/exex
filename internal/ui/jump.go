package ui

// Cross-view "go to caret address" jumps, shared by the list/byte/code views so
// d (disasm), h (hex) and m (raw) behave the same wherever they're bound. Each
// resolves the address (or file offset) and switches view, reporting via the
// status line when the target can't be shown.

// jumpDisasmAtAddr opens the disassembly view at addr, or reports why it can't.
func (m *Model) jumpDisasmAtAddr(addr uint64) {
	if addr == 0 {
		m.setStatus("no address to disassemble", true)
		return
	}
	if !m.canDisasmAt(addr) {
		m.setStatus("address is not in executable code", true)
		return
	}
	m.loadDisasmAt(addr)
}

// jumpHexAtAddr opens the virtual-address hex view at addr (openHexAt reports
// when addr is unmapped).
func (m *Model) jumpHexAtAddr(addr uint64) {
	if addr == 0 {
		m.setStatus("no mapped address here", true)
		return
	}
	m.openHexAt(addr)
}

// jumpRawAtAddr opens the raw file view at the file offset backing addr, or
// reports when addr has no bytes on disk.
func (m *Model) jumpRawAtAddr(addr uint64) {
	off, ok := m.fileOffsetForAddr(addr)
	if !ok {
		m.setStatus("address has no file bytes to show in raw", true)
		return
	}
	m.openRawAt(off)
}

// fileOffsetForAddr maps a virtual address to its file offset using the section
// whose file bytes cover it. Returns false for addresses outside any
// file-backed section (e.g. .bss).
func (m *Model) fileOffsetForAddr(addr uint64) (uint64, bool) {
	sec := m.file.SectionAt(addr)
	if sec == nil || sec.FileSize == 0 || addr < sec.Addr {
		return 0, false
	}
	delta := addr - sec.Addr
	if delta >= sec.FileSize {
		return 0, false
	}
	return sec.Offset + delta, true
}

// addrForOffset maps a file offset to the virtual address it loads at, using the
// section whose file bytes cover it. Returns false for offsets outside any
// allocated section (e.g. file headers, debug data not mapped at runtime).
func (m *Model) addrForOffset(off uint64) (uint64, bool) {
	sec := m.sectionAtOffset(off)
	if sec == nil || !sec.Alloc || sec.Addr == 0 || off < sec.Offset {
		return 0, false
	}
	return sec.Addr + (off - sec.Offset), true
}
