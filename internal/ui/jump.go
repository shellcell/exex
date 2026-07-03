package ui

// Cross-view "go to caret address" jumps, shared by the list/byte/code views so
// d (disasm), h (hex) and m (raw) behave the same wherever they're bound. Each
// resolves the address (or file offset) and switches view, reporting via the
// status line when the target can't be shown.

import "fmt"

// jumpDisasmAtAddr opens the disassembly view at addr, or reports why it can't.
// When the target isn't in the current (exec-only) image but a section with
// content covers it — e.g. a kernel/multiboot section that isn't flagged
// executable — it switches to disasm-all mode so the code can still be shown.
func (m *Model) jumpDisasmAtAddr(addr uint64) {
	if m.dis == nil {
		m.setStatus("no disassembler for this architecture", true)
		return
	}
	// Note: address 0 is not special-cased — in a relocatable object (.o, kernel
	// module) the sections and their functions legitimately live at address 0, so
	// canDisasmAt decides whether it's reachable.
	if !m.canDisasmAt(addr) {
		if !m.file.DisasmAll() && m.file.AddrDisassemblable(addr) {
			m.file.SetDisasmAll(true)
			m.resetDisasmImageState()
			m.setStatus("disasm: all sections (target isn't in an executable section)", false)
			m.loadDisasmAt(addr)
			return
		}
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

// jumpSymbolsAtAddr opens the Symbols view located on the symbol covering addr
// (the cross-view "open caret in Symbols" jump), filtered to its name so it is
// the visible selection.
func (m *Model) jumpSymbolsAtAddr(addr uint64) {
	sym, ok := m.file.SymbolAt(addr)
	if !ok || sym.Name == "" {
		m.setStatus(fmt.Sprintf("no symbol at 0x%x", addr), true)
		return
	}
	m.symbols.FilterByName(m.viewContext(), sym.Name)
	m.setMode(modeSymbols)
	m.setStatus("symbol "+m.displaySymbolName(sym)+" — Esc clears filter", false)
}

// jumpSectionsAtAddr opens the Sections view with the section containing addr
// selected.
func (m *Model) jumpSectionsAtAddr(addr uint64) {
	if !m.sections.SelectByAddr(addr) {
		m.setStatus(fmt.Sprintf("no section contains 0x%x", addr), true)
		return
	}
	m.setMode(modeSections)
}

// jumpRelocsAtAddr opens the Relocs view with the relocation patching addr
// selected, or reports when there is none.
func (m *Model) jumpRelocsAtAddr(addr uint64) {
	if !m.file.HasRelocs() {
		m.setStatus("no relocations in this binary", true)
		return
	}
	if !m.relocs.SelectByAddr(m.viewContext(), addr) {
		m.setStatus(fmt.Sprintf("no relocation patches 0x%x", addr), true)
		return
	}
	m.setMode(modeRelocs)
}

// jumpStringsAtAddr opens the Strings view with the string covering addr
// selected, or reports when there is none.
func (m *Model) jumpStringsAtAddr(addr uint64) {
	if !m.strs.SelectByAddr(m.viewContext(), addr) {
		m.setStatus(fmt.Sprintf("no string at 0x%x", addr), true)
		return
	}
	m.setMode(modeStrings)
}

// jumpStringsAtOffset opens the Strings view with the string covering file offset
// off selected — the offset-only counterpart used from the Raw view.
func (m *Model) jumpStringsAtOffset(off uint64) {
	if !m.strs.SelectByOffset(m.viewContext(), off) {
		m.setStatus(fmt.Sprintf("no string at file offset 0x%x", off), true)
		return
	}
	m.setMode(modeStrings)
}

// lowestVirtAddr returns the lowest mapped (allocated, non-zero) virtual address
// in the image — the natural "start" when there is no entry point. ok is false
// for a binary with no allocated sections (e.g. a pure object file).
func (m *Model) lowestVirtAddr() (uint64, bool) {
	var best uint64
	ok := false
	for i := range m.file.Sections {
		s := &m.file.Sections[i]
		if !s.Alloc || s.Addr == 0 || s.Size == 0 {
			continue
		}
		if !ok || s.Addr < best {
			best, ok = s.Addr, true
		}
	}
	return best, ok
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
