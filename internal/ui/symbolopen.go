package ui

// Shell-side symbol routing shared across views: openSymbol picks the most
// useful view for a symbol, canDisasmAt gates the disasm fallback, and
// displaySymbolName applies the Symbols view's global argument abbreviation to
// the symbol names shown in disasm/hex/source annotations. The Symbols list
// itself lives in internal/ui/views/symbols.

import (
	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/ui/views/symbols"
)

// canDisasmAt reports whether addr can actually be disassembled: there is a
// decoder for this architecture and the address lives in executable code. When
// false (an unsupported CPU, or an address outside any mapped exec section),
// callers should fall back to the hex view rather than the disasm view.
func (m *Model) canDisasmAt(addr uint64) bool {
	if m.dis == nil {
		return false
	}
	_, ok := m.file.ExecImage().PosForAddr(addr)
	return ok
}

// openSymbol opens a symbol in the most appropriate view. The hex and disasm
// views span the whole binary now, so this only chooses which view to land in
// and seeks the cursor onto the symbol's address:
//   - FUNC                  → disasm
//   - OBJECT/TLS/COMMON     → hex (virtual-address) view, cursor on the symbol
//   - SECTION               → exec ⇒ disasm; else hex/raw at the section
//   - NOTYPE                → exec section ⇒ disasm; else hex; else raw
//
// Anything that would land in disasm falls back to hex when disassembly isn't
// possible (no decoder for this CPU, or the address isn't in executable code).
func (m *Model) openSymbol(sym binfile.Symbol) {
	wantDisasm := false
	switch sym.Kind {
	case binfile.SymFunc:
		wantDisasm = true
	case binfile.SymObject, binfile.SymTLS, binfile.SymCommon:
		wantDisasm = false
	default:
		if sec := m.file.SectionAt(sym.Addr); sec != nil && binfile.IsExecSection(sec) {
			wantDisasm = true
		}
	}
	if wantDisasm && m.canDisasmAt(sym.Addr) {
		m.loadDisasmAt(sym.Addr)
	} else {
		m.openHexAt(sym.Addr)
	}
}

// displaySymbolName returns a symbol's display name with bracketed argument and
// template lists abbreviated (see symbols.AbbrevBrackets) when the global
// Symbols-view "args" collapse is on, so a symbol reads the same in the disasm,
// hex/raw and pointer-follow annotations as it does in the Symbols list. The
// Symbols view's per-row overrides are list-specific and intentionally don't
// apply here.
func (m *Model) displaySymbolName(s binfile.Symbol) string {
	if m.symbols.Abbrev {
		return symbols.AbbrevBrackets(s.Display())
	}
	return s.Display()
}
