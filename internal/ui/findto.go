package ui

// The shell half of the "Find from here" seed picker (internal/ui/modals/findto).
//
// Reading the caret needs the views and the binary, so building the seeds stays
// here; the overlay only presents them and hands the chosen one back through
// findto.Host.StartSearch.

import (
	"fmt"
	"strings"

	findtomodal "github.com/rabarbra/exex/internal/ui/modals/findto"
	"github.com/rabarbra/exex/internal/ui/scope"
	"github.com/rabarbra/exex/internal/ui/views/hexraw"
)

// openFindModal collects the search seeds available at the caret and opens the
// picker. With no seeds it reports rather than opening an empty picker.
func (m *Model) openFindModal() {
	if !m.find.Open(m.buildFindSeeds()) {
		m.setStatus("nothing under the caret to search for", true)
	}
}

// buildFindSeeds assembles the seeds for the current caret + view. Address-keyed
// seeds need a virtual address; the library seed comes from the Libs view and a
// source-path seed from the Sources view, so f is useful even where there is no
// address under the cursor.
func (m *Model) buildFindSeeds() []findtomodal.Seed {
	var out []findtomodal.Seed
	seen := map[string]bool{}
	add := func(s findtomodal.Seed) {
		key := string(rune(s.Scope)) + "\x00" + s.Value
		if s.Value == "" || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, s)
	}

	// View-specific seeds that aren't the caret address itself.
	switch m.mode {
	case modeDisasm:
		// The current instruction's resolved operand target (a call/branch/load
		// address) — the thing you most often want to chase from a line of code.
		if len(m.disasmInst) > 0 && m.disasmCur >= 0 && m.disasmCur < len(m.disasmInst) {
			inst := m.disasmInst[m.disasmCur]
			if t, ok := m.followableAddr(inst.Text); ok {
				prev := fmt.Sprintf("0x%x", t)
				if ann := m.targetAnnotation(t); ann != "" {
					prev += "  " + ann
				}
				add(findtomodal.Seed{Label: "Operand", Value: fmt.Sprintf("0x%x", t), Scope: scope.Addr, Preview: prev, Addr: t, HasAddr: true})
			}
		}
	case modeLibs:
		if lib, ok := m.libs.CurrentLib(m.viewContext()); ok {
			add(findtomodal.Seed{Label: "Library", Value: lib, Scope: scope.Libs, Preview: lib})
			if base := baseName(lib); base != lib {
				add(findtomodal.Seed{Label: "Path", Value: base, Scope: scope.Strings, Preview: base + "  (as string)"})
			}
		}
	case modeSources:
		if f, ok := m.sources.CurrentFile(); ok {
			add(findtomodal.Seed{Label: "Source", Value: baseName(f), Scope: scope.Strings, Preview: f + "  (as string)"})
		}
	}

	c, ok := m.caretPos()
	if !ok {
		return out
	}

	// Symbol covering the caret.
	if c.hasAddr {
		if sym, ok := m.file.SymbolAt(c.addr); ok && sym.Name != "" {
			add(findtomodal.Seed{Label: "Symbol", Value: sym.Name, Scope: scope.Symbols, Preview: m.displaySymbolName(sym), Addr: sym.Addr, HasAddr: sym.Addr != 0})
		}
	}
	// String at the caret (by address or offset).
	if s, ok := m.stringAtCaret(c); ok {
		txt := m.file.StringText(s)
		add(findtomodal.Seed{Label: "String", Value: txt, Scope: scope.Strings, Preview: strconvQuote(txt, 40), Addr: s.Addr, HasAddr: s.HasAddr})
	}
	// Section containing the caret.
	if c.hasAddr {
		if sec := m.file.SectionAt(c.addr); sec != nil && sec.Name != "" {
			add(findtomodal.Seed{Label: "Section", Value: sec.Name, Scope: scope.Sections, Preview: sec.Name, Addr: sec.Addr, HasAddr: sec.Addr != 0})
		}
	}
	// The address itself, when the caret has one.
	if c.hasAddr {
		add(findtomodal.Seed{Label: "Address", Value: fmt.Sprintf("0x%x", c.addr), Scope: scope.Addr, Preview: fmt.Sprintf("0x%x", c.addr)})
	}
	// The pointer the caret's bytes hold. In the Hex/Raw views use the view's own
	// aligned read (the exact word the follow-pointer action would use, so f
	// mid-pointer matches Enter); elsewhere read by address, or straight from the
	// raw bytes at the file offset so a Raw caret over an unmapped header still
	// offers a pointer search.
	if v, ok := m.caretPointerForFind(c); ok {
		prev := fmt.Sprintf("→ 0x%x", v)
		if ann := m.targetAnnotation(v); ann != "" {
			prev += "  " + ann
		}
		add(findtomodal.Seed{Label: "Pointer", Value: fmt.Sprintf("0x%x", v), Scope: scope.Addr, Preview: prev, Addr: v, HasAddr: m.file.IsMapped(v)})
	}
	return out
}

// caretPointerForFind resolves the pointer to offer as a Find seed: the Hex/Raw
// views' aligned word when active (matching follow-pointer), else the generic
// address/offset read.
func (m *Model) caretPointerForFind(c caret) (uint64, bool) {
	switch m.mode {
	case modeHex:
		return m.byteViews.CaretPointer(m.viewContextPtr(), hexraw.Hex)
	case modeRaw:
		return m.byteViews.CaretPointer(m.viewContextPtr(), hexraw.Raw)
	}
	return m.caretPointerAt(c)
}

// baseName returns the last path element of p (a library install path or a source
// file), for a tidier search seed.
func baseName(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 && i+1 < len(p) {
		return p[i+1:]
	}
	return p
}
