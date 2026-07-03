package ui

// The "Find from here" modal (f): a seed picker that reads the things at the
// caret — its address, the pointer it holds, the symbol/section covering it, a
// string or a library path — and, on selection, pre-seeds and opens the goto
// portal to search for that seed across the whole binary (with the portal's
// per-scope = per-view filtering and result list). It is the search counterpart
// of the jump modal (space), which opens the *same* position in another view;
// this searches for the *value* under the caret wherever it appears.

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/rabarbra/exex/internal/ui/layout"
	"github.com/rabarbra/exex/internal/ui/views/hexraw"
)

// findSeed is one candidate search: a label, the query value, the scope it
// searches, a human preview, and — for a located seed (symbol/string/section) —
// the address it resolves to, so the global search can look for references to it.
type findSeed struct {
	label   string
	value   string
	scope   gotoScope
	preview string
	addr    uint64
	hasAddr bool
}

// openFindModal collects the search seeds available at the caret and opens the
// picker. With no seeds it reports rather than opening an empty picker.
func (m *Model) openFindModal() {
	m.findSeeds = m.buildFindSeeds()
	if len(m.findSeeds) == 0 {
		m.setStatus("nothing under the caret to search for", true)
		return
	}
	m.findSel = 0
	m.findActive = true
}

// buildFindSeeds assembles the seeds for the current caret + view. Address-keyed
// seeds need a virtual address; the library seed comes from the Libs view and a
// source-path seed from the Sources view, so f is useful even where there is no
// address under the cursor.
func (m *Model) buildFindSeeds() []findSeed {
	var out []findSeed
	seen := map[string]bool{}
	add := func(s findSeed) {
		key := string(rune(s.scope)) + "\x00" + s.value
		if s.value == "" || seen[key] {
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
				add(findSeed{label: "Operand", value: fmt.Sprintf("0x%x", t), scope: gsAddr, preview: prev, addr: t, hasAddr: true})
			}
		}
	case modeLibs:
		if lib, ok := m.libs.CurrentLib(m.viewContext()); ok {
			add(findSeed{label: "Library", value: lib, scope: gsLibs, preview: lib})
			if base := baseName(lib); base != lib {
				add(findSeed{label: "Path", value: base, scope: gsStrings, preview: base + "  (as string)"})
			}
		}
	case modeSources:
		if f, ok := m.sources.CurrentFile(); ok {
			add(findSeed{label: "Source", value: baseName(f), scope: gsStrings, preview: f + "  (as string)"})
		}
	}

	c, ok := m.caretPos()
	if !ok {
		return out
	}

	// Symbol covering the caret.
	if c.hasAddr {
		if sym, ok := m.file.SymbolAt(c.addr); ok && sym.Name != "" {
			add(findSeed{label: "Symbol", value: sym.Name, scope: gsSymbols, preview: m.displaySymbolName(sym), addr: sym.Addr, hasAddr: sym.Addr != 0})
		}
	}
	// String at the caret (by address or offset).
	if s, ok := m.stringAtCaret(c); ok {
		txt := m.file.StringText(s)
		add(findSeed{label: "String", value: txt, scope: gsStrings, preview: strconvQuote(txt, 40), addr: s.Addr, hasAddr: s.HasAddr})
	}
	// Section containing the caret.
	if c.hasAddr {
		if sec := m.file.SectionAt(c.addr); sec != nil && sec.Name != "" {
			add(findSeed{label: "Section", value: sec.Name, scope: gsSections, preview: sec.Name, addr: sec.Addr, hasAddr: sec.Addr != 0})
		}
	}
	// The address itself, when the caret has one.
	if c.hasAddr {
		add(findSeed{label: "Address", value: fmt.Sprintf("0x%x", c.addr), scope: gsAddr, preview: fmt.Sprintf("0x%x", c.addr)})
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
		add(findSeed{label: "Pointer", value: fmt.Sprintf("0x%x", v), scope: gsAddr, preview: prev, addr: v, hasAddr: m.file.IsMapped(v)})
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

// activateFind launches the global value search for the selected candidate.
func (m *Model) activateFind() tea.Cmd {
	if m.findSel < 0 || m.findSel >= len(m.findSeeds) {
		return nil
	}
	return m.startFindSearch(m.findSeeds[m.findSel])
}

// updateFindModal drives the picker: up/down move, Enter (or a digit) runs the
// search for the seed, c copies the seed's value, Esc closes.
func (m *Model) updateFindModal(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc":
		m.findActive = false
	case "up", "k":
		if m.findSel > 0 {
			m.findSel--
		}
	case "down", "j":
		if m.findSel < len(m.findSeeds)-1 {
			m.findSel++
		}
	case "enter", "space":
		return m, m.activateFind()
	case "c":
		// Copy the highlighted seed's value — the symbol name, the address, the
		// string, etc. — so the caret's value can be grabbed without searching.
		if m.findSel >= 0 && m.findSel < len(m.findSeeds) {
			s := m.findSeeds[m.findSel]
			m.copyToClipboard(s.value, strings.ToLower(s.label))
		}
		m.findActive = false
	default:
		if len(key) == 1 && key[0] >= '1' && key[0] <= '9' {
			if i := int(key[0] - '1'); i < len(m.findSeeds) {
				m.findSel = i
				return m, m.activateFind()
			}
		}
	}
	return m, nil
}

// findSeedStyle colours a seed's value by its kind — the address hue for
// addresses/pointers, the symbol hue for symbols, and a readable default for the
// rest — so the value reads as content, not chrome.
func (m *Model) findSeedStyle(s findSeed) lipgloss.Style {
	switch s.scope {
	case gsAddr:
		return m.theme.addrStyle
	case gsSymbols:
		return m.theme.symbolNameStyle
	case gsStrings:
		return m.theme.infoStyle
	case gsSections:
		return m.theme.warnStyle
	default:
		return m.theme.tableRowStyle
	}
}

func (m *Model) renderFindModal() string {
	var sb strings.Builder
	rowW := modalListWidth(m.width)
	sb.WriteString(m.theme.modalTitle("Find"))
	sb.WriteByte('\n')
	sb.WriteByte('\n')
	sb.WriteString(" " + m.theme.modalHint("search the whole binary for the value under the caret") + "\n")
	sb.WriteByte('\n')
	m.modalListRow = 4 // title + blank + subtitle + blank

	const labelW = 9
	prevW := max(4, rowW-4-2-labelW-3)
	for i, s := range m.findSeeds {
		digit := m.theme.helpKeyStyle.Render(fmt.Sprintf("%d", i+1))
		label := m.theme.srcShadowStyle.Render(layout.PadVisual(s.label, labelW))
		scope := m.theme.srcShadowStyle.Render("in " + s.scope.String())
		// The value is the point of the row — colour it by kind (address/pointer in
		// the address hue, symbol in the symbol hue, …), never dim.
		preview := m.findSeedStyle(s).Render(layout.TruncateMiddle(s.preview, prevW))
		line := fmt.Sprintf(" %s %s  %s   %s", digit, label, preview, scope)
		line = layout.PadRight(line, rowW)
		if i == m.findSel {
			line = m.theme.tableSelStyle.Render(ansi.Strip(line))
		}
		sb.WriteString(line + "\n")
	}
	sb.WriteByte('\n')
	sb.WriteString(" " + m.theme.modalHint("↑/↓ select · ↵ or digit search · c copy value · Esc cancel"))
	return m.theme.modalStyle.Render(sb.String())
}
