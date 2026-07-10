// Package help is the keybinding cheat-sheet overlay (the `?` key): a static,
// two-column table of every binding, scrolled when it is taller than the
// terminal and dismissed by any other key.
//
// It has no list and no selection, so unlike the other overlays it exposes a
// scroll offset rather than a cursor — the shell's shared mouse-wheel and
// click-to-select handling does not apply to it.
package help

import (
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/rabarbra/exex/internal/ui/layout"
	"github.com/rabarbra/exex/internal/ui/modal"
)

// PageStep is how many rows PgUp/PgDn move the overlay.
const PageStep = 8

// State is the help overlay. The zero value is closed.
type State struct {
	active bool
	scroll int
}

func (s *State) Open()        { s.active, s.scroll = true, 0 }
func (s *State) Close()       { s.active = false }
func (s *State) Active() bool { return s.active }

// Scroll moves the view by delta rows. The offset is clamped where the overlay
// is rendered, because the row count depends on the terminal width.
func (s *State) Scroll(delta int) { s.scroll += delta }

// ScrollOffset is the current top row.
func (s *State) ScrollOffset() int { return s.scroll }

// Update handles one keypress: scroll keys page through the sheet (it can be
// taller than the terminal); any other key dismisses it.
func (s *State) Update(key string) {
	switch key {
	case "up", "k":
		s.scroll--
	case "down", "j":
		s.scroll++
	case "pgup":
		s.scroll -= PageStep
	case "pgdown":
		s.scroll += PageStep
	case "home", "g":
		s.scroll = 0
	case "end", "G":
		s.scroll = 1 << 20 // clamped to the bottom in Render
	default:
		s.Close()
	}
}

// renderHelpModal lists the keybindings, grouped by scope, in two columns. The
// key column is padded by display width (so multibyte arrows align) and the two
// columns are laid out side by side to keep the modal compact.
// Entry is one line of a help column: a section header, a key/description
// row, or a blank spacer.
type Entry struct {
	head string // section title (uppercased + ruled) when non-empty
	text string // a pre-rendered key+desc row; "" with no head = blank line
}

func (s *State) Render(ctx modal.Context) string {
	const keyW = 16
	row := func(keys, desc string) Entry {
		return Entry{text: ctx.KeyStyle.Render(layout.PadVisual(keys, keyW)) + " " + ctx.DescStyle.Render(desc)}
	}
	head := func(s string) Entry { return Entry{head: s} }
	blank := Entry{}

	left := []Entry{
		head("Global"),
		row("1–9 · 0", "switch view (0 = relocations)"),
		row("g", "jump to anything (symbol/section/string/lib/addr · ⇥ scope)"),
		row(",", "settings (theme, wrap, …)"),
		row("?", "this help"),
		row("w", "toggle long-line wrap"),
		row("d/h/m", "go to addr in disasm / hex / raw"),
		row("␣ / >", "open caret address in another view (menu)"),
		row("f", "find the value under the caret across the binary"),
		row("l", "search the binary for anything you type (disasm/data/strings/relocs)"),
		row("⇧a/⇧s/⇧l", "copy address / name / line"),
		row("t / ⇥", "switch view"),
		row("/  n/N", "search · next/prev"),
		row("^O", "back (return from an opened dependency)"),
		row("⇧F", "CPU features required (SSE/AVX/NEON · baseline)"),
		row("⇧H", "raw file header (ELF e_* / Mach-O load cmds / PE)"),
		row("q / ^C", "quit"),
		row("↵ Enter", "open / jump"),
		blank,
		head("Lists (all views)"),
		row("/", "filter / search"),
		row("↑/↓", "move line"),
		row("s/r", "sort · reverse"),
		row("PgUp/PgDn  [ ]", "page  ("+layout.CtrlKeys("↑", "↓")+")"),
		row("Home/End ^A/^E", "begin/end"),
		row("Esc", "clear filters"),
		blank,
		head("Tree actions"),
		row("t / ⇥", "toggle namespace tree / flat table"),
		row("←/→", "tree: collapse / expand group"),
		row("↵ · +/−", "tree: expand/collapse all below · all"),
		blank,
		head("Info"),
		row("t / ⇥", "fat-Mach-O arch slice · static-lib members list"),
		row("↵ Enter", "open entry point · open selected member"),
		blank,
		head("Sections"),
		row(layout.CtrlKeys("t", "f"), "filter by type / flags"),
		row("t / ⇥", "cycle sections / segments / header"),
		blank,
		head("Symbols"),
		row(layout.CtrlKeys("t", "b", "s"), "filter by type / bind / scope"),
		row("e / .", "collapse (…)/<…> to ... · all / current"),
	}
	right := []Entry{
		head("Disassembly"),
		row("↵ Enter", "follow address"),
		row("[ ]", "previous / next symbol"),
		row("←/→", "history back / forward"),
		row("x", "find references (xrefs)"),
		row("y", "list system calls"),
		row("a", "disassemble all sections / exec-only (object files, data)"),
		row("⇧a/⇧s/⇧c", "copy addr / symbol / function asm"),
		row("Tab", "show / hide right pane"),
		row("⇧Tab", "swap source / disasm"),
		row("⇧↑/⇧↓", "scroll right pane"),
		row("", "modals (xrefs / syscalls): / filter · s/r sort"),
		blank,
		head("Hex / Raw"),
		row("[ ]", "prev / next section"),
		row("⇧[ ⇧]", "prev / next nonzero"),
		row("t / ⇥", "trailing column: ascii ↔ numeric"),
		row("⇧t", "cycle interpretation (i8…i64/u…/f32/f64)"),
		row("i", "data inspector"),
		row("⇧a/⇧s/⇧p", "copy address / symbol / pointer"),
		row("↵ Enter", "follow pointer at cursor"),
		blank,
		head("Sources"),
		row("[ ]", "prev / next mapped line"),
		row(layout.CtrlKeys("p"), "filter: all / present / missing"),
		row("t / ⇥", "toggle directory tree / flat list"),
		row("↵ Enter / o", "open in disasm source-first view"),
		blank,
		head("Libraries / Relocations"),
		row("8 / 0", "libraries view / relocations view"),
		row("o", "(libs) open as primary"),
		row(layout.CtrlKeys("p"), "(libs) filter all/on-disk/cache"),
		row("t / ⇥", "(libs) flat ↔ tree"),
		row("↵", "libs: imported symbols · relocs: go to patched addr"),
		row("s/r  "+layout.CtrlKeys("t", "s"), "(relocs) sort/rev · type/section filter"),
		blank,
		head("Strings"),
		row(layout.CtrlKeys("s"), "filter by section"),
		row(layout.CtrlKeys("p"), "filter to paths only"),
		row("t / ⇥", "table ↔ compact (· flow) layout"),
	}

	leftLines := helpColumn(ctx, left)
	rightLines := helpColumn(ctx, right)
	lw, rw := lipgloss.Width(leftLines[0]), lipgloss.Width(rightLines[0])

	// Two side-by-side columns when they fit the terminal; otherwise stack into a
	// single column so the modal never overruns a narrow window.
	var bodyRows []string
	if lw+rw+6 <= ctx.Width-6 {
		div := ctx.ShadowStyle.Render("│")
		n := max(len(leftLines), len(rightLines))
		for i := range n {
			l, r := layout.PadVisual("", lw), layout.PadVisual("", rw)
			if i < len(leftLines) {
				l = leftLines[i]
			}
			if i < len(rightLines) {
				r = rightLines[i]
			}
			bodyRows = append(bodyRows, l+"  "+div+"  "+r)
		}
	} else {
		bodyRows = append(bodyRows, leftLines...)
		bodyRows = append(bodyRows, layout.PadVisual("", lw))
		bodyRows = append(bodyRows, rightLines...)
	}

	// Vertically window the body when it is taller than the screen, scrolled by
	// s.scroll (the title, hint and modal chrome cost ~8 rows).
	hint := "Mouse: wheel scrolls · over right pane scrolls it · click selects · double-click follows"
	total := len(bodyRows)
	maxRows := max(1, ctx.Height-8)
	if total > maxRows {
		s.scroll = layout.Clamp(s.scroll, 0, total-maxRows)
		bodyRows = bodyRows[s.scroll : s.scroll+maxRows]
		hint = fmt.Sprintf("↑/↓ scroll · %d–%d of %d · Esc/any key closes",
			s.scroll+1, s.scroll+maxRows, total)
	} else {
		s.scroll = 0
	}

	// Never let a row push the modal past the terminal (very narrow windows).
	rowCap := max(1, ctx.Width-6)

	var b strings.Builder
	b.WriteString(ctx.Title("Keybindings"))
	b.WriteString("\n\n")
	for _, r := range bodyRows {
		b.WriteString(layout.FitANSIWidth(r, rowCap))
		b.WriteString("\n")
	}
	b.WriteString("\n")
	// The hint is capped like the body rows. Uncapped it set the overlay's minimum
	// width, so on a narrow terminal the footer — not the content — pushed the
	// modal past the right edge.
	b.WriteString(layout.FitANSIWidth(ctx.Hint(hint), rowCap))
	return ctx.Frame(b.String())
}

// helpColumn renders a help column: rows padded to a common width, section
// headers shown uppercase with a dim rule to the column edge (matching the Info
// view), blanks as empty lines.
func helpColumn(ctx modal.Context, entries []Entry) []string {
	w := 0
	for _, e := range entries {
		if e.head == "" {
			if rw := ansi.StringWidth(e.text); rw > w {
				w = rw
			}
		}
	}
	out := make([]string, len(entries))
	for i, e := range entries {
		switch {
		case e.head != "":
			label := strings.ToUpper(e.head) + " "
			line := ctx.HeadStyle.Render(label)
			if fill := w - lipgloss.Width(label); fill > 0 {
				line += ctx.ShadowStyle.Render(strings.Repeat("─", fill))
			}
			out[i] = layout.PadVisual(line, w)
		default:
			out[i] = layout.PadVisual(e.text, w)
		}
	}
	return out
}
