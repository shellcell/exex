// Package help is the keybinding cheat-sheet overlay (the `?` key): a static,
// two-column table of every binding, scrolled when it is taller than the
// terminal and dismissed by any other key.
//
// It has no list and no selection: its scrolling and dismiss-on-any-key
// behaviour is textoverlay.Scroller, shared with the raw-header overlay.
package help

import (
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/rabarbra/exex/internal/ui/layout"
	"github.com/rabarbra/exex/internal/ui/modal"
	"github.com/rabarbra/exex/internal/ui/modals/textoverlay"
)

// pageStep is how many rows PgUp/PgDn move the sheet. Its rows are dense
// key/description pairs, so it pages by less than the header overlay.
const pageStep = 8

// State is the help overlay. The zero value is closed.
type State struct {
	textoverlay.Scroller
}

// Update handles one keypress: scroll keys page through the sheet, any other key
// dismisses it.
func (s *State) Update(key string) { s.Scroller.Update(key, pageStep) }

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

	// The per-view groups run in view order (the 1–9 · 0 keys), and each group
	// lists its keys in the same order as that view's footer, so a key sits in
	// the same place whether you read it here or down there.
	left := []Entry{
		head("Global"),
		row("1–9 · 0", "switch view (0 = relocations)"),
		row("g", "goto anything (symbol/section/string/lib/addr · ⇥ scope)"),
		row("d/h/m", "go to the caret address in disasm / hex / raw"),
		row("␣ · >", "open the caret address in another view (menu)"),
		row("f", "find the value under the caret across the binary"),
		row("l", "search the binary for anything you type"),
		row("/ · n/N", "search or filter this view · next / prev match"),
		row("w", "toggle long-line wrap"),
		row("⇧h", "raw file header (ELF e_* / Mach-O load cmds / PE)"),
		row("⇧f", "CPU features required (SSE/AVX/NEON · baseline)"),
		row("^o", "back (return from an opened dependency)"),
		row(",", "settings (theme, wrap, …)"),
		row("?", "this help"),
		row("q · ^c", "quit"),
		blank,
		head("Every list"),
		row("↑/↓ · ↵", "move the cursor · open / jump"),
		row("PgUp/PgDn · [ ]", "page  ("+layout.CtrlKeys("↑", "↓")+")"),
		row("Home/End · ^a/^e", "first / last row"),
		row("t", "switch the view's layout (table ↔ tree ↔ …)"),
		row("s/r", "sort · reverse"),
		row("^…", "the filters named on the status line"),
		row("esc", "clear filters"),
		row("⇧a/⇧s/⇧l", "copy address / name / whole line"),
		blank,
		head("Trees"),
		row("←/→", "collapse / expand the group"),
		row("↵ · +/−", "expand-collapse all below · all"),
		blank,
		head("Mouse"),
		row("click", "select a row · toggle a status-line chip · sort by a column"),
		row("double-click", "open / follow, as ↵ does"),
		row("wheel", "scroll · over the right pane, scrolls that pane"),
		blank,
		head("1 · Info"),
		row("↵", "open the entry point (or the selected member)"),
		row("t", "fat-Mach-O arch slice · static-library members"),
		blank,
		head("2 · Sections"),
		row("↵", "open the section (disasm / hex / raw, as fits)"),
		row("t", "sections ↔ segments"),
		row(layout.CtrlKeys("t", "f"), "filter by type / flags"),
		blank,
		head("3 · Symbols"),
		row("↵", "jump to the symbol"),
		row("e · .", "collapse (…)/<…> to “…” · all rows / this row"),
		row("t", "namespace tree ↔ flat table"),
		row(layout.CtrlKeys("t", "s", "b"), "filter by type / scope / bind"),
	}
	right := []Entry{
		head("4 · Disassembly"),
		row("↵", "follow the address on this line"),
		row("[ ]", "previous / next symbol"),
		row("←/→", "history back / forward"),
		row("h/m", "this address in hex / raw"),
		row("x · y", "find references (xrefs) · list system calls"),
		row("a", "disassemble all sections ↔ exec-only (objects, data)"),
		row("⇥ · ⇧⇥", "show/hide the source pane · swap the panes"),
		row("⇧↑/⇧↓", "scroll the follower pane on its own"),
		row("⇧a/⇧s/⇧c", "copy address / symbol / the function's asm"),
		row("", "in the xref & syscall lists: / filter · s/r sort"),
		blank,
		head("5 · Hex   ·   7 · Raw"),
		row("↵", "follow the pointer at the caret"),
		row("[ ] · ⇧[ ⇧]", "prev/next section · prev/next nonzero"),
		row("d/m · d", "hex → disasm/raw · raw → disasm"),
		row("i", "data inspector"),
		row("t · ⇧t", "trailing column ascii ↔ numeric · its type"),
		row("⇧a/⇧s/⇧p", "copy address / symbol / pointer"),
		blank,
		head("6 · Libraries"),
		row("↵ · o", "its imported symbols · open it as the primary file"),
		row("t · r", "path tree ↔ flat list · reverse"),
		row(layout.CtrlKeys("p"), "filter: all / on-disk / dyld cache"),
		blank,
		head("8 · Strings"),
		row("↵", "jump to the string in hex"),
		row("t", "table ↔ compact (· flow) layout"),
		row(layout.CtrlKeys("s", "p"), "filter by section / to paths only"),
		blank,
		head("9 · Sources"),
		row("↵ · o", "open in the disasm view, source-first"),
		row("[ ]", "previous / next mapped line"),
		row("t", "directory tree ↔ flat list"),
		row(layout.CtrlKeys("p"), "filter: all / present / missing"),
		blank,
		head("0 · Relocations"),
		row("↵", "go to the patched address in hex"),
		row("e", "collapse (…)/<…> in the bound symbol names"),
		row(layout.CtrlKeys("t", "s"), "filter by type / section"),
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

	// Vertically window the body when it is taller than the screen.
	hint := "Mouse: wheel scrolls · over right pane scrolls it · click selects · double-click follows"
	total := len(bodyRows)
	var from, to int
	var scrolled bool
	bodyRows, from, to, scrolled = s.Window(bodyRows, ctx.Height)
	if scrolled {
		hint = fmt.Sprintf("↑/↓ scroll · %d–%d of %d · Esc/any key closes", from, to, total)
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
