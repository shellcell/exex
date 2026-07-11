// Package rawheader is the raw container-header overlay (⇧H): the ELF e_*
// fields, the Mach-O mach_header and load commands, or the PE COFF/optional
// header, as an aligned field table.
//
// The header is a property of the whole file, so it is an overlay rather than a
// Sections sub-mode. Like the help sheet it has no list and no selection, and
// shares textoverlay.Scroller for its paging and dismiss-on-any-key behaviour.
package rawheader

import (
	"fmt"
	"strings"

	"github.com/rabarbra/exex/internal/ui/layout"
	"github.com/rabarbra/exex/internal/ui/modal"
	"github.com/rabarbra/exex/internal/ui/modals/textoverlay"
)

// fieldKeyWidth is the aligned width of the field-name column.
const fieldKeyWidth = 20

// pageStep is how many rows PgUp/PgDn move. Header rows are one field each, so
// it pages by more than the denser help sheet.
const pageStep = 10

// State is the raw-header overlay. The zero value is closed.
type State struct {
	textoverlay.Scroller
}

// Update handles one keypress: scroll keys page through the fields, any other
// key dismisses the overlay.
func (s *State) Update(key string) { s.Scroller.Update(key, pageStep) }

// Render draws the field table for the binary in ctx.
func (s *State) Render(ctx modal.Context) string {
	fields := ctx.File.RawHeader()
	rowW := ctx.ListWidth()
	var sb strings.Builder
	sb.WriteString(ctx.Title(string(ctx.File.Format) + " header"))
	sb.WriteString("\n\n")
	if len(fields) == 0 {
		sb.WriteString(" " + ctx.ShadowStyle.Render("no raw header fields for this format") + "\n")
		return ctx.Frame(sb.String())
	}

	// Build every row, then window vertically to the terminal height.
	rows := make([]string, 0, len(fields))
	for _, f := range fields {
		row := " " + ctx.AccentStyle.Render(layout.PadVisual(f.Name, fieldKeyWidth)) + " " +
			ctx.RowStyle.Render(f.Value)
		rows = append(rows, layout.FitANSIWidth(row, rowW))
	}
	total := len(rows)
	rows, from, to, scrolled := s.Window(rows, ctx.Height)
	hint := "↑/↓ scroll · Esc/⇧H close"
	if scrolled {
		hint = fmt.Sprintf("↑/↓ scroll · %d–%d of %d · Esc closes", from, to, total)
	}
	sb.WriteString(strings.Join(rows, "\n"))
	sb.WriteString("\n\n")
	sb.WriteString(ctx.Hint(hint))
	return ctx.Frame(sb.String())
}
