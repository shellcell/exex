package ui

// The raw container header (ELF e_*, Mach-O mach_header + load commands, PE
// COFF/optional header) as an aligned field table, shown in a scrollable overlay
// (toggled with ⇧H) rather than as a hidden Sections sub-mode — the header is a
// property of the whole file, so it belongs with the Info-level overlays.

import (
	"fmt"
	"strings"
)

// headerFieldKeyWidth is the aligned width of the field-name column.
const headerFieldKeyWidth = 20

// headerPageStep is the scroll distance for PgUp/PgDn in the header overlay.
const headerPageStep = 10

// renderHeaderModal renders the raw header field table as a centred, scrollable
// overlay.
func (m *Model) renderHeaderModal() string {
	fields := m.file.RawHeader()
	rowW := modalListWidth(m.width)
	var sb strings.Builder
	sb.WriteString(m.theme.modalTitle(string(m.file.Format) + " header"))
	sb.WriteString("\n\n")
	if len(fields) == 0 {
		sb.WriteString(" " + m.theme.srcShadowStyle.Render("no raw header fields for this format") + "\n")
		return m.theme.modalStyle.Render(sb.String())
	}

	// Build every row, then window vertically to the terminal height.
	rows := make([]string, 0, len(fields))
	for _, f := range fields {
		row := " " + m.theme.headerKey.Render(padVisual(f.Name, headerFieldKeyWidth)) + " " +
			m.theme.tableRowStyle.Render(f.Value)
		rows = append(rows, fitANSIWidth(row, rowW))
	}
	maxRows := max(1, m.height-8)
	hint := "↑/↓ scroll · Esc/⇧H close"
	if len(rows) > maxRows {
		m.headerScroll = clamp(m.headerScroll, 0, len(rows)-maxRows)
		hint = fmt.Sprintf("↑/↓ scroll · %d–%d of %d · Esc closes",
			m.headerScroll+1, m.headerScroll+maxRows, len(rows))
		rows = rows[m.headerScroll : m.headerScroll+maxRows]
	} else {
		m.headerScroll = 0
	}
	sb.WriteString(strings.Join(rows, "\n"))
	sb.WriteString("\n\n")
	sb.WriteString(m.theme.modalHint(hint))
	return m.theme.modalStyle.Render(sb.String())
}

// cycleSectionsMode advances the Sections view's `t` toggle between the section
// and segment tables (the raw header moved to the ⇧H overlay), skipping segments
// when the binary has none (e.g. PE). It returns a status label for the new mode.
func (m *Model) cycleSectionsMode() string {
	if m.showSegments {
		m.showSegments = false
	} else if len(m.segments) > 0 {
		m.showSegments = true
	}
	m.sectionsCur, m.sectionsTop = 0, 0
	m.sectionsFilter.SetValue("")
	m.recomputeSections()
	if m.showSegments {
		return "showing segments (t for sections)"
	}
	return "showing sections (t for segments)"
}
