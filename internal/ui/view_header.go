package ui

// The Sections view's third mode: the raw container header (ELF e_*, Mach-O
// mach_header, PE COFF/optional header) as an aligned field table. It reuses the
// Sections view's `t` toggle (sections → segments → header) and its scroll
// cursor, but is a static key/value list, so filters, sort and row actions are
// inert here.

// headerFieldKeyWidth is the aligned width of the field-name column.
const headerFieldKeyWidth = 20

// renderHeaderFields renders the raw header field table for the Sections view's
// header mode, scrolled by the shared section cursor.
func (m *Model) renderHeaderFields(bodyH int) string {
	if bodyH < 3 {
		bodyH = 3
	}
	fields := m.file.RawHeader()
	hint := m.theme.footerStyle.Render(
		string(m.file.Format) + " header   t: toggle (sections · segments · header)")
	header := m.tableHeader(" Field                Value")
	if len(fields) == 0 {
		rows := []string{hint, header, " " + m.theme.srcShadowStyle.Render("no raw header fields for this format")}
		return padBodyRows(rows, m.width, bodyH)
	}

	visible := bodyH - 2 // hint row + header
	if visible < 1 {
		visible = 1
	}
	if m.sectionsCur >= len(fields) {
		m.sectionsCur = len(fields) - 1
	}
	if m.sectionsCur < 0 {
		m.sectionsCur = 0
	}
	top := m.visualTopForView(m.sectionsCur, m.sectionsTop, len(fields), visible, func(int) int { return 1 })
	m.sectionsTop = top
	m.pageRows = pageStep(top, len(fields), visible, func(int) int { return 1 })

	rows := []string{hint, header}
	for i := top; i < len(fields); i++ {
		f := fields[i]
		line := " " + m.theme.headerKey.Render(padVisual(f.Name, headerFieldKeyWidth)) + " " +
			m.theme.tableRowStyle.Render(f.Value)
		if i == m.sectionsCur {
			line = m.theme.tableSelStyle.Render(padVisual(f.Name, headerFieldKeyWidth+1) + " " + f.Value)
		}
		if !appendRenderedRowsIndented(&rows, line, m.width, m.wrap, 6, bodyH) {
			break
		}
	}
	return padBodyRows(rows, m.width, bodyH)
}

// cycleSectionsMode advances the Sections view's `t` toggle through
// sections → segments → header → sections, skipping the segment table when the
// binary has none (e.g. PE). It returns a status label for the new mode.
func (m *Model) cycleSectionsMode() string {
	switch {
	case m.showHeader:
		m.showHeader = false // → sections
	case m.showSegments:
		m.showSegments = false
		m.showHeader = true // → header
	default:
		if len(m.segments) > 0 {
			m.showSegments = true // → segments
		} else {
			m.showHeader = true // no segments: sections → header
		}
	}
	m.sectionsCur, m.sectionsTop = 0, 0
	m.sectionsFilter.SetValue("")
	if !m.showHeader {
		m.recomputeSections()
	}
	switch {
	case m.showHeader:
		return "showing header (t for sections)"
	case m.showSegments:
		return "showing segments (t for header)"
	default:
		return "showing sections (t for segments)"
	}
}
