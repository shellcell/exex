package ui

// shift+l (received as "L") copies the full current row — every column as shown —
// to the clipboard, across the list, byte and code views. It reuses each view's
// own row renderer and strips styling so the clipboard gets clean text.

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/x/ansi"
)

// copyCurrentLine copies the row under the cursor in the active view. It reports
// whether the key was handled (true for every view that has rows; false in views
// without a row concept, so the caller can let other handling proceed).
func (m *Model) copyCurrentLine() bool {
	line, ok := m.currentLineText()
	if !ok {
		return false
	}
	if line == "" {
		m.setStatus("nothing to copy on this line", true)
		return true
	}
	m.copyToClipboard(line, "line")
	return true
}

// currentLineText returns the plain text of the current row in the active view.
func (m *Model) currentLineText() (string, bool) {
	addrW := m.file.AddrHexWidth()
	clean := func(s string) string {
		return strings.TrimSpace(collapseSpaces(ansi.Strip(s)))
	}
	switch m.mode {
	case modeSections:
		if m.sectionsCur < 0 || m.sectionsCur >= len(m.sectionsFiltered) {
			return "", true
		}
		return clean(m.sectionRow(m.sectionsCur, addrW)), true
	case modeSymbols:
		if m.symbolsCur < 0 || m.symbolsCur >= len(m.symbolsRows) {
			return "", true
		}
		return clean(strings.Join(m.symbolRows(m.symbolsCur, addrW), " ")), true
	case modeStrings:
		m.ensureStrings()
		if m.stringsCur < 0 || m.stringsCur >= len(m.stringsFiltered) {
			return "", true
		}
		return clean(m.stringRow(m.stringsCur, addrW)), true
	case modeLibs:
		if m.libsCur < 0 || m.libsCur >= len(m.libsRows) {
			return "", true
		}
		return clean(m.libRow(m.libsCur, false)), true
	case modeSources:
		if m.srcFile != "" {
			return m.srcFile, true // open file: copy its path
		}
		if f, ok := m.sourceFileAt(m.sourcesCur); ok {
			return f, true
		}
		if m.sourcesCur >= 0 && m.sourcesCur < len(m.sourcesRows) {
			return m.sourcesRows[m.sourcesCur].node.label, true
		}
		return "", true
	case modeDisasm:
		if len(m.disasmInst) == 0 || m.disasmCur < 0 || m.disasmCur >= len(m.disasmInst) {
			return "", true
		}
		in := m.disasmInst[m.disasmCur]
		return clean(fmt.Sprintf("0x%0*x  %s  %s", addrW, in.Addr, ansi.Strip(bytesHex(in.Bytes, len(in.Bytes))), in.Text)), true
	case modeHex:
		m.ensureHex()
		return clean(m.byteRowText(modeHex, m.hexImg, m.hexCur, m.hexImg.AddrAt)), true
	case modeRaw:
		m.ensureRaw()
		return clean(m.byteRowText(modeRaw, rawBytes(m.rawData), m.rawCur, identityAddr)), true
	}
	return "", false
}

// byteRowText renders the hex/raw row containing the cursor and strips styling.
func (m *Model) byteRowText(md mode, data byteSource, cur int, addrAt func(int) uint64) string {
	if data.Len() == 0 {
		return ""
	}
	start := m.hexRowTop(md, cur, addrAt)
	span := m.hexRowSpan(md, data, start, addrAt)
	return ansi.Strip(m.renderHexRow(md, data, cur, span, m.file.AddrHexWidth(), addrAt))
}

// collapseSpaces squeezes runs of spaces to one, so a wide table row copies as a
// single readable, space-separated line rather than column-padded text.
func collapseSpaces(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	space := false
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' {
			space = true
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteByte(s[i])
	}
	return b.String()
}
