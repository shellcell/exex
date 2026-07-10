package ui

// Text-script mode. When the argument isn't an ELF/Mach-O/PE binary but a
// readable text file (a shell/python/… script — which is still "executable"),
// exex shows it in a simple read-only viewer instead of erroring. Two kinds of
// token are highlighted and openable from a picker menu (Enter / o): filesystem
// paths that resolve to a real file (absolute, ~-relative, or relative to the
// script's own directory), and bare command names found on $PATH (the
// interpreters and tools the script invokes, e.g. bash, python, grep). Opening a
// referenced binary switches to the full explorer; another text file opens here
// (with Esc to go back).

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode/utf8"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/config"
	"github.com/rabarbra/exex/internal/syntax"
	"github.com/rabarbra/exex/internal/ui/layout"
)

// maxTextFileBytes bounds how much of a text file the viewer loads.
const maxTextFileBytes = 16 << 20

// LooksLikeText reports whether data (a prefix of a file is fine) is plausibly a
// text file: no NUL bytes and overwhelmingly printable/UTF-8. Used to decide
// whether a non-binary argument should open in the text viewer.
func LooksLikeText(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return false // a NUL byte means binary
	}
	printable := 0
	for _, b := range data {
		if b == '\n' || b == '\t' || b == '\r' || (b >= 0x20 && b < 0x7f) || b >= 0x80 {
			printable++
		}
	}
	return printable*100/len(data) >= 95 && utf8.Valid(data)
}

// pathSpan marks a byte range on a line that is a resolvable filesystem path.
type pathSpan struct {
	start, end int
	resolved   string // absolute path on disk
}

// textHist is one entry in the back stack (a previously-viewed file + scroll).
type textHist struct {
	path string
	top  int
}

type textModel struct {
	cfg   config.Config
	theme Theme

	hl *syntax.Highlighter

	path    string
	dir     string
	lines   []string
	hlLines []string     // syntax-highlighted lines (ANSI), indexed like lines
	spans   [][]pathSpan // path spans per line
	picks   []string     // unique resolved paths, for the open menu

	top           int
	width, height int

	pickerActive bool
	pickerSel    int
	pickerTop    int

	hist   []textHist
	status string
}

// NewText builds the text-viewer model for a script/text file.
func NewText(path string, cfg config.Config) (tea.Model, error) {
	m := &textModel{cfg: cfg, theme: NewTheme(cfg), hl: syntax.NewHighlighter(sourceSyntaxTheme(cfg))}
	if err := m.load(path); err != nil {
		return nil, err
	}
	return m, nil
}

// load reads path and recomputes the highlighted paths.
func (m *textModel) load(path string) error {
	data, err := readFilePrefix(path, maxTextFileBytes+1)
	if err != nil {
		return err
	}
	if len(data) > maxTextFileBytes {
		data = data[:maxTextFileBytes]
	}
	m.path = path
	m.dir = filepath.Dir(path)
	m.lines = strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	m.hlLines = m.hl.Highlight(path, m.lines)
	m.spans, m.picks = extractPaths(m.lines, m.dir)
	m.top = 0
	m.pickerActive = false
	m.pickerSel, m.pickerTop = 0, 0
	return nil
}

func (m *textModel) Init() tea.Cmd { return nil }

func (m *textModel) bodyHeight() int {
	if m.height <= 2 {
		return 1
	}
	return m.height - 2 // header + footer
}

func (m *textModel) maxTop() int {
	if d := len(m.lines) - m.bodyHeight(); d > 0 {
		return d
	}
	return 0
}

func (m *textModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil
	case tea.MouseMsg:
		if w, ok := msg.(tea.MouseWheelMsg); ok {
			switch w.Mouse().Button {
			case tea.MouseWheelUp:
				m.scroll(-3)
			case tea.MouseWheelDown:
				m.scroll(3)
			}
		}
		return m, nil
	case tea.KeyMsg:
		return m.handleKey(msg.String())
	}
	return m, nil
}

func (m *textModel) handleKey(key string) (tea.Model, tea.Cmd) {
	if m.pickerActive {
		switch key {
		case "esc", "o":
			m.pickerActive = false
		case "up", "k":
			if m.pickerSel > 0 {
				m.pickerSel--
			}
		case "down", "j":
			if m.pickerSel < len(m.picks)-1 {
				m.pickerSel++
			}
		case "enter":
			if m.pickerSel >= 0 && m.pickerSel < len(m.picks) {
				return m.open(m.picks[m.pickerSel])
			}
		}
		return m, nil
	}

	switch key {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "esc", "backspace", "ctrl+w":
		return m.back()
	case "enter", "o":
		if len(m.picks) == 0 {
			m.status = "no openable file paths found in this file"
			return m, nil
		}
		m.pickerActive = true
		m.pickerSel, m.pickerTop = 0, 0
	case "up", "k":
		m.scroll(-1)
	case "down", "j":
		m.scroll(1)
	case "pgup", "[":
		m.scroll(-m.bodyHeight())
	case "pgdown", "]":
		m.scroll(m.bodyHeight())
	case "home", "g":
		m.top = 0
	case "end", "G":
		m.top = m.maxTop()
	}
	return m, nil
}

func (m *textModel) scroll(delta int) {
	m.top = layout.Clamp(m.top+delta, 0, m.maxTop())
}

// back returns to the previously-viewed text file, or quits at the root.
func (m *textModel) back() (tea.Model, tea.Cmd) {
	if len(m.hist) == 0 {
		return m, tea.Quit
	}
	prev := m.hist[len(m.hist)-1]
	m.hist = m.hist[:len(m.hist)-1]
	if err := m.load(prev.path); err != nil {
		m.status = "back: " + err.Error()
		return m, nil
	}
	m.top = layout.Clamp(prev.top, 0, m.maxTop())
	return m, nil
}

// open acts on a chosen path: a binary opens in the full explorer; another text
// file opens here (pushing the current file onto the back stack).
func (m *textModel) open(resolved string) (tea.Model, tea.Cmd) {
	m.pickerActive = false
	if f, err := binfile.Open(resolved); err == nil {
		nm, nerr := New(f, Options{Config: &m.cfg})
		if nerr != nil {
			f.Close()
			m.status = "open: " + nerr.Error()
			return m, nil
		}
		nm.width, nm.height = m.width, m.height
		return nm, nm.Init()
	}
	data, err := readFilePrefix(resolved, 8192)
	if err != nil {
		m.status = "open: " + err.Error()
		return m, nil
	}
	if !LooksLikeText(data) {
		m.status = "can't open " + filepath.Base(resolved) + ": not a binary or text file"
		return m, nil
	}
	m.hist = append(m.hist, textHist{path: m.path, top: m.top})
	if err := m.load(resolved); err != nil {
		m.status = "open: " + err.Error()
	}
	return m, nil
}

func readFilePrefix(path string, limit int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, int64(limit)))
}

func (m *textModel) View() tea.View {
	if m.width == 0 || m.height == 0 {
		return tea.NewView("initializing…")
	}
	bodyH := m.bodyHeight()
	suffix := fmt.Sprintf("   (%d lines, %d paths)", len(m.lines), len(m.picks))
	header := m.theme.viewTitleLine(layout.TruncateMiddle(m.path, max(1, m.width-lipgloss.Width(suffix)))+suffix, m.width)

	var b strings.Builder
	for i := m.top; i < len(m.lines) && i < m.top+bodyH; i++ {
		b.WriteString(m.renderLine(i))
		b.WriteByte('\n')
	}
	body := layout.PadBody(b.String(), m.width, bodyH)

	footer := m.theme.footerStyle.Render("↑/↓ scroll · Enter/o open path menu · Esc back · q quit")
	if m.status != "" {
		footer = m.theme.infoStyle.Render(m.status)
	}
	out := header + "\n" + body + "\n" + layout.PadRight(footer, m.width)

	if m.pickerActive {
		out = m.overlayCenterText(out, m.renderPicker())
	}

	v := tea.NewView(out)
	v.AltScreen = true
	v.MouseMode = tea.MouseModeCellMotion
	return v
}

// renderLine renders one syntax-highlighted source line, underlining the
// resolvable path/command spans so they read as openable links without losing
// their syntax colour.
func (m *textModel) renderLine(i int) string {
	line := m.lines[i]
	if i < len(m.hlLines) && m.hlLines[i] != "" {
		line = m.hlLines[i]
	}
	line = underlineRanges(line, m.spans[i])
	return layout.PadRight(layout.FitANSIWidth(line, m.width), m.width)
}

// underlineRanges adds an underline over the given byte ranges of an
// ANSI-coloured line. The spans are byte offsets into the *plain* text; this
// maps them onto the coloured string (escapes don't count as visible bytes) and
// re-asserts the underline after any SGR reset inside a span, so it survives the
// per-token resets the syntax highlighter emits. The fg colour is left intact.
func underlineRanges(s string, spans []pathSpan) string {
	if len(spans) == 0 {
		return s
	}
	const ulOn, ulOff = "\x1b[4m", "\x1b[24m"
	var b strings.Builder
	b.Grow(len(s) + len(spans)*8)
	vis, si := 0, 0
	inSpan := false
	for i := 0; i < len(s); {
		if s[i] == 0x1b { // copy an escape sequence verbatim
			j := i + 1
			if j < len(s) && s[j] == '[' {
				j++
				for j < len(s) && (s[j] < 0x40 || s[j] > 0x7e) {
					j++
				}
				if j < len(s) {
					j++
				}
			}
			esc := s[i:j]
			b.WriteString(esc)
			if inSpan && (esc == "\x1b[0m" || esc == "\x1b[m") {
				b.WriteString(ulOn) // reset cleared underline — turn it back on
			}
			i = j
			continue
		}
		if !inSpan && si < len(spans) && vis == spans[si].start {
			b.WriteString(ulOn)
			inSpan = true
		}
		b.WriteByte(s[i])
		vis++
		i++
		if inSpan && vis == spans[si].end {
			b.WriteString(ulOff)
			inSpan = false
			si++
		}
	}
	if inSpan {
		b.WriteString(ulOff)
	}
	return b.String()
}

func (m *textModel) renderPicker() string {
	const visible = 12
	rowW := modalListWidth(m.width)
	var sb strings.Builder
	sb.WriteString(m.theme.modalTitle("Open path"))
	sb.WriteString("\n\n")
	top := layout.VisualTop(m.pickerSel, m.pickerTop, len(m.picks), visible, func(int) int { return 1 })
	m.pickerTop = top
	end := min(top+visible, len(m.picks))
	for i := top; i < end; i++ {
		label := m.picks[i]
		if rel, err := filepath.Rel(m.dir, label); err == nil && !strings.HasPrefix(rel, "..") {
			label = rel
		}
		line := layout.PadRight(" "+layout.TruncateMiddle(label, rowW-2), rowW)
		if i == m.pickerSel {
			line = m.theme.tableSelStyle.Render(line)
		}
		sb.WriteString(line)
		sb.WriteString("\n")
	}
	sb.WriteString("\n")
	sb.WriteString(m.theme.modalHint(
		fmt.Sprintf("↑/↓ select · Enter open · Esc cancel   (%d/%d)", m.pickerSel+1, len(m.picks))))
	return m.theme.modalStyle.Render(sb.String())
}

// overlayCenterText centres a modal over the text view (mirrors the binary UI's
// overlayCenter, without the model dependency).
func (m *textModel) overlayCenterText(bg, modal string) string {
	mw := lipgloss.Width(modal)
	mh := lipgloss.Height(modal)
	return layout.Overlay(bg, modal, (m.width-mw)/2, (m.height-mh)/2)
}

// extractPaths finds, per line, the byte spans that are filesystem paths
// resolving to an existing regular file (absolute, ~-relative, or relative to
// dir), and the de-duplicated set of resolved paths for the open menu.
func extractPaths(lines []string, dir string) ([][]pathSpan, []string) {
	spans := make([][]pathSpan, len(lines))
	seen := map[string]bool{}
	pathCache := map[string]string{} // memoised filesystem hits and misses
	cmdCache := map[string]string{}  // memoised $PATH lookups
	var picks []string
	for i, line := range lines {
		var ls []pathSpan
		for s := 0; s < len(line); {
			if isPathDelim(line[s]) {
				s++
				continue
			}
			e := s
			for e < len(line) && !isPathDelim(line[e]) {
				e++
			}
			tok := line[s:e]
			// A filesystem path first; otherwise a bare command name on $PATH.
			resolved, cached := pathCache[tok]
			if !cached {
				resolved = resolveExistingPath(tok, dir)
				pathCache[tok] = resolved
			}
			if resolved == "" {
				resolved = resolveCommand(tok, cmdCache)
			}
			if resolved != "" {
				ls = append(ls, pathSpan{start: s, end: e, resolved: resolved})
				if !seen[resolved] {
					seen[resolved] = true
					picks = append(picks, resolved)
				}
			}
			s = e
		}
		spans[i] = ls
	}
	return spans, picks
}

// isPathDelim reports whether b separates path tokens. Shell/quote/operator
// punctuation (and ':' so PATH-lists and URLs split into parts) are delimiters.
func isPathDelim(b byte) bool {
	switch b {
	case ' ', '\t', '"', '\'', '`', '(', ')', '[', ']', '{', '}',
		'<', '>', '|', '&', ';', ',', '=', '*', '?', '!', ':', '$', '#':
		return true
	}
	return false
}

// resolveExistingPath returns the absolute path a token points at when it looks
// path-like and resolves to an existing regular file, else "". Relative tokens
// resolve against dir (the script's own directory).
func resolveExistingPath(tok, dir string) string {
	if len(tok) < 2 {
		return ""
	}
	// Require a path-ish shape to avoid matching bare words that happen to name a
	// file: a separator, a dot, or a ~ prefix.
	if !strings.ContainsAny(tok, "/.") && !strings.HasPrefix(tok, "~") {
		return ""
	}
	p := tok
	if strings.HasPrefix(p, "~") {
		if home, err := os.UserHomeDir(); err == nil {
			p = home + p[1:]
		}
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(dir, p)
	}
	if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
		return p
	}
	return ""
}

// resolveCommand returns the $PATH location of a bare command-name token (the
// interpreters/tools a script invokes, e.g. bash, python3, grep), or "". Tokens
// containing a path separator are left to resolveExistingPath; shell keywords
// (if, then, fi, …) aren't on $PATH so they don't match. Results are memoised in
// cache (including misses) so a token is looked up at most once per file.
func resolveCommand(tok string, cache map[string]string) string {
	if strings.ContainsAny(tok, "/~") || !isCommandName(tok) {
		return ""
	}
	if p, ok := cache[tok]; ok {
		return p
	}
	p, err := exec.LookPath(tok)
	if err != nil {
		p = ""
	}
	cache[tok] = p
	return p
}

// isCommandName reports whether tok has the shape of a command name: at least
// two characters, starting alphanumeric, the rest alphanumeric or ._+-, and
// containing at least one letter (so pure numbers aren't looked up).
func isCommandName(tok string) bool {
	if len(tok) < 2 {
		return false
	}
	letter := false
	for i := 0; i < len(tok); i++ {
		switch c := tok[i]; {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
			letter = true
		case c >= '0' && c <= '9':
		case c == '.' || c == '_' || c == '+' || c == '-':
		default:
			return false
		}
	}
	return letter
}
