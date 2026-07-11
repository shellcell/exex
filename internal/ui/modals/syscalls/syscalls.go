// Package syscalls is the system-calls results overlay: every place the binary
// enters the kernel, grouped by scope (this function / the whole binary / one row
// per distinct call / the binary plus its linked libraries), sortable, filterable
// and followable with Enter.
//
// Finding the sites is analysis (internal/dump) and running the two scans off the
// UI goroutine is the shell's. This package owns what the results look like, how
// they respond to input, and which scope is showing — including the fact that the
// full scope's scan is started lazily the first time it is selected.
package syscalls

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/rabarbra/exex/internal/dump"
	"github.com/rabarbra/exex/internal/ui/layout"
	"github.com/rabarbra/exex/internal/ui/modal"
)

// Scope selects which sites the overlay lists.
type Scope uint8

const (
	ScopeFunc   Scope = iota // only the function under the cursor
	ScopeAll                 // every site in the binary
	ScopeUnique              // one row per distinct syscall number
	ScopeFull                // unique across the binary + its linked libs
	ScopeCount
)

// SortKey selects how the overlay orders its rows. Each key has a "natural"
// direction (number/name/address ascending, count descending) that `r` reverses.
type SortKey uint8

const (
	SortNumber SortKey = iota // grouped: numbered (by number), vDSO, unresolved
	SortName                  // resolved name (A→Z)
	SortCount                 // occurrences (most-used first)
	SortAddr                  // first site's address (execution order)
	SortKeyCount
)

func (k SortKey) String() string {
	switch k {
	case SortName:
		return "name"
	case SortCount:
		return "count"
	case SortAddr:
		return "address"
	default:
		return "number"
	}
}

// Row is one displayed line: a representative site and, in the aggregated scopes,
// how many sites share its number.
type Row struct {
	Site  dump.SyscallSite
	Count int
}

// Host is what the overlay needs from the shell beyond the modal base.
type Host interface {
	modal.Host
	// StartFullScan launches the (lazy) binary + libraries scan.
	StartFullScan() tea.Cmd
	// CancelFullScan abandons it, when leaving the full scope or jumping away.
	CancelFullScan()
}

// State is the results overlay. Call SetInput once before use.
type State struct {
	active bool

	results []dump.SyscallSite
	shown   []Row
	sel     int
	top     int
	total   int // rows in the active scope before the text filter

	scope     Scope
	sort      SortKey
	sortDesc  bool
	filter    textinput.Model
	filtering bool

	// The function under the cursor when the scan was launched, so its sites can
	// be marked and pre-selected.
	fnLo, fnHi uint64
	fnName     string

	// Full scope (binary + linked libraries), scanned lazily off-thread. The
	// overlay renders its progress, so it holds the display side of that state.
	full        []dump.SyscallSite
	fullNotes   []string // libraries that couldn't be scanned
	fullObjs    int      // objects scanned
	fullDone    bool
	fullRunning bool

	listRow int
}

// SetInput installs the filter widget. The shell owns its styling, so it builds
// it and hands it over.
func (s *State) SetInput(in textinput.Model) { s.filter = in }

// ensureInput guarantees the filter is constructed before it is focused or
// rendered, so a State built without SetInput can't panic.
func (s *State) ensureInput() {
	if s.filter.Prompt == "" {
		s.filter = textinput.New()
		s.filter.Prompt = "/ "
	}
}

// SetFunc records the function the scan was launched from.
func (s *State) SetFunc(lo, hi uint64, name string) { s.fnLo, s.fnHi, s.fnName = lo, hi, name }

// FuncName is the name of that function, or "".
func (s *State) FuncName() string { return s.fnName }

// InFunc reports whether addr is inside it.
func (s *State) InFunc(addr uint64) bool {
	return s.fnHi > s.fnLo && addr >= s.fnLo && addr < s.fnHi
}

// CountInFunc is how many of the given sites fall inside it.
func (s *State) CountInFunc(sites []dump.SyscallSite) int {
	n := 0
	for _, site := range sites {
		if s.InFunc(site.Addr) {
			n++
		}
	}
	return n
}

// Open shows the overlay for a finished direct scan. It lands in the function
// scope when the cursor's function has syscalls (the common "what does this
// function call?" question); otherwise it shows them all.
func (s *State) Open(sites []dump.SyscallSite) {
	s.results = sites
	s.sel, s.top = 0, 0
	s.resetFilter()
	if s.CountInFunc(sites) > 0 {
		s.scope = ScopeFunc
	} else {
		s.scope = ScopeAll
	}
	s.rebuild()
	s.active = true
}

// OpenFull shows the overlay straight in full (binary + libs) scope, for a binary
// with no direct syscall sites of its own. It reports whether the caller must
// start the library scan.
//
// A macOS executable never traps to the kernel itself — its syscalls live in
// libsystem_kernel, reached through the dyld shared cache — so rather than a bare
// "none found" that hides where the syscalls actually are, the transitive scan is
// surfaced. A statically linked ELF with none of its own works the same way.
func (s *State) OpenFull() (needsScan bool) {
	s.results = nil
	s.sel, s.top = 0, 0
	s.resetFilter()
	s.scope = ScopeFull
	s.rebuild()
	s.active = true
	return !s.fullDone && !s.fullRunning
}

func (s *State) resetFilter() {
	s.ensureInput()
	s.filter.SetValue("")
	s.filter.Blur()
	s.filtering = false
}

func (s *State) Active() bool { return s.active }
func (s *State) Close()       { s.active = false }
func (s *State) ListRow() int { return s.listRow }
func (s *State) Sel() int     { return s.sel }

// Scope returns the active scope.
func (s *State) Scope() Scope { return s.scope }

// SetScope switches scope and rebuilds the rows, without the key handler's
// side effects (starting or cancelling the library scan).
func (s *State) SetScope(sc Scope) {
	s.scope = sc
	s.sel, s.top = 0, 0
	s.rebuild()
}

// FullSites returns the library-scan results collected so far.
func (s *State) FullSites() []dump.SyscallSite { return s.full }

// Shown returns how many rows the active scope + filter leave visible.
func (s *State) Shown() int { return len(s.shown) }

// Rows returns the visible rows.
func (s *State) Rows() []Row { return s.shown }

// Filtering reports whether the filter box has the keyboard.
func (s *State) Filtering() bool { return s.filtering }

// FullDone reports whether it has completed.
func (s *State) FullDone() bool { return s.fullDone }

// SetFullRunning records that the library scan has started, or been abandoned.
func (s *State) SetFullRunning(running bool) { s.fullRunning = running }

// SetFullResults records a finished library scan and rebuilds the rows.
func (s *State) SetFullResults(sites []dump.SyscallSite, notes []string, objs int) {
	s.full, s.fullNotes, s.fullObjs = sites, notes, objs
	s.fullDone, s.fullRunning = true, false
	s.rebuild()
}

// RelabelSymbols re-resolves every direct site's containing-symbol name, for when
// the shell's symbol display form changes while the overlay is open.
func (s *State) RelabelSymbols(displayAt func(addr uint64) string) {
	for i := range s.results {
		s.results[i].Sym = displayAt(s.results[i].Addr)
	}
	s.rebuild()
}

func (s *State) List() (sel *int, top, n int, wrap, ok bool) {
	return &s.sel, s.top, len(s.shown), false, true
}

func (s *State) ClickRow(listRow int) bool {
	return modal.ClickIndex(&s.sel, s.top, len(s.shown), listRow)
}

// rebuild recomputes the displayed rows for the active scope, sort and filter.
func (s *State) rebuild() {
	rows := s.shown[:0]
	switch s.scope {
	case ScopeFunc:
		for _, site := range s.results {
			if s.InFunc(site.Addr) {
				rows = append(rows, Row{Site: site, Count: 1})
			}
		}
	case ScopeUnique:
		rows = uniqueRows(s.results, rows)
	case ScopeFull:
		rows = uniqueRows(s.full, rows)
	default: // ScopeAll
		for _, site := range s.results {
			rows = append(rows, Row{Site: site, Count: 1})
		}
	}
	sortRows(rows, s.sort, s.sortDesc)
	s.total = len(rows)

	// Apply the free-text filter (compacting in place — the kept index never
	// overtakes the read index, so the shared backing array is safe to reuse).
	if needle := strings.ToLower(strings.TrimSpace(s.filter.Value())); needle != "" {
		kept := rows[:0]
		for _, r := range rows {
			if rowMatches(r, needle) {
				kept = append(kept, r)
			}
		}
		rows = kept
	}
	s.shown = rows
	if s.sel >= len(rows) {
		s.sel = max(0, len(rows)-1)
	}
}

// sortRows orders rows by the chosen key. The default (number) groups them like
// the dump: numbered first (ascending), then vDSO, then unresolved.
func sortRows(rows []Row, key SortKey, desc bool) {
	less := func(i, j int) bool {
		a, b := rows[i], rows[j]
		switch key {
		case SortName:
			if a.Site.Name != b.Site.Name {
				return a.Site.Name < b.Site.Name
			}
			return numberLess(a.Site, b.Site)
		case SortCount:
			if a.Count != b.Count {
				return a.Count > b.Count // most-used first
			}
			return numberLess(a.Site, b.Site)
		case SortAddr:
			return a.Site.Addr < b.Site.Addr
		default: // SortNumber
			return numberLess(a.Site, b.Site)
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if desc {
			return less(j, i)
		}
		return less(i, j)
	})
}

// numberLess is the dump's canonical order: numbered sites first (by number),
// then vDSO calls, then unresolved sites (by instruction text).
func numberLess(a, b dump.SyscallSite) bool {
	if a.HasNum != b.HasNum {
		return a.HasNum
	}
	if a.HasNum {
		return a.Num < b.Num
	}
	if a.VDSO != b.VDSO {
		return a.VDSO
	}
	return a.Text < b.Text
}

// rowMatches reports whether a row matches the (lower-cased) filter needle,
// testing the resolved name, the number (decimal and 0x hex), the symbol/origin
// and the instruction text — so "write", "4", "0x4" or "_start" all narrow.
func rowMatches(r Row, needle string) bool {
	s := r.Site
	if layout.ContainsFold(s.Name, needle) || layout.ContainsFold(s.Sym, needle) ||
		layout.ContainsFold(s.Origin, needle) || layout.ContainsFold(s.Text, needle) {
		return true
	}
	if s.HasNum {
		if layout.ContainsFold(strconv.FormatInt(s.Num, 10), needle) ||
			layout.ContainsFold("0x"+strconv.FormatInt(s.Num, 16), needle) {
			return true
		}
	}
	return s.VDSO && layout.ContainsFold("vdso", needle)
}

// category classifies a site for colouring: resolved-to-a-name, number-only
// (known number but no table entry), vDSO, or unresolved.
type category uint8

const (
	catNamed      category = iota // number resolved to a table name
	catNumberOnly                 // number known, not in the table
	catVDSO                       // vDSO / __kernel_ helper call
	catUnresolved                 // couldn't recover the number
)

func categoryOf(s dump.SyscallSite) category {
	switch {
	case s.HasNum && s.Name != "":
		return catNamed
	case s.HasNum:
		return catNumberOnly
	case s.VDSO:
		return catVDSO
	default:
		return catUnresolved
	}
}

func catStyle(ctx modal.Context, c category) lipgloss.Style {
	switch c {
	case catNamed:
		return ctx.InfoStyle // green
	case catNumberOnly:
		return ctx.WarnStyle // yellow
	case catVDSO:
		return ctx.AccentStyle // blue/cyan
	default:
		return ctx.ShadowStyle // dim
	}
}

// uniqueRows aggregates sites into one row per distinct syscall (number, or
// vDSO/unresolved text), counting occurrences. The first site of each kind is
// kept as the representative (carrying its origin, for the full scope).
func uniqueRows(sites []dump.SyscallSite, rows []Row) []Row {
	idx := make(map[string]int, len(sites))
	var key [24]byte
	for _, s := range sites {
		var k string
		switch {
		case s.HasNum:
			k = "n" + string(strconv.AppendInt(key[:0], s.Num, 10))
		case s.VDSO:
			k = "v" + s.Text
		default:
			k = "u" + s.Text
		}
		if j, ok := idx[k]; ok {
			rows[j].Count++
			continue
		}
		idx[k] = len(rows)
		rows = append(rows, Row{Site: s, Count: 1})
	}
	return rows
}

// ScopeLabel names the active scope, for the status line and the subtitle.
func (s *State) ScopeLabel() string {
	switch s.scope {
	case ScopeFunc:
		if s.fnName != "" {
			return "in " + s.fnName
		}
		return "this function"
	case ScopeUnique:
		return "unique"
	case ScopeFull:
		if s.fullRunning {
			return "full (+libs) — scanning…"
		}
		if s.fullDone {
			return fmt.Sprintf("full · binary + %d libs", max(0, s.fullObjs-1))
		}
		return "full (+libs)"
	default:
		return "whole binary"
	}
}

// Update drives the results list. When the filter box is focused, typing edits it
// and only the arrows/Enter/Esc/Tab are special; otherwise t cycles scope, s/r
// sort, / focuses the filter, Enter jumps and Esc closes.
func (s *State) Update(host Host, msg tea.KeyMsg, key string) tea.Cmd {
	s.ensureInput()
	rows := s.shown
	if s.filtering {
		switch key {
		case "esc": // clear the filter and leave the box (overlay stays open)
			s.clearFilter()
			return nil
		case "up":
			if s.sel > 0 {
				s.sel--
			}
			return nil
		case "down":
			if s.sel < len(rows)-1 {
				s.sel++
			}
			return nil
		case "enter":
			return s.Activate(host)
		default:
			if key == "tab" { // commit the filter, return to command keys
				s.filter.Blur()
				s.filtering = false
				return nil
			}
			var cmd tea.Cmd
			s.filter, cmd = s.filter.Update(msg)
			s.sel, s.top = 0, 0
			s.rebuild()
			return cmd
		}
	}

	switch key {
	case "esc":
		s.Close()
	case "/":
		s.filtering = true
		return s.filter.Focus()
	case "t", "tab", "shift+tab":
		oldScope := s.scope
		if key == "shift+tab" {
			s.scope = (s.scope + ScopeCount - 1) % ScopeCount
		} else {
			s.scope = (s.scope + 1) % ScopeCount
		}
		if oldScope == ScopeFull && s.scope != ScopeFull {
			host.CancelFullScan()
		}
		s.sel, s.top = 0, 0
		s.rebuild()
		host.SetStatus("syscalls: "+s.ScopeLabel(), false)
		// Entering full scope kicks off the (lazy) binary + libraries scan.
		if s.scope == ScopeFull && !s.fullDone && !s.fullRunning {
			return host.StartFullScan()
		}
	case "s":
		s.sort = (s.sort + 1) % SortKeyCount
		s.sel, s.top = 0, 0
		s.rebuild()
		host.SetStatus("sort: "+s.sort.String(), false)
	case "r":
		s.sortDesc = !s.sortDesc
		s.sel, s.top = 0, 0
		s.rebuild()
	case "up", "k":
		if s.sel > 0 {
			s.sel--
		}
	case "down", "j":
		if s.sel < len(rows)-1 {
			s.sel++
		}
	case "enter":
		return s.Activate(host)
	}
	return nil
}

// clearFilter empties the filter, defocuses it and rebuilds the rows.
func (s *State) clearFilter() {
	s.filter.SetValue("")
	s.filter.Blur()
	s.filtering = false
	s.sel, s.top = 0, 0
	s.rebuild()
}

// Activate follows the selected site to the disassembly, refusing sites that live
// in a linked library (a different address space).
func (s *State) Activate(host Host) tea.Cmd {
	if s.sel < 0 || s.sel >= len(s.shown) {
		return nil
	}
	site := s.shown[s.sel].Site
	if site.Origin != "" && site.Origin != "this binary" {
		host.SetStatus("site is in "+site.Origin+" — open it as primary to inspect", true)
		return nil
	}
	s.Close()
	host.CancelFullScan()
	host.LoadDisasmAt(site.Addr)
	return nil
}

// scopeBar renders the four scopes as a segmented control with the active one
// highlighted, so the t-cycle's options and current position are explicit rather
// than hidden behind a keystroke.
func (s *State) scopeBar(ctx modal.Context) string {
	names := [ScopeCount]string{"function", "binary", "unique", "full+libs"}
	var b strings.Builder
	b.WriteString(ctx.Hint("scope "))
	for i, n := range names {
		if i > 0 {
			b.WriteString(ctx.ShadowStyle.Render(" "))
		}
		if Scope(i) == s.scope {
			b.WriteString(ctx.SelStyle.Render(" " + n + " "))
		} else {
			b.WriteString(ctx.ShadowStyle.Render(" " + n + " "))
		}
	}
	if s.scope == ScopeFunc && s.fnName != "" {
		b.WriteString(ctx.Hint("  " + s.fnName))
	}
	return b.String()
}

// legend renders the colour key (named / num-only / vdso / unresolved) and the
// active sort, so the row colouring is self-explanatory.
func (s *State) legend(ctx modal.Context) string {
	sep := ctx.ShadowStyle.Render(" · ")
	dir := "↑"
	if s.sortDesc {
		dir = "↓"
	}
	return catStyle(ctx, catNamed).Render("named") + sep +
		catStyle(ctx, catNumberOnly).Render("num-only") + sep +
		catStyle(ctx, catVDSO).Render("vdso") + sep +
		catStyle(ctx, catUnresolved).Render("unresolved") +
		ctx.Hint("    sort: "+s.sort.String()+dir)
}

// Name-column bounds. The column sizes itself to the widest label actually
// present, because a fixed 16 truncated real syscall names ("kdebug_trace_string"
// became "kd…e_string") while the origin column beside it sat half empty. The
// extra width comes out of the origin column, which pads generously.
const (
	minNameW = 16
	maxNameW = 32
)

// labelText is the syscall's display label: "#<num> <name>", or whichever part
// is known.
func labelText(s dump.SyscallSite) string {
	switch {
	case s.Name != "" && s.HasNum:
		return fmt.Sprintf("#%d %s", s.Num, s.Name)
	case s.Name != "":
		return s.Name
	case s.HasNum:
		return fmt.Sprintf("#%d", s.Num)
	case s.VDSO:
		return "vdso"
	}
	return ""
}

// labelWidth is labelText's display width, computed arithmetically so sizing the
// column over every row costs no allocations.
func labelWidth(s dump.SyscallSite) int {
	switch {
	case s.Name != "" && s.HasNum:
		return 1 + digits(s.Num) + 1 + len(s.Name)
	case s.Name != "":
		return len(s.Name)
	case s.HasNum:
		return 1 + digits(s.Num)
	case s.VDSO:
		return len("vdso")
	}
	return 0
}

func digits(n int64) int {
	if n < 0 {
		return 1 + digits(-n)
	}
	d := 1
	for n >= 10 {
		n /= 10
		d++
	}
	return d
}

// nameColumnWidth sizes the name column to the widest label in *every* row, not
// just the visible ones, so the columns don't shift as the list scrolls.
func nameColumnWidth(rows []Row) int {
	w := minNameW
	for i := range rows {
		if lw := labelWidth(rows[i].Site); lw > w {
			w = lw
		}
	}
	return min(w, maxNameW)
}

// noteLines is how many lines the unresolved-libraries note will occupy, so the
// row area can be shrunk to keep the whole overlay within the terminal.
func (s *State) noteLines() int {
	if s.scope != ScopeFull || len(s.fullNotes) == 0 {
		return 0
	}
	n := 2 + min(len(s.fullNotes), 4) // blank + header + up to 4 libs
	if len(s.fullNotes) > 4 {
		n++ // "… and N more"
	}
	return n
}

func (s *State) Render(ctx modal.Context) string {
	s.ensureInput()
	var sb strings.Builder
	addrW := ctx.AddrHexWidth()
	rowW := ctx.ListWidth()
	// Size the row area so the whole overlay fits the terminal height. Chrome is:
	// border(2) + padding(2) + title + blank + scope + filter + legend + blank
	// (6 header) + blank + footer (2) = 14 lines, plus the unresolved-library notes
	// when shown — subtract all of it so the overlay shrinks instead of overflowing.
	visible := layout.Clamp(ctx.Height-14-s.noteLines(), 3, 40)
	rows := s.shown
	if s.sel >= len(rows) {
		s.sel = max(0, len(rows)-1)
	}
	full := s.scope == ScopeFull
	aggregated := s.scope == ScopeUnique || full

	// Column budget: "● <addr|count>  <name|#num>  <sym|origin>  <text>". The name
	// column takes what it needs; the origin column absorbs the difference.
	nameW := nameColumnWidth(rows)
	avail := rowW - len("● ") - (2 + addrW) - len("  ") - nameW - len("  ") - len("  ") - 6
	textW := layout.Clamp(avail/3, 10, 32)
	symW := max(8, avail-textW)

	// Header: title, scope segmented control, filter box (with shown/total count),
	// and the colour/sort legend — then a blank line before the rows.
	sb.WriteString(ctx.Title("System calls"))
	sb.WriteString("\n\n")
	sb.WriteString(" " + layout.FitANSIWidth(s.scopeBar(ctx), rowW-1))
	sb.WriteString("\n")
	countStr := fmt.Sprintf("  %d", len(rows))
	if s.total != len(rows) {
		countStr = fmt.Sprintf("  %d of %d", len(rows), s.total)
	}
	s.filter.SetWidth(layout.Clamp(rowW-len(countStr)-4, 12, 60))
	sb.WriteString(" " + layout.FitANSIWidth(s.filter.View()+ctx.Hint(countStr), rowW-1))
	sb.WriteString("\n")
	sb.WriteString(" " + layout.FitANSIWidth(s.legend(ctx), rowW-1))
	sb.WriteString("\n\n")
	s.listRow = 6 // title + blank + scope + filter + legend + blank
	s.top = layout.VisualTop(s.sel, s.top, len(rows), visible, func(int) int { return 1 })
	// Always emit exactly `visible` rows (padding with blanks past the last hit) so
	// the overlay keeps a constant height and doesn't bounce vertically as the
	// filter narrows the list.
	blankRow := layout.PadVisual("", rowW)
	// No rows (an over-narrow filter, or a still-running full scan): a single
	// centred message in the middle of the reserved row area.
	emptyMsg := ""
	if len(rows) == 0 {
		switch {
		case full && s.fullRunning:
			emptyMsg = "scanning binary + libraries…"
		case full && s.fullDone:
			emptyMsg = "no syscalls found in the binary or its libraries"
		case s.filter.Value() != "":
			emptyMsg = "no syscalls match the filter"
		default:
			emptyMsg = "no syscalls"
		}
	}
	for row := range visible {
		i := s.top + row
		if i >= len(rows) {
			if emptyMsg != "" && row == visible/2 {
				sb.WriteString(modal.CenterLine(ctx.ShadowStyle.Render(emptyMsg), rowW))
			} else {
				sb.WriteString(blankRow)
			}
			sb.WriteString("\n")
			continue
		}
		h := rows[i].Site
		loc := h.Sym
		if full { // in the full scope the originating object is more useful than the symbol
			loc = h.Origin
		}
		if loc == "" {
			loc = "—"
		}
		mark := " "
		if !aggregated && s.InFunc(h.Addr) {
			mark = "●"
		}
		text := layout.TruncateMiddle(h.Text, textW)
		if h.VDSO {
			text += " ·vdso"
		}
		label := labelText(h)
		// Colour the syscall label by resolution category (named / num-only / vdso /
		// unresolved) so the eye can pick out which numbers actually mapped to a name.
		num := catStyle(ctx, categoryOf(h)).Render(layout.PadVisual(layout.TruncateMiddle(label, nameW), nameW))
		// In aggregated scopes (unique / full) show a use count instead of an address.
		first := fmt.Sprintf("0x%0*x", addrW, h.Addr)
		if aggregated {
			first = layout.PadVisual(fmt.Sprintf("%d×", rows[i].Count), 2+addrW)
		}
		line := fmt.Sprintf("%s %s  %s  %s  %s",
			mark, first, num,
			layout.PadVisual(layout.TruncateMiddle(loc, symW), symW),
			text)
		line = layout.PadVisual(line, rowW)
		if i == s.sel { // strip the category colour so the selection bar reads cleanly
			line = ctx.SelStyle.Render(ansi.Strip(line))
		}
		sb.WriteString(line)
		sb.WriteString("\n")
	}
	// Full scope: list libraries that couldn't be scanned, mirroring the dump.
	if full && len(s.fullNotes) > 0 {
		sb.WriteString("\n")
		sb.WriteString(" " + ctx.WarnStyle.Render(fmt.Sprintf("%d unresolved libraries:", len(s.fullNotes))) + "\n")
		shown := s.fullNotes
		if len(shown) > 4 {
			shown = shown[:4]
		}
		for _, n := range shown {
			sb.WriteString(" " + ctx.ShadowStyle.Render(layout.FitANSIWidth(n, rowW)) + "\n")
		}
		if len(s.fullNotes) > 4 {
			sb.WriteString(" " + ctx.ShadowStyle.Render(fmt.Sprintf("  … and %d more", len(s.fullNotes)-4)) + "\n")
		}
	}

	sb.WriteString("\n")
	footer := fmt.Sprintf("↑/↓ select · ↵ jump · t scope · s/r sort · / filter · Esc close   (%d/%d)",
		min(s.sel+1, len(rows)), len(rows))
	if s.filtering {
		footer = fmt.Sprintf("type to filter · ↵ jump · Tab done · Esc clear   (%d/%d)",
			min(s.sel+1, len(rows)), len(rows))
	}
	sb.WriteString(ctx.Hint(layout.FitANSIWidth(footer, rowW)))
	return ctx.Frame(sb.String())
}
