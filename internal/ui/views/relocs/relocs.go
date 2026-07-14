// Package relocs implements the Relocations view: a filterable table of the
// binary's relocations — the GOT/PLT slots and base fixups the loader patches.
// Enter jumps to the patched address in the Hex view. The view is the pilot for
// the view.Context design: all its logic hangs off State and depends only on a
// view.Context (render inputs) and a view.Host (actions), never on the UI
// model — so it is testable in isolation.
package relocs

import (
	"fmt"
	"sort"
	"strings"

	"charm.land/bubbles/v2/textinput"
	"github.com/charmbracelet/x/ansi"

	"github.com/shellcell/exex/internal/binfile"
	"github.com/shellcell/exex/internal/ui/layout"
	"github.com/shellcell/exex/internal/ui/view"
)

// SortField is the relocation table's sort key.
type SortField uint8

const (
	SortOffset SortField = iota // file/index order, by patched address
	SortType
	SortSection
	SortSym
)

// String returns the sort's filter-status label.
func (s SortField) String() string {
	switch s {
	case SortType:
		return "type"
	case SortSection:
		return "section"
	case SortSym:
		return "symbol"
	}
	return "offset"
}

// State stores cursor, filter and cache state for the Relocations view.
type State struct {
	Cur      int             // cursor in the relocation table
	Top      int             // viewport top of the relocation table
	Filter   textinput.Model // symbol/type/section search (the `/` filter)
	Filtered []int           // indices into file.Relocations() after the filter
	Sort     SortField       // sort field for the relocation table
	SortDesc bool            // reverse the relocation sort

	typeOn   bool     // type-name facet filter active
	typeSel  string   // the relocation type it restricts to
	types    []string // distinct types, for cycling
	secOn    bool     // section facet filter active
	secSel   string   // the section it restricts to
	secs     []string // distinct sections, for cycling
	rowCache layout.RowMemo[view.RowCacheKey, string]

	Chips []view.StatusChip // clickable status-line toggles (screen-column spans)

	statusCache view.StatusCache // memoised status row (see view.StatusCache)
}

// DropCaches discards memoised rendered rows (e.g. after a theme change).
func (st *State) DropCaches() {
	st.rowCache = nil
}

// Recompute rebuilds Filtered from the active facet filters (type / section)
// and the text filter (matching symbol, type or section).
func (st *State) Recompute(ctx view.Context) {
	rels := ctx.File.Relocations()
	needle := strings.ToLower(st.Filter.Value())
	st.Filtered = st.Filtered[:0]
	for i := range rels {
		if st.typeOn && rels[i].Type != st.typeSel {
			continue
		}
		if st.secOn && rels[i].Section != st.secSel {
			continue
		}
		if needle == "" ||
			layout.ContainsFold(rels[i].Sym, needle) ||
			(rels[i].Sym != "" && ctx.SymNameDisplay != nil && layout.ContainsFold(ctx.SymNameDisplay(rels[i].Sym), needle)) ||
			layout.ContainsFold(rels[i].Type, needle) ||
			layout.ContainsFold(rels[i].Section, needle) {
			st.Filtered = append(st.Filtered, i)
		}
	}
	st.applySort(rels)
	if st.Cur >= len(st.Filtered) {
		st.Cur = max(0, len(st.Filtered)-1)
	}
}

// BuildFacets collects the distinct relocation types and section names, so the
// ctrl+t / ctrl+s facet filters can cycle through them. Built once per scan.
func (st *State) BuildFacets(ctx view.Context) {
	rels := ctx.File.Relocations()
	seenT, seenS := map[string]bool{}, map[string]bool{}
	st.types = st.types[:0]
	st.secs = st.secs[:0]
	for i := range rels {
		if t := rels[i].Type; t != "" && !seenT[t] {
			seenT[t] = true
			st.types = append(st.types, t)
		}
		if s := rels[i].Section; s != "" && !seenS[s] {
			seenS[s] = true
			st.secs = append(st.secs, s)
		}
	}
	sort.Strings(st.types)
	sort.Strings(st.secs)
}

// applySort orders Filtered by the active field. Offset order is the table's
// natural order, so it only needs reversing for descending.
func (st *State) applySort(rels []binfile.Reloc) {
	if st.Sort == SortOffset {
		sort.SliceStable(st.Filtered, func(a, b int) bool {
			less := rels[st.Filtered[a]].Offset < rels[st.Filtered[b]].Offset
			if st.SortDesc {
				return !less
			}
			return less
		})
		return
	}
	key := func(r binfile.Reloc) string {
		switch st.Sort {
		case SortType:
			return r.Type
		case SortSection:
			return r.Section
		default: // SortSym
			return r.Sym
		}
	}
	sort.SliceStable(st.Filtered, func(a, b int) bool {
		ra, rb := rels[st.Filtered[a]], rels[st.Filtered[b]]
		ka, kb := key(ra), key(rb)
		less := ka < kb
		if ka == kb { // tie-break by patched address so equal keys read in order
			less = ra.Offset < rb.Offset
		}
		if st.SortDesc {
			return !less
		}
		return less
	})
}

// Update handles keys while the Relocations view is active. A focused filter
// input is captured centrally by the host, so by the time a key reaches here it
// is navigation or an action.
func (st *State) Update(ctx view.Context, host view.Host, key string) {
	if layout.NavKey(&st.Cur, len(st.Filtered), host.ListPage(), key) {
		return
	}
	switch key {
	case "s":
		st.Sort = (st.Sort + 1) % 4
		st.Cur, st.Top = 0, 0
		st.Recompute(ctx)
		host.SetStatus("sort: "+st.Sort.String(), false)
	case "r":
		st.SortDesc = !st.SortDesc
		st.Cur, st.Top = 0, 0
		st.Recompute(ctx)
		dir := "ascending"
		if st.SortDesc {
			dir = "descending"
		}
		host.SetStatus("sort order: "+dir, false)
	case "ctrl+t":
		layout.CycleStringList(&st.typeOn, &st.typeSel, st.types)
		st.Cur, st.Top = 0, 0
		st.Recompute(ctx)
		if st.typeOn {
			host.SetStatus("reloc type filter: "+st.typeSel, false)
		} else {
			host.SetStatus("reloc type filter: all", false)
		}
	case "ctrl+s":
		layout.CycleStringList(&st.secOn, &st.secSel, st.secs)
		st.Cur, st.Top = 0, 0
		st.Recompute(ctx)
		if st.secOn {
			host.SetStatus("reloc section filter: "+st.secSel, false)
		} else {
			host.SetStatus("reloc section filter: all", false)
		}
	case "/":
		st.Filter.Focus()
	case "esc":
		dirty := st.Filter.Value() != "" || st.Filter.Focused() || st.typeOn || st.secOn
		if dirty {
			st.Filter.SetValue("")
			st.Filter.Blur()
			st.typeOn, st.secOn = false, false
			st.Cur, st.Top = 0, 0
			st.Recompute(ctx)
			host.SetStatus("filters cleared", false)
		}
	case "w":
		host.ToggleWrap()
	case "enter", "h":
		if r, ok := st.current(ctx); ok && r.Offset != 0 {
			host.JumpHexAtAddr(r.Offset)
		}
	case "d": // disassemble at the patched address (falls back to hex if it's data)
		if r, ok := st.current(ctx); ok && r.Offset != 0 {
			host.JumpDisasmAtAddr(r.Offset)
		}
	case "m": // raw bytes at the patched address
		if r, ok := st.current(ctx); ok && r.Offset != 0 {
			host.JumpRawAtAddr(r.Offset)
		}
	case "S":
		if r, ok := st.current(ctx); ok && r.Sym != "" {
			host.CopyToClipboard(r.Sym, "symbol")
		}
	case "A":
		if r, ok := st.current(ctx); ok {
			host.CopyToClipboard(fmt.Sprintf("0x%0*x", ctx.File.AddrHexWidth(), r.Offset), "address")
		}
	}
}

// ClickHeader handles a click on the table's sortable header row.
func (st *State) ClickHeader(ctx view.Context, host view.Host, x int) bool {
	sort, ok := layout.HitSortableHeader(st.headerCols(ctx), x)
	if !ok {
		return false
	}
	fieldChanged := layout.ApplySortHeaderClick(&st.Sort, &st.SortDesc, sort)
	st.Cur, st.Top = 0, 0
	st.Recompute(ctx)
	if fieldChanged {
		host.SetStatus("sort: "+st.Sort.String(), false)
	} else {
		host.SetStatus("sort order: "+layout.SortDirectionLabel(st.SortDesc), false)
	}
	return true
}

// headerCols maps the relocation table's header columns to their x ranges,
// matching the layout in Render / rowText.
func (st *State) headerCols(ctx view.Context) []layout.SortableHeaderCol[SortField] {
	addrW := ctx.File.AddrHexWidth()
	offCol := 2 + addrW
	typeStart := 1 + offCol + 2
	secStart := typeStart + 24 + 1
	symStart := secStart + 12 + 1
	return []layout.SortableHeaderCol[SortField]{
		{Start: 1, End: 1 + offCol, Sort: SortOffset},
		{Start: typeStart, End: typeStart + 24, Sort: SortType},
		{Start: secStart, End: secStart + 12, Sort: SortSection},
		{Start: symStart, End: ctx.Width, Sort: SortSym},
	}
}

// current returns the relocation under the cursor, through the filter.
func (st *State) current(ctx view.Context) (binfile.Reloc, bool) {
	if st.Cur < 0 || st.Cur >= len(st.Filtered) {
		return binfile.Reloc{}, false
	}
	return ctx.File.Relocations()[st.Filtered[st.Cur]], true
}

// CaretAddr returns the patched address of the relocation under the cursor, for
// the shell's cross-view "open caret in…" jump.
func (st *State) CaretAddr(ctx view.Context) (uint64, bool) {
	if r, ok := st.current(ctx); ok && r.Offset != 0 {
		return r.Offset, true
	}
	return 0, false
}

// SelectByAddr moves the cursor to the first relocation patching addr (the
// shell's "open caret in Relocs" jump), clearing filters that would hide it.
// Reports whether one was found.
func (st *State) SelectByAddr(ctx view.Context, addr uint64) bool {
	st.Filter.SetValue("")
	st.typeOn, st.secOn = false, false
	st.Recompute(ctx)
	rels := ctx.File.Relocations()
	for i, ri := range st.Filtered {
		if rels[ri].Offset == addr {
			st.Cur, st.Top = i, 0
			return true
		}
	}
	return false
}

// Render draws the view body.
func (st *State) Render(ctx view.Context, host view.Host) string {
	bodyH := ctx.BodyH
	if bodyH < 3 {
		bodyH = 3
	}
	// Filtered is (re)built on entry and on every filter/sort/facet change —
	// not here, so a reloc-heavy object isn't re-filtered and re-sorted per frame.
	rels := ctx.File.Relocations()
	// No relocations at all → a clean centred message with no table chrome.
	if len(rels) == 0 {
		return ctx.EmptyBody(emptyHint(ctx.File.Format))
	}
	addrW := ctx.File.AddrHexWidth()

	var filterRow string
	st.Chips = st.Chips[:0]
	if st.Filter.Focused() {
		filterRow = st.Filter.View()
	} else {
		tf, sf := "all", "all"
		if st.typeOn {
			tf = st.typeSel
		}
		if st.secOn {
			sf = st.secSel
		}
		filterRow, st.Chips = ctx.StatusLine(&st.statusCache, st.Filter.Value(), "relocations", len(st.Filtered), len(rels), []view.StatusItem{
			{Key: "s", Label: "sort", Value: view.SortValue(st.Sort.String(), st.SortDesc)},
			{Key: "ctrl+t", Label: "type", Value: tf},
			{Key: "ctrl+s", Label: "section", Value: sf},
		})
	}
	desc := st.SortDesc
	header := ctx.TableHeader(fmt.Sprintf(" %-*s  %-24s %-12s %s",
		addrW+2, layout.SortHeaderLabel("Offset", addrW+2, SortOffset, st.Sort, desc),
		layout.SortHeaderLabel("Type", 24, SortType, st.Sort, desc),
		layout.SortHeaderLabel("Section", 12, SortSection, st.Sort, desc),
		layout.SortHeaderLabel("Symbol / Addend", 16, SortSym, st.Sort, desc)))

	visible := bodyH - 2
	if visible < 1 {
		visible = 1
	}
	top := ctx.VisualTop(st.Cur, st.Top, len(st.Filtered), visible, func(int) int { return 1 })
	st.Top = top
	host.SetPageRows(layout.PageStep(top, len(st.Filtered), visible, func(int) int { return 1 }))

	if len(st.Filtered) == 0 {
		// rels > 0 here, so this is always a filter with no matches — keep the
		// filter row + header so the user sees what's narrowing it.
		return ctx.EmptyList("no matching relocations  ·  Esc clears filters", filterRow, header)
	}
	rows := []string{filterRow, header}
	for i := top; i < len(st.Filtered); i++ {
		line := st.row(ctx, st.Filtered[i], addrW)
		if i == st.Cur {
			line = ctx.SelStyle.Render(ansi.Strip(line))
		}
		if !layout.AppendRenderedRowsIndented(&rows, line, ctx.Width, ctx.Wrap, 6, bodyH) {
			break
		}
	}
	return layout.PadBodyRows(rows, ctx.Width, bodyH)
}

// row renders one relocation row, memoised by the layout inputs.
func (st *State) row(ctx view.Context, ri, addrW int) string {
	return st.rowCache.Get(view.RowCacheKey{I: ri, Width: ctx.Width, AddrW: addrW, Wrap: ctx.Wrap}, func() string {
		return st.rowText(ctx, ri, addrW)
	})
}

func (st *State) rowText(ctx view.Context, ri, addrW int) string {
	r := ctx.File.Relocations()[ri]
	target := r.Sym
	if target != "" && ctx.SymNameDisplay != nil {
		target = ctx.SymNameDisplay(target)
	}
	if r.HasAddend {
		add := fmt.Sprintf("0x%x", uint64(r.Addend))
		if target != "" {
			target += " + " + add
		} else {
			target = add
		}
	}
	typ := r.Type
	sec := r.Section
	if !ctx.Wrap {
		typ = layout.TruncateMiddle(typ, 24)
		sec = layout.TruncateMiddle(sec, 12)
		target = layout.TruncateMiddle(target, max(8, ctx.Width-addrW-2-24-12-8))
	}
	return fmt.Sprintf(" %s  %s %s %s",
		ctx.AddrStyle.Render(fmt.Sprintf("0x%0*x", addrW, r.Offset)),
		ctx.RowStyle.Render(layout.PadVisual(typ, 24)),
		ctx.ShadowStyle.Render(layout.PadVisual(sec, 12)),
		ctx.SymStyle.Render(target))
}

// emptyHint explains why a binary has no relocation table to show.
func emptyHint(f binfile.Format) string {
	switch f {
	case binfile.FormatMachO:
		return "No relocations — this Mach-O has no dyld bind/rebase, chained fixups, or per-section relocations."
	case binfile.FormatPE:
		return "No relocations — this PE has no base-relocation directory (it loads at a fixed address)."
	}
	return "No relocations — this binary is fully resolved (statically linked, or no dynamic fixups)."
}

// ClickStatus toggles the status-line chip at screen column x, by handing its
// key to Update — a click is that key arriving by mouse. Reports whether a chip
// was hit.
func (st *State) ClickStatus(ctx view.Context, host view.Host, x int) bool {
	key, ok := view.ChipAt(st.Chips, x)
	if !ok {
		return false
	}
	st.Update(ctx, host, key)
	return true
}
