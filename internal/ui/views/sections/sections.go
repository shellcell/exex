// Package sections implements the Sections view: a filterable table of the
// binary's sections. Enter routes a section to the most useful view (disasm for
// code, hex for other mapped sections, raw for unmapped ones). The `t` key
// toggles to the coarser segment (memory-region) table, which sections live
// inside. Like relocs, the view depends only on a view.Context (render inputs)
// and a view.Host (actions), never on the UI model.
package sections

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

// SortField is the display order of the (filtered) section/segment list.
type SortField uint8

const (
	SortIndex SortField = iota // file order (the natural section index)
	SortName
	SortAddr
	SortSize
)

// String returns the sort's filter-status label.
func (s SortField) String() string {
	switch s {
	case SortName:
		return "name"
	case SortAddr:
		return "address"
	case SortSize:
		return "size"
	}
	return "index"
}

// State stores list/filter state for the Sections view, which toggles between
// the section table and the coarser segment (memory-region) table.
type State struct {
	Sections     []binfile.Section
	Segments     []binfile.Segment
	ShowSegments bool            // the `t` toggle: list segments instead of sections
	Filter       textinput.Model // name search (the `/` filter)
	Filtered     []int           // indices into the active slice (sections or segments)
	Cur          int
	Top          int
	RenderedTop  int               // Top as of the last render, for mouse hit-testing
	Chips        []view.StatusChip // clickable status-line toggles (screen-column spans)
	Sort         SortField         // sort field for the (filtered) list
	SortDesc     bool              // reverse the active sort

	TypeOn    bool     // type-name column filter active
	TypeSel   string   // the type name it restricts to
	Types     []string // distinct type names, for cycling
	FlagsOn   bool     // flags column filter active
	FlagsSel  string   // the flag string it restricts to
	FlagsList []string // distinct flag strings, for cycling

	rowCache    layout.RowMemo[view.RowCacheKey, string]
	heightCache layout.RowMemo[view.RowCacheKey, int]

	statusCache view.StatusCache // memoised status row (see view.StatusCache)
}

// DropCaches drops cached section rows and heights.
func (st *State) DropCaches() {
	st.rowCache = nil
	st.heightCache = nil
}

// sortValue returns the name/addr/size of the active table's row idx, for the
// sort comparators (works for both the section and segment tables).
func (st *State) sortValue(idx int) (name string, addr, size uint64) {
	if st.ShowSegments {
		s := st.Segments[idx]
		return s.Name, s.Addr, s.Size
	}
	s := st.Sections[idx]
	return s.Name, s.Addr, s.Size
}

// applySort orders Filtered by the active field. Index order is the slice's
// natural order, so it only needs reversing for descending.
func (st *State) applySort() {
	desc := st.SortDesc
	if st.Sort == SortIndex {
		if desc {
			layout.ReverseInts(st.Filtered)
		}
		return
	}
	sort.SliceStable(st.Filtered, func(a, b int) bool {
		na, aa, sa := st.sortValue(st.Filtered[a])
		nb, ab, sb := st.sortValue(st.Filtered[b])
		var less bool
		switch st.Sort {
		case SortName:
			less = na < nb
		case SortAddr:
			less = aa < ab
		case SortSize:
			less = sa < sb
		}
		if desc {
			return !less
		}
		return less
	})
}

// BuildFacets collects the distinct type names and flag strings of the section
// table, so the ctrl+t / ctrl+f filters can cycle through them.
func (st *State) BuildFacets() {
	seenT, seenF := map[string]bool{}, map[string]bool{}
	st.Types = st.Types[:0]
	st.FlagsList = st.FlagsList[:0]
	for i := range st.Sections {
		if t := st.Sections[i].TypeName; t != "" && !seenT[t] {
			seenT[t] = true
			st.Types = append(st.Types, t)
		}
		if fl := st.Sections[i].Flags; fl != "" && !seenF[fl] {
			seenF[fl] = true
			st.FlagsList = append(st.FlagsList, fl)
		}
	}
	sort.Strings(st.Types)
	sort.Strings(st.FlagsList)
}

// Recompute rebuilds Filtered from the current filter text, matching on the
// name of the active table (sections or segments).
func (st *State) Recompute() {
	st.DropCaches()
	needle := strings.ToLower(st.Filter.Value())
	st.Filtered = st.Filtered[:0]
	names := len(st.Sections)
	if st.ShowSegments {
		names = len(st.Segments)
	}
	for i := 0; i < names; i++ {
		var name string
		if st.ShowSegments {
			name = st.Segments[i].Name
		} else {
			name = st.Sections[i].Name
			// The type/flags filters only apply to the section table.
			if st.TypeOn && st.Sections[i].TypeName != st.TypeSel {
				continue
			}
			if st.FlagsOn && st.Sections[i].Flags != st.FlagsSel {
				continue
			}
		}
		if needle == "" || layout.ContainsFold(name, needle) {
			st.Filtered = append(st.Filtered, i)
		}
	}
	st.applySort()
	if st.Cur >= len(st.Filtered) {
		st.Cur = max(0, len(st.Filtered)-1)
	}
}

// CycleMode advances the `t` toggle between the section and segment tables,
// skipping segments when the binary has none (e.g. PE). It returns a status
// label for the new mode.
func (st *State) CycleMode() string {
	if st.ShowSegments {
		st.ShowSegments = false
	} else if len(st.Segments) > 0 {
		st.ShowSegments = true
	}
	st.Cur, st.Top = 0, 0
	st.Filter.SetValue("")
	st.Recompute()
	if st.ShowSegments {
		return "showing segments (t for sections)"
	}
	return "showing sections (t for segments)"
}

// Update handles keys while the Sections view is active. A focused filter input
// is captured centrally by the host, so by the time a key reaches here it is
// navigation or an action.
func (st *State) Update(ctx view.Context, host view.Host, key string) {
	if layout.NavKey(&st.Cur, len(st.Filtered), host.ListPage(), key) {
		return
	}
	switch key {
	case "/":
		st.Filter.Focus()
	case "esc":
		dirty := st.TypeOn || st.FlagsOn || st.Filter.Value() != "" || st.Filter.Focused()
		st.Filter.SetValue("")
		st.Filter.Blur()
		st.TypeOn = false
		st.FlagsOn = false
		st.Cur, st.Top = 0, 0
		st.Recompute()
		if dirty {
			host.SetStatus("filters cleared", false)
		}
	case "ctrl+t":
		if st.ShowSegments {
			return
		}
		layout.CycleStringList(&st.TypeOn, &st.TypeSel, st.Types)
		st.Cur, st.Top = 0, 0
		st.Recompute()
		if st.TypeOn {
			host.SetStatus("section type filter: "+st.TypeSel, false)
		} else {
			host.SetStatus("section type filter: all", false)
		}
	case "ctrl+f":
		if st.ShowSegments {
			return
		}
		layout.CycleStringList(&st.FlagsOn, &st.FlagsSel, st.FlagsList)
		st.Cur, st.Top = 0, 0
		st.Recompute()
		if st.FlagsOn {
			host.SetStatus("section flags filter: "+st.FlagsSel, false)
		} else {
			host.SetStatus("section flags filter: all", false)
		}
	case "t":
		host.SetStatus(st.CycleMode(), false)
	case "enter":
		if st.ShowSegments {
			if seg, ok := st.currentSegment(); ok {
				if seg.Addr != 0 {
					host.OpenHexAt(seg.Addr)
				} else {
					host.OpenRawAt(seg.Offset)
				}
			}
			return
		}
		sec, ok := st.currentSection()
		if !ok {
			return
		}
		if sec.Alloc && sec.Addr != 0 {
			host.OpenHexAt(sec.Addr)
		} else {
			host.OpenRawAt(sec.Offset)
		}
	case "d":
		// JumpDisasmAtAddr falls back to disasm-all when the target isn't in an
		// executable section (e.g. a multiboot/boot section), so kernel code that
		// isn't flagged executable can still be disassembled.
		if st.ShowSegments {
			if seg, ok := st.currentSegment(); ok && seg.Addr != 0 {
				host.JumpDisasmAtAddr(seg.Addr)
			} else {
				host.SetStatus("segment has no address to disassemble", true)
			}
			return
		}
		if sec, ok := st.currentSection(); ok {
			host.JumpDisasmAtAddr(sec.Addr)
		}
	case "h":
		if addr, ok := st.CurrentAddr(); ok {
			host.JumpHexAtAddr(addr)
		}
	case "m":
		// Raw is file-offset based, so jump by the section/segment's file offset
		// directly — non-allocated sections (.symtab, .strtab, …) have no virtual
		// address but do have file bytes, so an address-based jump would fail.
		if st.ShowSegments {
			if seg, ok := st.currentSegment(); ok {
				if seg.FileSize > 0 {
					host.OpenRawAt(seg.Offset)
				} else {
					host.SetStatus("segment has no file bytes", true)
				}
			}
			return
		}
		if sec, ok := st.currentSection(); ok {
			if sec.FileSize > 0 {
				host.OpenRawAt(sec.Offset)
			} else {
				host.SetStatus("section has no file bytes (e.g. .bss)", true)
			}
		}
	case "s":
		st.Sort = (st.Sort + 1) % 4
		st.Cur, st.Top = 0, 0
		st.Recompute()
		host.SetStatus("sort: "+st.Sort.String(), false)
	case "r":
		st.SortDesc = !st.SortDesc
		st.Cur, st.Top = 0, 0
		st.Recompute()
		dir := "ascending"
		if st.SortDesc {
			dir = "descending"
		}
		host.SetStatus("sort order: "+dir, false)
	case "w":
		host.ToggleWrap()
	case "A":
		if st.ShowSegments {
			if seg, ok := st.currentSegment(); ok {
				host.CopyToClipboard(fmt.Sprintf("0x%0*x", ctx.File.AddrHexWidth(), seg.Addr), "address")
			}
			return
		}
		if sec, ok := st.currentSection(); ok {
			host.CopyToClipboard(fmt.Sprintf("0x%0*x", ctx.File.AddrHexWidth(), sec.Addr), "address")
		}
	case "S":
		if st.ShowSegments {
			if seg, ok := st.currentSegment(); ok {
				host.CopyToClipboard(seg.Name, "segment name")
			}
			return
		}
		if sec, ok := st.currentSection(); ok {
			host.CopyToClipboard(sec.Name, "section name")
		}
	}
}

// ClickHeader handles a click on the table's sortable header row.
func (st *State) ClickHeader(ctx view.Context, host view.Host, x int) bool {
	addrW := ctx.File.AddrHexWidth()
	phys := st.havePhys()
	if st.ShowSegments {
		phys = st.segmentsHavePhys()
	}
	sort, ok := layout.HitSortableHeader(st.headerCols(ctx.Width, addrW, phys), x)
	if !ok {
		return false
	}
	fieldChanged := layout.ApplySortHeaderClick(&st.Sort, &st.SortDesc, sort)
	st.Cur, st.Top = 0, 0
	st.Recompute()
	if fieldChanged {
		host.SetStatus("sort: "+st.Sort.String(), false)
	} else {
		host.SetStatus("sort order: "+layout.SortDirectionLabel(st.SortDesc), false)
	}
	return true
}

// headerCols maps the table's header columns to their x ranges, matching the
// layout in Render / RowText.
func (st *State) headerCols(width, addrW int, phys bool) []layout.SortableHeaderCol[SortField] {
	addrCol := 2 + addrW
	nameStart, nameW, typeW := 6, 22, 14
	if st.ShowSegments {
		nameW, typeW = 16, 5
	}
	addrStart := nameStart + nameW + 1 + typeW + 1
	sizeStart := addrStart + addrCol + 1
	if phys {
		sizeStart += addrCol + 1
	}
	return []layout.SortableHeaderCol[SortField]{
		{Start: 1, End: 4, Sort: SortIndex},
		{Start: nameStart, End: nameStart + nameW, Sort: SortName},
		{Start: addrStart, End: addrStart + addrCol, Sort: SortAddr},
		{Start: sizeStart, End: sizeStart + 12, Sort: SortSize},
	}
}

// CurrentAddr returns the virtual address of the selected row (section or
// segment), for the h/m cross-view jumps.
func (st *State) CurrentAddr() (uint64, bool) {
	if st.ShowSegments {
		if seg, ok := st.currentSegment(); ok {
			return seg.Addr, true
		}
		return 0, false
	}
	if sec, ok := st.currentSection(); ok {
		return sec.Addr, true
	}
	return 0, false
}

// currentSection returns the selected section through the active filter.
func (st *State) currentSection() (binfile.Section, bool) {
	if st.ShowSegments || st.Cur < 0 || st.Cur >= len(st.Filtered) {
		return binfile.Section{}, false
	}
	return st.Sections[st.Filtered[st.Cur]], true
}

// currentSegment returns the selected segment through the active filter.
func (st *State) currentSegment() (binfile.Segment, bool) {
	if !st.ShowSegments || st.Cur < 0 || st.Cur >= len(st.Filtered) {
		return binfile.Segment{}, false
	}
	return st.Segments[st.Filtered[st.Cur]], true
}

// CaretAddr returns the base address of the section/segment under the cursor,
// for the shell's cross-view "open caret in…" jump.
func (st *State) CaretAddr() (uint64, bool) {
	if st.ShowSegments {
		if s, ok := st.currentSegment(); ok {
			return s.Addr, true
		}
		return 0, false
	}
	if s, ok := st.currentSection(); ok {
		return s.Addr, true
	}
	return 0, false
}

// SelectByAddr moves the cursor to the section/segment whose address range covers
// addr (the shell's "open caret in Sections" jump), clearing filters that would
// hide it. Reports whether one was found.
func (st *State) SelectByAddr(addr uint64) bool {
	st.Filter.SetValue("")
	st.TypeOn, st.FlagsOn = false, false
	st.Recompute()
	covers := func(base, size uint64) bool {
		if size == 0 {
			return base == addr
		}
		return addr >= base && addr < base+size
	}
	for i, idx := range st.Filtered {
		var base, size uint64
		if st.ShowSegments {
			base, size = st.Segments[idx].Addr, st.Segments[idx].Size
		} else {
			base, size = st.Sections[idx].Addr, st.Sections[idx].Size
		}
		if covers(base, size) {
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
	total := len(st.Sections)
	kind := "sections"
	if st.ShowSegments {
		total = len(st.Segments)
		kind = "segments"
	}
	filterRow := st.Filter.View()
	st.Chips = st.Chips[:0]
	if !st.Filter.Focused() {
		items := []view.StatusItem{
			{Key: "t", Label: "view", Value: kind},
			{Key: "s", Label: "sort", Value: view.SortValue(st.Sort.String(), st.SortDesc)},
		}
		// Segments have no type/flags facets to filter on.
		if !st.ShowSegments {
			tf, ff := "all", "all"
			if st.TypeOn {
				tf = st.TypeSel
			}
			if st.FlagsOn {
				ff = st.FlagsSel
			}
			items = append(items,
				view.StatusItem{Key: "ctrl+t", Label: "type", Value: tf},
				view.StatusItem{Key: "ctrl+f", Label: "flags", Value: ff},
			)
		}
		filterRow, st.Chips = ctx.StatusLine(&st.statusCache, st.Filter.Value(), kind, len(st.Filtered), total, items)
	}

	addrW := ctx.File.AddrHexWidth()
	addrCol := 2 + addrW
	phys := st.havePhys()
	if st.ShowSegments {
		phys = st.segmentsHavePhys()
	}
	var hdr string
	idxLabel := layout.SortHeaderLabel("#", 3, SortIndex, st.Sort, st.SortDesc)
	nameTitle := "Name"
	if st.ShowSegments {
		nameTitle = "Type"
	}
	nameW := 22
	if st.ShowSegments {
		nameW = 16
	}
	nameLabel := layout.SortHeaderLabel(nameTitle, nameW, SortName, st.Sort, st.SortDesc)
	addrLabel := layout.SortHeaderLabel("Addr", addrCol, SortAddr, st.Sort, st.SortDesc)
	sizeTitle := "Size"
	if st.ShowSegments {
		sizeTitle = "MemSize"
	}
	sizeLabel := layout.SortHeaderLabel(sizeTitle, 12, SortSize, st.Sort, st.SortDesc)
	switch {
	case st.ShowSegments && phys:
		hdr = fmt.Sprintf(" %3s  %-16s %-5s %-*s %-*s %-12s %-12s  %s",
			idxLabel, nameLabel, "Perms", addrCol, addrLabel, addrCol, "LMA", sizeLabel, "FileSize", "Align")
	case st.ShowSegments:
		hdr = fmt.Sprintf(" %3s  %-16s %-5s %-*s %-12s %-12s  %s",
			idxLabel, nameLabel, "Perms", addrCol, addrLabel, sizeLabel, "FileSize", "Align")
	case phys:
		hdr = fmt.Sprintf(" %3s  %-22s %-14s %-*s %-*s %-12s  %s",
			idxLabel, nameLabel, "Type", addrCol, addrLabel, addrCol, "LMA", sizeLabel, "Flags")
	default:
		hdr = fmt.Sprintf(" %3s  %-22s %-14s %-*s %-12s  %s",
			idxLabel, nameLabel, "Type", addrCol, addrLabel, sizeLabel, "Flags")
	}
	header := ctx.TableHeader(hdr)

	visible := bodyH - 2 // filter row + header
	if visible < 1 {
		visible = 1
	}
	rowHeight := st.RowHeightFn(ctx)
	top := ctx.VisualTop(st.Cur, st.Top, len(st.Filtered), visible, rowHeight)
	host.SetPageRows(layout.PageStep(top, len(st.Filtered), visible, rowHeight))
	st.Top = top
	st.RenderedTop = top

	if len(st.Filtered) == 0 {
		msg := "no entries"
		if st.Filter.Value() != "" || st.TypeOn || st.FlagsOn {
			msg = "no matching entries  ·  Esc clears filters"
		}
		return ctx.EmptyList(msg, filterRow, header)
	}
	rows := []string{filterRow, header}
	for i := top; i < len(st.Filtered); i++ {
		line := st.row(ctx, i, addrW)
		if i == st.Cur {
			line = ctx.SelStyle.Render(ansi.Strip(line))
		}
		if !layout.AppendRenderedRowsIndented(&rows, line, ctx.Width, ctx.Wrap, 6, bodyH) {
			break
		}
	}
	return layout.PadBodyRows(rows, ctx.Width, bodyH)
}

// RowHeightFn returns the per-row rendered height, for the scroll geometry.
func (st *State) RowHeightFn(ctx view.Context) func(int) int {
	return func(i int) int {
		if i < 0 || i >= len(st.Filtered) {
			return 1
		}
		addrW := ctx.File.AddrHexWidth()
		return st.heightCache.Get(view.RowCacheKey{I: i, Width: ctx.Width, AddrW: addrW, Wrap: ctx.Wrap}, func() int {
			return len(layout.RenderLineRowsIndented(st.row(ctx, i, addrW), ctx.Width, ctx.Wrap, 6))
		})
	}
}

// RowText returns the current row's rendered text, for the copy-line action.
func (st *State) RowText(ctx view.Context) string {
	if st.Cur < 0 || st.Cur >= len(st.Filtered) {
		return ""
	}
	return st.row(ctx, st.Cur, ctx.File.AddrHexWidth())
}

// row renders one section/segment row, memoised by the layout inputs.
func (st *State) row(ctx view.Context, i, addrW int) string {
	return st.rowCache.Get(view.RowCacheKey{I: i, Width: ctx.Width, AddrW: addrW, Wrap: ctx.Wrap}, func() string {
		if st.ShowSegments {
			return st.segmentRow(ctx, i, addrW)
		}
		return st.sectionRowText(ctx, i, addrW)
	})
}

// havePhys / segmentsHavePhys report whether any row carries a distinct
// load/physical address, so the views add an LMA / PAddr column only then.
func (st *State) havePhys() bool {
	for i := range st.Sections {
		if st.Sections[i].PhysAddr != 0 {
			return true
		}
	}
	return false
}

func (st *State) segmentsHavePhys() bool {
	for i := range st.Segments {
		if st.Segments[i].PhysAddr != 0 {
			return true
		}
	}
	return false
}

// physCell renders a load/physical address column, or a dim "-" when unset.
func physCell(ctx view.Context, phys uint64, addrW int) string {
	if phys == 0 {
		return ctx.ShadowStyle.Render(layout.PadVisual("-", 2+addrW))
	}
	return ctx.AddrStyle.Render(fmt.Sprintf("0x%0*x", addrW, phys))
}

func (st *State) sectionRowText(ctx view.Context, i, addrW int) string {
	idx := st.Filtered[i]
	s := st.Sections[idx]
	name := s.Name
	typeName := s.TypeName
	if !ctx.Wrap {
		name = layout.TruncateMiddle(name, 22)
		typeName = layout.TruncateMiddle(typeName, 14)
	}
	rowStyle := ctx.SectionStyle(&s)
	lma := ""
	if st.havePhys() {
		lma = " " + physCell(ctx, s.PhysAddr, addrW)
	}
	return fmt.Sprintf(" %s  %s %s %s%s %s  %s",
		ctx.AddrStyle.Render(fmt.Sprintf("%3d", idx)),
		rowStyle.Render(layout.PadVisual(name, 22)),
		rowStyle.Render(layout.PadVisual(typeName, 14)),
		ctx.AddrStyle.Render(fmt.Sprintf("0x%0*x", addrW, s.Addr)),
		lma,
		rowStyle.Render(fmt.Sprintf("%-12d", s.Size)),
		rowStyle.Render(s.Flags))
}

// segmentRow renders one segment row, coloured by its permissions so segment
// colours read like the section table.
func (st *State) segmentRow(ctx view.Context, i, addrW int) string {
	idx := st.Filtered[i]
	s := st.Segments[idx]
	name := s.Name
	if !ctx.Wrap {
		name = layout.TruncateMiddle(name, 16)
	}
	rowStyle := ctx.SegmentStyle(s.X, s.W)
	align := "-"
	if s.Align > 0 {
		align = fmt.Sprintf("0x%x", s.Align)
	}
	paddr := ""
	if st.segmentsHavePhys() {
		paddr = " " + physCell(ctx, s.PhysAddr, addrW)
	}
	return fmt.Sprintf(" %s  %s %s %s%s %s %s  %s",
		ctx.AddrStyle.Render(fmt.Sprintf("%3d", idx)),
		rowStyle.Render(layout.PadVisual(name, 16)),
		rowStyle.Render(layout.PadVisual(s.Perms(), 5)),
		ctx.AddrStyle.Render(fmt.Sprintf("0x%0*x", addrW, s.Addr)),
		paddr,
		rowStyle.Render(fmt.Sprintf("%-12d", s.Size)),
		rowStyle.Render(fmt.Sprintf("%-12d", s.FileSize)),
		rowStyle.Render(align))
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
