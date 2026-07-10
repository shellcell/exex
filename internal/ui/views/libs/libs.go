// Package libs implements the dynamic-libraries view: the DT_NEEDED entries
// together with the linkage context (interpreter, libc kind, RPATH, RUNPATH),
// as a flat list or a collapsible path tree, with name filtering and an
// on-disk/in-cache availability lens. Enter jumps to the imported symbols of
// the selected library (via view.Host); opening a library as the primary file
// swaps the whole model, so that action stays in the shell. Like the other
// extracted views, it depends only on a view.Context and a view.Host.
package libs

import (
	"sort"
	"strings"

	"charm.land/bubbles/v2/textinput"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/rabarbra/exex/internal/explorer"
	"github.com/rabarbra/exex/internal/ui/layout"
	"github.com/rabarbra/exex/internal/ui/view"
)

// availKind classifies one library's on-disk availability.
type availKind uint8

const (
	libOnDisk  availKind = iota // resolves to a real file we can open
	libInCache                  // a system lib served from the dyld shared cache
	libMissing                  // neither — can't be located
)

// State stores cursor, filter and tree state for the Libraries view.
type State struct {
	Cur         int
	Top         int
	RenderedTop int  // Top as of the last render, for mouse hit-testing
	Tree        bool // show needed libraries as a path tree
	TreeInit    bool
	Rows        []layout.TreeRow // flattened visible rows (dirs + libs)
	Filter      textinput.Model  // name search (the `/` filter)
	SortDesc    bool             // reverse the (name) sort
	Avail       view.AvailFilter // availability filter: all / on-disk / in cache

	collapsed map[string]bool      // collapsed directory paths
	availKind map[string]availKind // cached (filesystem-touching) classifications
	built     bool
}

// libAvail classifies a library path, caching the (filesystem-touching) result.
func (st *State) libAvail(ctx view.Context, lib string) availKind {
	if st.availKind == nil {
		st.availKind = map[string]availKind{}
	}
	if k, ok := st.availKind[lib]; ok {
		return k
	}
	var k availKind
	switch {
	case func() bool { _, ok := explorer.ResolveLibPath(lib, ctx.File.Path, ctx.File.Info, nil); return ok }():
		k = libOnDisk
	case explorer.IsDyldSharedCacheLib(lib):
		k = libInCache
	default:
		k = libMissing
	}
	st.availKind[lib] = k
	return k
}

// CycleMode toggles between the flat list and the path tree.
func (st *State) CycleMode(ctx view.Context) string {
	st.Tree = !st.Tree
	st.Cur, st.Top = 0, 0
	st.BuildRows(ctx)
	if st.Tree {
		return "libs view: tree"
	}
	return "libs view: flat list"
}

// sortedIdxs returns the needed-library indices sorted alphabetically by path,
// so both the flat list and the (adjacency-based) tree read in order.
func (st *State) sortedIdxs(ctx view.Context) ([]int, []string) {
	var libs []string
	if ctx.File.Info != nil {
		libs = ctx.File.Info.DynamicLibs
	}
	needle := strings.ToLower(st.Filter.Value())
	idxs := make([]int, 0, len(libs))
	for i := range libs {
		switch st.Avail {
		case view.AvailPresent:
			if st.libAvail(ctx, libs[i]) != libOnDisk {
				continue
			}
		case view.AvailCache:
			if st.libAvail(ctx, libs[i]) != libInCache {
				continue
			}
		}
		if needle != "" && !layout.ContainsFold(libs[i], needle) {
			continue
		}
		idxs = append(idxs, i)
	}
	sort.Slice(idxs, func(a, b int) bool {
		if st.SortDesc {
			return libs[idxs[a]] > libs[idxs[b]]
		}
		return libs[idxs[a]] < libs[idxs[b]]
	})
	return idxs, libs
}

// BuildRows flattens the needed libraries into a path tree (tree mode) or one
// leaf row per library (flat mode).
func (st *State) BuildRows(ctx view.Context) {
	st.built = true
	idxs, libs := st.sortedIdxs(ctx)
	if st.Tree {
		roots := layout.BuildTree(idxs, func(i int) string { return libs[i] }, layout.SegPath)
		if !st.TreeInit {
			st.TreeInit = true
			if ctx.TreeCollapseDefault {
				st.collapsed = map[string]bool{}
				layout.EachInternal(roots, func(p string) { st.collapsed[p] = true })
			}
		}
		st.Rows = layout.FlattenTree(roots, st.collapsed, 0, st.Rows[:0])
		return
	}
	nodes := make([]layout.TreeNode, len(idxs))
	rows := st.Rows[:0]
	for k, idx := range idxs {
		nodes[k] = layout.TreeNode{Label: libs[idx], Leaf: idx, Count: 1}
		rows = append(rows, layout.TreeRow{Node: &nodes[k], Depth: 0})
	}
	st.Rows = rows
}

// LibAt returns the library string for a leaf row.
func (st *State) LibAt(ctx view.Context, rowIdx int) (string, bool) {
	if ctx.File.Info == nil || rowIdx < 0 || rowIdx >= len(st.Rows) {
		return "", false
	}
	n := st.Rows[rowIdx].Node
	if n.Leaf < 0 {
		return "", false
	}
	return ctx.File.Info.DynamicLibs[n.Leaf], true
}

// CurrentLib returns the library under the cursor when the row is a leaf.
func (st *State) CurrentLib(ctx view.Context) (string, bool) {
	return st.LibAt(ctx, st.Cur)
}

func (st *State) ensureCollapsed() {
	if st.collapsed == nil {
		st.collapsed = map[string]bool{}
	}
}

// ToggleNode collapses/expands the directory node at the current row (the
// mouse-click path; keyboard folding goes through Update).
func (st *State) ToggleNode(ctx view.Context) {
	if st.Cur < 0 || st.Cur >= len(st.Rows) || st.Rows[st.Cur].Node.Leaf >= 0 {
		return
	}
	st.ensureCollapsed()
	p := st.Rows[st.Cur].Node.Path
	st.collapsed[p] = !st.collapsed[p]
	st.BuildRows(ctx)
	st.clampCursor()
}

// SetAllCollapsed collapses or expands every directory node.
func (st *State) SetAllCollapsed(ctx view.Context, collapsed bool) {
	if !st.Tree || ctx.File.Info == nil {
		return
	}
	if !collapsed {
		st.collapsed = nil
	} else {
		st.collapsed = map[string]bool{}
		idxs, libs := st.sortedIdxs(ctx)
		roots := layout.BuildTree(idxs, func(i int) string { return libs[i] }, layout.SegPath)
		layout.EachInternal(roots, func(p string) { st.collapsed[p] = true })
	}
	st.BuildRows(ctx)
	st.clampCursor()
}

func (st *State) clampCursor() {
	if st.Cur >= len(st.Rows) {
		st.Cur = max(0, len(st.Rows)-1)
	}
}

// Update handles keys while the Libraries view is active. Opening a library as
// the primary file replaces the whole model, so the shell's adapter intercepts
// that key ("o") before delegating here.
func (st *State) Update(ctx view.Context, host view.Host, key string) {
	if ctx.File.Info == nil || len(ctx.File.Info.DynamicLibs) == 0 {
		return
	}
	if layout.NavKey(&st.Cur, len(st.Rows), host.ListPage(), key) {
		return
	}
	switch key {
	case "/":
		st.Filter.Focus()
	case "esc":
		dirty := st.Avail != view.AvailAll || st.Filter.Value() != "" || st.Filter.Focused()
		st.Filter.SetValue("")
		st.Filter.Blur()
		st.Avail = view.AvailAll
		st.Cur, st.Top = 0, 0
		st.BuildRows(ctx)
		if dirty {
			host.SetStatus("filters cleared", false)
		}
	case "s":
		// Libraries sort by name only; report the (single) field for consistency.
		host.SetStatus("sort: name", false)
	case "r":
		st.SortDesc = !st.SortDesc
		st.Cur, st.Top = 0, 0
		st.BuildRows(ctx)
		dir := "ascending"
		if st.SortDesc {
			dir = "descending"
		}
		host.SetStatus("sort order: "+dir, false)
	case "w":
		host.ToggleWrap()
	case "ctrl+p":
		// cycle availability filter: all → on-disk → in-cache → all
		switch st.Avail {
		case view.AvailAll:
			st.Avail = view.AvailPresent
		case view.AvailPresent:
			st.Avail = view.AvailCache
		default:
			st.Avail = view.AvailAll
		}
		st.Cur, st.Top = 0, 0
		st.BuildRows(ctx)
		host.SetStatus("libs: "+view.AvailLabel(st.Avail), false)
	case "t":
		host.SetStatus(st.CycleMode(ctx), false)
	case "-", "_":
		st.SetAllCollapsed(ctx, true)
		host.SetStatus("collapsed all", false)
	case "+", "=":
		st.SetAllCollapsed(ctx, false)
		host.SetStatus("expanded all", false)
	case "right":
		if st.Tree {
			st.ensureCollapsed()
			if layout.TreeExpandOne(st.Rows, &st.Cur, st.collapsed) {
				st.BuildRows(ctx)
			}
		}
	case "left":
		if st.Tree {
			st.ensureCollapsed()
			if layout.TreeCollapseOne(st.Rows, &st.Cur, st.collapsed) {
				st.BuildRows(ctx)
			}
		}
	case "S":
		if lib, ok := st.CurrentLib(ctx); ok {
			host.CopyToClipboard(lib, "library")
		}
	case "enter":
		if st.Cur < len(st.Rows) && st.Rows[st.Cur].Node.Leaf < 0 {
			st.ensureCollapsed()
			if layout.TreeToggleSubtree(st.Rows, st.Cur, st.collapsed) {
				st.BuildRows(ctx)
			}
		} else if lib, ok := st.CurrentLib(ctx); ok {
			host.OpenSymbolsForLib(lib)
		}
	}
}

// ClickHeader handles a click on the "Needed libraries" title (the only
// sortable column: name order, toggled between ascending and descending).
func (st *State) ClickHeader(ctx view.Context, host view.Host, x int) bool {
	if ctx.File.Info == nil || len(ctx.File.Info.DynamicLibs) == 0 {
		return false
	}
	if x < 1 || x >= 1+titleWidth() {
		return false
	}
	st.SortDesc = !st.SortDesc
	st.Cur, st.Top = 0, 0
	st.BuildRows(ctx)
	host.SetStatus("sort order: "+layout.SortDirectionLabel(st.SortDesc), false)
	return true
}

// Render draws the view body.
func (st *State) Render(ctx view.Context, host view.Host) string {
	bodyH := ctx.BodyH
	info := ctx.File.Info
	if info == nil || len(info.DynamicLibs) == 0 {
		body := "no dynamic libraries — this binary is statically linked or has no DT_NEEDED entries\n"
		if info != nil && info.StaticLinked {
			body += "\n" + ctx.LabelStyle.Render("Static-linked:") + " yes\n"
			if info.Libc.Kind != "" && info.Libc.Kind != "none" {
				body += ctx.LabelStyle.Render("Libc:") + " " + info.Libc.Kind
				if info.Libc.Version != "" {
					body += " " + info.Libc.Version
				}
				body += "\n"
			}
		}
		return lipgloss.Place(ctx.Width, bodyH, lipgloss.Center, lipgloss.Center, strings.TrimRight(body, "\n"))
	}

	if !st.built {
		st.BuildRows(ctx)
	}
	b := strings.Builder{}
	header := st.renderHeader(ctx)
	b.WriteString(header)
	headerH := renderedLineCount(header)
	visible := bodyH - headerH
	if visible < 1 {
		visible = 1
	}
	rowHeight := st.RowHeightFn(ctx)
	top := ctx.VisualTop(st.Cur, st.Top, len(st.Rows), visible, rowHeight)
	st.Top = top
	st.RenderedTop = top
	host.SetPageRows(layout.PageStep(top, len(st.Rows), visible, rowHeight))
	if len(st.Rows) == 0 {
		b.WriteString(ctx.PlaceCentred("no matching libraries  ·  Esc clears filters", bodyH-headerH))
		return layout.PadBody(b.String(), ctx.Width, bodyH)
	}
	rendered := headerH
renderRows:
	for i := top; i < len(st.Rows); i++ {
		line := st.row(ctx, i, i == st.Cur)
		for _, row := range layout.RenderLineRowsIndented(line, ctx.Width, ctx.Wrap, 6) {
			if rendered >= bodyH {
				break renderRows
			}
			b.WriteString(row)
			b.WriteString("\n")
			rendered++
		}
	}
	return layout.PadBody(b.String(), ctx.Width, bodyH)
}

func (st *State) renderHeader(ctx view.Context) string {
	info := ctx.File.Info
	var b strings.Builder
	if info.Interp != "" {
		b.WriteString(ctx.LabelStyle.Render("Interpreter: "))
		b.WriteString(info.Interp)
		b.WriteString("\n")
	}
	if info.Libc.Kind != "" {
		libcLine := info.Libc.Kind
		if info.Libc.Version != "" {
			libcLine += " " + info.Libc.Version
		}
		if info.Libc.Source != "" {
			libcLine += "  " + ctx.FooterStyle.Render("("+info.Libc.Source+")")
		}
		b.WriteString(ctx.LabelStyle.Render("Libc:        "))
		b.WriteString(libcLine)
		b.WriteString("\n")
	}
	if len(info.RPath) > 0 {
		b.WriteString(ctx.LabelStyle.Render("RPATH:       "))
		b.WriteString(strings.Join(info.RPath, ":"))
		b.WriteString("\n")
	}
	if len(info.RunPath) > 0 {
		b.WriteString(ctx.LabelStyle.Render("RUNPATH:     "))
		b.WriteString(strings.Join(info.RunPath, ":"))
		b.WriteString("\n")
	}
	b.WriteString("\n")
	if st.Filter.Focused() {
		b.WriteString(st.Filter.View())
		b.WriteString("\n")
	} else if st.Filter.Value() != "" {
		b.WriteString(ctx.FooterStyle.Render("/ " + st.Filter.Value()))
		b.WriteString("\n")
	}
	suffix := st.headerSuffix(ctx)
	hdr := " " + layout.ActiveSortHeaderLabel("Needed libraries", titleWidth(), st.SortDesc) + suffix
	b.WriteString(ctx.TableHeader(hdr))
	b.WriteString("\n")
	return b.String()
}

func (st *State) headerSuffix(ctx view.Context) string {
	suffix := ""
	if st.Avail != view.AvailAll {
		suffix += "  " + ctx.KeyStyle.Render(layout.CtrlKeys("p")) + ctx.FooterStyle.Render(" "+view.AvailLabel(st.Avail))
	}
	if st.Tree {
		suffix += "  " + ctx.FooterStyle.Render("(tree · ←/→ fold · ↵ all below · +/− all · t flat)")
	}
	return suffix
}

func titleWidth() int {
	return lipgloss.Width("Needed libraries") + 3
}

// HeaderRows is the rendered height of the header block above the list.
func (st *State) HeaderRows(ctx view.Context) int {
	if ctx.File.Info == nil || len(ctx.File.Info.DynamicLibs) == 0 {
		return 0
	}
	return renderedLineCount(st.renderHeader(ctx))
}

// TitleRow is the body row of the clickable "Needed libraries" title, or -1
// when the view has no list.
func (st *State) TitleRow(ctx view.Context) int {
	rows := st.HeaderRows(ctx)
	if rows == 0 {
		return -1
	}
	return rows - 1
}

func renderedLineCount(s string) int {
	if s == "" {
		return 0
	}
	return lipgloss.Height(strings.TrimSuffix(s, "\n"))
}

// RowHeightFn returns the per-row rendered height, for the scroll geometry.
func (st *State) RowHeightFn(ctx view.Context) func(int) int {
	return func(i int) int {
		if i < 0 || i >= len(st.Rows) {
			return 1
		}
		return len(layout.RenderLineRowsIndented(st.row(ctx, i, false), ctx.Width, ctx.Wrap, 6))
	}
}

// RowText returns the current row's rendered text, for the copy-line action.
func (st *State) RowText(ctx view.Context) string {
	if st.Cur < 0 || st.Cur >= len(st.Rows) {
		return ""
	}
	return st.row(ctx, st.Cur, false)
}

func (st *State) row(ctx view.Context, i int, selected bool) string {
	row := st.Rows[i]
	n := row.Node
	if n.Leaf < 0 {
		collapsed := st.collapsed != nil && st.collapsed[n.Path]
		return ctx.TreeNodeRow(row.Depth, n.Label, n.Count, collapsed, selected, " ")
	}
	indent := strings.Repeat(" ", row.Depth*layout.TreeIndent)
	lib := ctx.File.Info.DynamicLibs[n.Leaf]
	display := n.Label // basename in tree mode, full path in flat mode
	// Tag a library's provenance. Cache libraries are openable (extracted from
	// the dyld shared cache), so they keep their path colour; only libraries we
	// can't locate at all are dimmed.
	tag, dim := "", false
	switch st.libAvail(ctx, lib) {
	case libInCache:
		tag = "  ·cache"
	case libMissing:
		tag, dim = "  ·missing", true
	}
	if !ctx.Wrap {
		display = layout.TruncateMiddle(display, max(1, ctx.Width-len(indent)-2-len(tag)))
	}
	var line string
	if dim {
		line = " " + indent + ctx.ShadowStyle.Render(display+tag)
	} else {
		line = " " + indent + ctx.PathStyle(lib, display) + ctx.ShadowStyle.Render(tag)
	}
	if selected {
		return ctx.SelStyle.Render(ansi.Strip(line))
	}
	return ctx.SymStyle.Render(line)
}
