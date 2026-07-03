// Package sources implements the Sources view's file list (DWARF only): every
// source file referenced by the line table, as a project-first flat list or a
// directory tree, with name filtering and an on-disk availability lens.
// Opening a file (Enter/o) switches to the disasm view in source-first mode —
// that split source/disasm pane needs the shell's disasm state, so the view
// triggers it via view.Host and the pane itself lives with the shell. Like the
// other extracted views, this package depends only on a view.Context (render
// inputs) and a view.Host (actions).
package sources

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"charm.land/bubbles/v2/textinput"
	"github.com/charmbracelet/x/ansi"

	sourceutil "github.com/rabarbra/exex/internal/sourcefiles"
	"github.com/rabarbra/exex/internal/ui/layout"
	"github.com/rabarbra/exex/internal/ui/view"
)

// SortField is the flat-list order of the source files.
type SortField uint8

const (
	SortProject SortField = iota // project files first (the natural default)
	SortName                     // pure alphabetical by path
)

// String returns the sort's filter-status label.
func (s SortField) String() string {
	if s == SortName {
		return "name"
	}
	return "project"
}

// State stores the file-list state for the Sources view.
type State struct {
	Files       []string
	Filter      textinput.Model
	Filtered    []int // indices into Files
	Cur         int   // cursor in Rows
	Top         int
	RenderedTop int  // Top as of the last render, for mouse hit-testing
	Tree        bool // show the file list as a directory tree
	TreeInit    bool
	Rows        []layout.TreeRow // flattened visible rows (dirs + files)
	Sort        SortField        // flat-list order: project-first or name
	SortDesc    bool             // reverse the active sort
	Avail       view.AvailFilter // availability filter: all / present / missing

	collapsed map[string]bool // collapsed directory paths
}

// Ensure loads the source-file list once.
func (st *State) Ensure(ctx view.Context) {
	if st.Files == nil {
		st.Files = ctx.File.SourceFiles()
		if st.Files == nil {
			st.Files = []string{}
		}
		wd, _ := os.Getwd()
		sourceutil.SortForProject(st.Files, ctx.File.Path, wd)
		st.Recompute(ctx)
	}
}

// applySort orders Filtered for the flat list. The project-first order is the
// natural order of Files, so it only reverses for descending; name order sorts
// by path. (Tree mode always groups alphabetically.)
func (st *State) applySort() {
	desc := st.SortDesc
	if st.Sort == SortName {
		sort.SliceStable(st.Filtered, func(a, b int) bool {
			fa, fb := st.Files[st.Filtered[a]], st.Files[st.Filtered[b]]
			if desc {
				return fa > fb
			}
			return fa < fb
		})
		return
	}
	if desc {
		layout.ReverseInts(st.Filtered)
	}
}

// Recompute rebuilds the filtered file list and visible rows from the current
// filter (and, in tree mode, the directory tree + collapse state).
func (st *State) Recompute(ctx view.Context) {
	needle := strings.ToLower(st.Filter.Value())
	st.Filtered = st.Filtered[:0]
	for i, f := range st.Files {
		if needle != "" && !layout.ContainsFold(f, needle) {
			continue
		}
		switch st.Avail {
		case view.AvailPresent:
			if !ctx.File.SourceExists(f) {
				continue
			}
		case view.AvailMissing:
			if ctx.File.SourceExists(f) {
				continue
			}
		}
		st.Filtered = append(st.Filtered, i)
	}
	st.applySort()
	st.BuildRows(ctx)
	st.clampCursor()
}

// sortedIdxs returns the filtered file indices sorted alphabetically by path —
// needed for the adjacency-based directory tree (the flat list keeps its
// project-first order).
func (st *State) sortedIdxs() []int {
	idxs := append([]int(nil), st.Filtered...)
	sort.Slice(idxs, func(a, b int) bool { return st.Files[idxs[a]] < st.Files[idxs[b]] })
	return idxs
}

// BuildRows flattens the filtered files into a directory tree (tree mode) or
// one leaf row per file (flat mode).
func (st *State) BuildRows(ctx view.Context) {
	if st.Tree {
		roots := layout.BuildTree(st.sortedIdxs(), func(i int) string { return st.Files[i] }, layout.SegPath)
		if !st.TreeInit {
			st.TreeInit = true
			if ctx.TreeCollapseDefault {
				st.collapsed = map[string]bool{}
				layout.EachInternal(roots, func(p string) { st.collapsed[p] = true })
			}
		}
		collapsed := st.collapsed
		if st.Filter.Value() != "" {
			collapsed = nil
		}
		st.Rows = layout.FlattenTree(roots, collapsed, 0, st.Rows[:0])
		return
	}
	nodes := make([]layout.TreeNode, len(st.Filtered))
	rows := st.Rows[:0]
	for k, idx := range st.Filtered {
		nodes[k] = layout.TreeNode{Label: st.Files[idx], Leaf: idx, Count: 1}
		rows = append(rows, layout.TreeRow{Node: &nodes[k], Depth: 0})
	}
	st.Rows = rows
}

// FileAt returns the file path for the row, when it is a leaf.
func (st *State) FileAt(rowIdx int) (string, bool) {
	if rowIdx < 0 || rowIdx >= len(st.Rows) {
		return "", false
	}
	n := st.Rows[rowIdx].Node
	if n.Leaf < 0 {
		return "", false
	}
	return st.Files[n.Leaf], true
}

// CurrentFile returns the file under the cursor when the row is a leaf.
func (st *State) CurrentFile() (string, bool) {
	return st.FileAt(st.Cur)
}

// ToggleNode collapses/expands the directory node at the current row (the
// mouse-click path; keyboard folding goes through Update).
func (st *State) ToggleNode(ctx view.Context) {
	if st.Cur < 0 || st.Cur >= len(st.Rows) {
		return
	}
	n := st.Rows[st.Cur].Node
	if n.Leaf >= 0 {
		return
	}
	st.ensureCollapsed()
	st.collapsed[n.Path] = !st.collapsed[n.Path]
	st.BuildRows(ctx)
	st.clampCursor()
}

// SetAllCollapsed collapses or expands every directory node.
func (st *State) SetAllCollapsed(ctx view.Context, collapsed bool) {
	if !st.Tree {
		return
	}
	if !collapsed {
		st.collapsed = nil
	} else {
		st.collapsed = map[string]bool{}
		roots := layout.BuildTree(st.sortedIdxs(), func(i int) string { return st.Files[i] }, layout.SegPath)
		layout.EachInternal(roots, func(p string) { st.collapsed[p] = true })
	}
	st.BuildRows(ctx)
	st.clampCursor()
}

func (st *State) ensureCollapsed() {
	if st.collapsed == nil {
		st.collapsed = map[string]bool{}
	}
}

func (st *State) clampCursor() {
	if st.Cur >= len(st.Rows) {
		st.Cur = max(0, len(st.Rows)-1)
	}
}

// Update handles keys while the Sources file list is active. The cross-source
// search modal (ctrl+f) needs the shell's search state, so the shell's adapter
// intercepts that key before delegating here.
func (st *State) Update(ctx view.Context, host view.Host, key string) {
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
		st.Recompute(ctx)
		if dirty {
			host.SetStatus("filters cleared", false)
		}
	case "ctrl+p":
		// cycle availability filter: all → present → missing → all
		switch st.Avail {
		case view.AvailAll:
			st.Avail = view.AvailPresent
		case view.AvailPresent:
			st.Avail = view.AvailMissing
		default:
			st.Avail = view.AvailAll
		}
		st.Cur, st.Top = 0, 0
		st.Recompute(ctx)
		host.SetStatus("sources: "+view.AvailLabel(st.Avail), false)
	case "s":
		st.Sort = (st.Sort + 1) % 2
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
	case "t":
		st.Tree = !st.Tree
		st.Cur, st.Top = 0, 0
		st.Recompute(ctx)
		label := "flat list"
		if st.Tree {
			label = "tree"
		}
		host.SetStatus("sources view: "+label, false)
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
		if f, ok := st.CurrentFile(); ok {
			host.CopyToClipboard(f, "source path")
		}
	case "o":
		// Open the selected file in the disasm source-first view (doc #27: `o`
		// opens a source there, mirroring its "open lib as primary" role in Libs).
		if f, ok := st.CurrentFile(); ok {
			host.OpenSourceFile(f)
		}
	case "w":
		host.ToggleWrap()
	case "enter", " ":
		if st.Cur >= 0 && st.Cur < len(st.Rows) && st.Rows[st.Cur].Node.Leaf < 0 {
			st.ensureCollapsed()
			if layout.TreeToggleSubtree(st.Rows, st.Cur, st.collapsed) {
				st.BuildRows(ctx)
			}
		} else if f, ok := st.CurrentFile(); ok {
			host.OpenSourceFile(f)
		}
	}
}

// Render draws the file list.
func (st *State) Render(ctx view.Context, host view.Host) string {
	bodyH := ctx.BodyH
	if bodyH < 2 {
		bodyH = 2
	}
	filterRow := st.Filter.View()
	if !st.Filter.Focused() {
		facet := ""
		if st.Tree {
			facet = "  tree"
		}
		if st.Avail != view.AvailAll {
			facet += "  " + ctx.KeyStyle.Render(layout.CtrlKeys("p")) + " " + view.AvailLabel(st.Avail)
		}
		if !st.Tree {
			dir := "↑"
			if st.SortDesc {
				dir = "↓"
			}
			facet += "  " + ctx.KeyStyle.Render("s") + " sort:" + st.Sort.String() + dir
		}
		filterRow = ctx.FooterStyle.Render(fmt.Sprintf("/ %s   (%d / %d source files)",
			st.Filter.Value(), len(st.Filtered), len(st.Files))) + ctx.FooterStyle.Render(facet)
	}

	visible := bodyH - 1
	if visible < 1 {
		visible = 1
	}
	one := func(int) int { return 1 }
	top := ctx.VisualTop(st.Cur, st.Top, len(st.Rows), visible, one)
	st.Top = top
	st.RenderedTop = top
	host.SetPageRows(layout.PageStep(top, len(st.Rows), visible, one))
	end := top + visible
	if end > len(st.Rows) {
		end = len(st.Rows)
	}

	if len(st.Rows) == 0 {
		msg := "no source files"
		if st.Filter.Value() != "" || st.Avail != view.AvailAll {
			msg = "no matching source files  ·  Esc clears filters"
		}
		return ctx.EmptyList(msg, filterRow)
	}
	var b strings.Builder
	b.WriteString(filterRow)
	b.WriteString("\n")
	for i := top; i < end; i++ {
		b.WriteString(st.row(ctx, i, i == st.Cur))
		b.WriteString("\n")
	}
	return layout.PadBody(b.String(), ctx.Width, bodyH)
}

// RowText returns the current row's plain text, for the copy-line action.
func (st *State) RowText() string {
	if f, ok := st.CurrentFile(); ok {
		return f
	}
	if st.Cur >= 0 && st.Cur < len(st.Rows) {
		return st.Rows[st.Cur].Node.Label
	}
	return ""
}

func (st *State) row(ctx view.Context, i int, selected bool) string {
	row := st.Rows[i]
	n := row.Node
	if n.Leaf < 0 {
		collapsed := st.collapsed != nil && st.collapsed[n.Path]
		return ctx.TreeNodeRow(row.Depth, n.Label, n.Count, collapsed, selected, " ")
	}
	full := st.Files[n.Leaf]
	indent := strings.Repeat(" ", row.Depth*layout.TreeIndent)
	trunc := layout.TruncateMiddle(n.Label, max(8, ctx.Width-len(indent)-2))
	name := ctx.PathStyle(full, trunc)
	if !ctx.File.SourceExists(full) { // not on disk: dim it (can't be opened)
		name = ctx.ShadowStyle.Render(trunc)
	}
	line := layout.PadRight(" "+indent+name, ctx.Width)
	if selected {
		return ctx.SelStyle.Render(ansi.Strip(line))
	}
	return ctx.RowStyle.Render(line)
}
