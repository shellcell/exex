package ui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/x/ansi"
)

// treeNodeRow renders a collapsible group row: indent + arrow + coloured label +
// dim "(count)". Group nodes use the tree-node colour (not the leaf colours); a
// selected node is shown in reverse video of that colour (a coloured cursor cue),
// rather than the full-width white selection bar that leaf rows get. leftPad is
// the view's leading margin ("" for symbols, " " for sources/libs).
func (m *Model) treeNodeRow(depth int, label string, count int, collapsed, selected bool, leftPad string, width int) string {
	indent := strings.Repeat(" ", depth*treeIndent)
	arrow := "▾ "
	if collapsed {
		arrow = "▸ "
	}
	style := m.theme.treeNodeStyle
	if selected {
		style = style.Reverse(true)
	}
	cnt := ""
	if collapsed {
		cnt = fmt.Sprintf("  (%d)", max(count, 0)) // show the hidden-leaf count
	}
	avail := width - len(leftPad) - len(indent) - 2 - ansi.StringWidth(cnt)
	if avail < 1 {
		avail = 1
	}
	return leftPad + indent + style.Render(arrow+truncateMiddle(label, avail)) + m.theme.srcShadowStyle.Render(cnt)
}

// A small, reusable collapsible "name tree" shared by the list views (symbols,
// sources, libs). It groups path-like strings — C++/Swift scoped names split on
// "."/"::", or filesystem paths split on "/" — into a multi-level tree whose
// internal nodes can be collapsed. Building and flattening are pure functions;
// the owning view keeps the collapse state and the flattened row slice.

// treeNode is one node of a name tree. Internal (group) nodes have leaf == -1
// and children; leaves carry the index of the underlying item (symbol/file/lib).
type treeNode struct {
	label    string // segment shown for this node; internal nodes keep the trailing separator
	path     string // full path from the root, unique — the collapse-state key
	leaf     int    // item index for a leaf, -1 for an internal node
	count    int    // number of leaf descendants (for the collapsed "(n)" hint)
	children []*treeNode
}

// treeRow is one flattened, currently-visible row: a node and its depth.
type treeRow struct {
	node  *treeNode
	depth int
}

// segFunc returns the byte length of the first path segment of s (including its
// trailing separator), or -1 when s has no separator (so s is a leaf remainder).
type segFunc func(s string) int

// segScoped splits a scoped name into its first segment by scope/word boundary:
// ".", "::" and " " (space), weighed equally — the earliest one at bracket depth
// zero wins. A name thus folds by whichever scope/word boundary comes first, and a
// family sharing a descriptive prefix ("lazy protocol witness table accessor for
// type …") stays unified (folded by the first space) instead of fragmenting by
// whichever member happens to reach a dot. Separators inside template arguments
// <…>, parameter lists (…) or [...] never split. Returns -1 when there is no
// boundary. "_" is handled separately, as a second-pass fallback (see segUnder and
// buildScopedLevel). Single-child chains are path-compressed afterward, so e.g.
// "void " → "std::" reads as "void std::".
func segScoped(s string) int {
	depth := 0
	content := false // seen a non-separator char at depth 0 yet?
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '<', '(', '[':
			content = true
			depth++
		case '>', ')', ']':
			content = true
			if depth > 0 {
				depth--
			}
		case '.', ' ':
			// Don't split inside a leading run of separators (no node labelled just
			// spaces); require a real character first.
			if depth == 0 && content {
				return i + 1
			}
		case ':':
			if depth == 0 && content && i+1 < len(s) && s[i+1] == ':' {
				return i + 2
			}
		default:
			if depth == 0 {
				content = true
			}
		}
	}
	return -1
}

// segUnder splits on "_" the way segScoped splits on scope separators: earliest
// underscore at bracket depth zero, after a real character (so a leading "__" run
// never forms an underscore-only node). It is the second-pass fallback used to fold
// items that segScoped left as singletons, letting flat C/Zig families group —
// "irq_stub_100"/"irq_stub_101" by "irq_", and "__zig_is_named_enum_value_X.Y"
// (each unique by scope) by their shared "__zig_is_named_enum_value_" prefix.
func segUnder(s string) int {
	depth := 0
	content := false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '<', '(', '[':
			content = true
			depth++
		case '>', ')', ']':
			content = true
			if depth > 0 {
				depth--
			}
		case '_':
			if depth == 0 && content {
				return i + 1
			}
		default:
			if depth == 0 {
				content = true
			}
		}
	}
	return -1
}

// segPath splits on "/" (filesystem paths and library install paths).
func segPath(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			return i + 1
		}
	}
	return -1
}

// buildTree groups idxs (already sorted by label) into a name tree using seg to
// pick segment boundaries.
func buildTree(idxs []int, label func(int) string, seg segFunc) []*treeNode {
	return buildTreeLevel(idxs, label, seg, 0, "")
}

// buildScopedTree groups symbols into a two-pass name tree: first by scope/word
// boundaries (segScoped), then folding whatever that leaves as singletons by a
// shared "_" prefix (segUnder). idxs must already be sorted by label.
func buildScopedTree(idxs []int, label func(int) string) []*treeNode {
	return buildScopedLevel(idxs, label, 0, "")
}

// buildScopedLevel builds one level of the scoped tree. Pass 1 groups runs of
// items that share a scope/word segment; items whose segment is unique fall
// through to pass 2, which folds them by a shared "_" prefix. Anything still
// unique becomes a leaf shown by its remaining path. Groups (from either pass)
// sort before leaves, each in label order.
func buildScopedLevel(idxs []int, label func(int) string, prefixLen int, prefix string) []*treeNode {
	var nodes []*treeNode

	// Pass 1: fold by scope/word boundary; collect the leftovers (unique segments).
	var rest []int
	for i := 0; i < len(idxs); {
		rem := label(idxs[i])[prefixLen:]
		sl := segScoped(rem)
		if sl < 0 {
			rest = append(rest, idxs[i])
			i++
			continue
		}
		seg := rem[:sl]
		j := i + 1
		for j < len(idxs) && sharesSeg(label(idxs[j]), prefixLen, sl, seg, segScoped) {
			j++
		}
		if j-i == 1 {
			rest = append(rest, idxs[i])
			i++
			continue
		}
		nodes = append(nodes, scopedGroup(idxs[i:j], label, seg, prefixLen, prefix))
		i = j
	}

	// Pass 2: among the leftovers, fold shared "_" prefixes; the rest are leaves.
	for i := 0; i < len(rest); {
		rem := label(rest[i])[prefixLen:]
		sl := segUnder(rem)
		if sl >= 0 {
			seg := rem[:sl]
			j := i + 1
			for j < len(rest) && sharesSeg(label(rest[j]), prefixLen, sl, seg, segUnder) {
				j++
			}
			if j-i > 1 {
				nodes = append(nodes, scopedGroup(rest[i:j], label, seg, prefixLen, prefix))
				i = j
				continue
			}
		}
		nodes = append(nodes, &treeNode{label: rem, path: prefix + rem, leaf: rest[i], count: 1})
		i++
	}

	// Pass 1 and pass 2 produce two separately-ordered streams; restore a single
	// sorted order with collapsible groups ahead of loose leaves.
	sort.SliceStable(nodes, func(i, j int) bool {
		if a, b := leafRank(nodes[i]), leafRank(nodes[j]); a != b {
			return a < b
		}
		return nodes[i].label < nodes[j].label
	})
	return nodes
}

// sharesSeg reports whether full (at prefixLen) begins with seg and has seg as its
// own first segment under fn — i.e. it belongs in the same group.
func sharesSeg(full string, prefixLen, sl int, seg string, fn segFunc) bool {
	return len(full) >= prefixLen+sl && full[prefixLen:prefixLen+sl] == seg && fn(full[prefixLen:]) == sl
}

// scopedGroup builds an internal node for idxs (which all share segment seg),
// recursing for its children, compressing single-child chains and summing counts.
func scopedGroup(idxs []int, label func(int) string, seg string, prefixLen int, prefix string) *treeNode {
	node := &treeNode{label: seg, path: prefix + seg, leaf: -1}
	node.children = buildScopedLevel(idxs, label, prefixLen+len(seg), node.path)
	compressTree(node)
	for _, c := range node.children {
		node.count += c.count
	}
	return node
}

func buildTreeLevel(idxs []int, label func(int) string, seg segFunc, prefixLen int, prefix string) []*treeNode {
	var nodes []*treeNode
	for i := 0; i < len(idxs); {
		rem := label(idxs[i])[prefixLen:]
		sl := seg(rem)
		if sl < 0 {
			nodes = append(nodes, &treeNode{label: rem, path: prefix + rem, leaf: idxs[i], count: 1})
			i++
			continue
		}
		segStr := rem[:sl]
		j := i + 1
		for j < len(idxs) {
			r := label(idxs[j])
			if len(r) >= prefixLen+sl && r[prefixLen:prefixLen+sl] == segStr && seg(r[prefixLen:]) == sl {
				j++
				continue
			}
			break
		}
		if j-i == 1 {
			// A segment owned by a single item needs no group: show it whole as a leaf.
			nodes = append(nodes, &treeNode{label: rem, path: prefix + rem, leaf: idxs[i], count: 1})
			i++
			continue
		}
		node := &treeNode{label: segStr, path: prefix + segStr, leaf: -1}
		node.children = buildTreeLevel(idxs[i:j], label, seg, prefixLen+sl, node.path)
		compressTree(node)
		for _, c := range node.children {
			node.count += c.count
		}
		nodes = append(nodes, node)
		i = j
	}
	// Collapsible groups first, then the loose leaves, each keeping sorted order.
	sort.SliceStable(nodes, func(i, j int) bool {
		return leafRank(nodes[i]) < leafRank(nodes[j])
	})
	return nodes
}

func leafRank(n *treeNode) int {
	if n.leaf < 0 {
		return 0 // internal (group) node sorts first
	}
	return 1
}

// compressTree folds chains of single internal children into one node, so a run
// of single-child namespaces (a::b::c::) reads as one row instead of three.
func compressTree(n *treeNode) {
	for len(n.children) == 1 && n.children[0].leaf < 0 {
		c := n.children[0]
		n.label += c.label
		n.path = c.path
		n.children = c.children
	}
}

// flattenTree appends the visible rows of nodes to out: every node, plus the
// children of expanded internal nodes (collapsed[path] hides descendants).
func flattenTree(nodes []*treeNode, collapsed map[string]bool, depth int, out []treeRow) []treeRow {
	for _, n := range nodes {
		out = append(out, treeRow{node: n, depth: depth})
		if n.leaf < 0 && !collapsed[n.path] {
			out = flattenTree(n.children, collapsed, depth+1, out)
		}
	}
	return out
}

// treeExpandOne expands the collapsed node at *cur (one level) and moves the
// cursor onto the first item of the now-revealed branch. Returns whether anything
// changed (the caller then rebuilds the flattened rows).
func treeExpandOne(rows []treeRow, cur *int, collapsed map[string]bool) bool {
	if *cur < 0 || *cur >= len(rows) {
		return false
	}
	n := rows[*cur].node
	if n.leaf >= 0 || !collapsed[n.path] {
		return false
	}
	delete(collapsed, n.path)
	*cur++ // land on the first child of the expanded branch
	return true
}

// treeCollapseOne collapses the node at *cur, or — when it is a leaf or already
// collapsed — the nearest ancestor group above it (moving the cursor onto it).
func treeCollapseOne(rows []treeRow, cur *int, collapsed map[string]bool) bool {
	if *cur < 0 || *cur >= len(rows) {
		return false
	}
	row := rows[*cur]
	if row.node.leaf < 0 && !collapsed[row.node.path] {
		collapsed[row.node.path] = true
		return true
	}
	for k := *cur - 1; k >= 0; k-- {
		if rows[k].depth < row.depth && rows[k].node.leaf < 0 {
			*cur = k
			collapsed[rows[k].node.path] = true
			return true
		}
	}
	return false
}

// treeToggleSubtree expands or collapses the whole subtree under the node at cur:
// collapse-all-below when it is currently expanded, expand-all-below when not.
func treeToggleSubtree(rows []treeRow, cur int, collapsed map[string]bool) bool {
	if cur < 0 || cur >= len(rows) || rows[cur].node.leaf >= 0 {
		return false
	}
	n := rows[cur].node
	setSubtreeCollapsed(n, collapsed, !collapsed[n.path])
	return true
}

// setSubtreeCollapsed collapses (c=true) or expands (c=false) node and every
// internal node beneath it in the given collapse set.
func setSubtreeCollapsed(node *treeNode, collapsed map[string]bool, c bool) {
	eachInternal([]*treeNode{node}, func(p string) {
		if c {
			collapsed[p] = true
		} else {
			delete(collapsed, p)
		}
	})
}

// eachInternal calls fn for every internal node's path (used by "collapse all").
func eachInternal(nodes []*treeNode, fn func(path string)) {
	for _, n := range nodes {
		if n.leaf < 0 {
			fn(n.path)
			eachInternal(n.children, fn)
		}
	}
}
