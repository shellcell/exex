package layout

import "sort"

// TreeIndent is the per-depth indentation of a tree row.
const TreeIndent = 2

// A small, reusable collapsible "name tree" shared by the list views (symbols,
// sources, libs). It groups path-like strings — C++/Swift scoped names split on
// "."/"::", or filesystem paths split on "/" — into a multi-level tree whose
// internal nodes can be collapsed. Building and flattening are pure functions;
// the owning view keeps the collapse state and the flattened row slice.

// TreeNode is one node of a name tree. Internal (group) nodes have leaf == -1
// and children; leaves carry the index of the underlying item (symbol/file/lib).
type TreeNode struct {
	Label    string // segment shown for this node; internal nodes keep the trailing separator
	Path     string // internal nodes only: full path from the root, the collapse-state key. Left empty for leaves (never read for them — collapse keys off the item index), which avoids a prefix+label concatenation per leaf (tens of MB on a 100k+-symbol tree).
	Leaf     int    // item index for a leaf, -1 for an internal node
	Count    int    // number of leaf descendants (for the collapsed "(n)" hint)
	Children []*TreeNode
}

// TreeRow is one flattened, currently-visible row: a node and its depth.
type TreeRow struct {
	Node  *TreeNode
	Depth int
}

// SegFunc returns the byte length of the first path segment of s (including its
// trailing separator), or -1 when s has no separator (so s is a leaf remainder).
type SegFunc func(s string) int

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

// SegPath splits on "/" (filesystem paths and library install paths).
func SegPath(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			return i + 1
		}
	}
	return -1
}

// BuildTree groups idxs (already sorted by label) into a name tree using seg to
// pick segment boundaries.
func BuildTree(idxs []int, label func(int) string, seg SegFunc) []*TreeNode {
	return buildTreeLevel(idxs, label, seg, 0, "")
}

// BuildScopedTree groups symbols into a two-pass name tree: first by scope/word
// boundaries (segScoped), then folding whatever that leaves as singletons by a
// shared "_" prefix (segUnder). idxs must already be sorted by label.
func BuildScopedTree(idxs []int, label func(int) string) []*TreeNode {
	return buildScopedLevel(idxs, label, 0, "")
}

// buildScopedLevel builds one level of the scoped tree. Pass 1 groups runs of
// items that share a scope/word segment; items whose segment is unique fall
// through to pass 2, which folds them by a shared "_" prefix. Anything still
// unique becomes a leaf shown by its remaining path. Groups (from either pass)
// sort before leaves, each in label order.
func buildScopedLevel(idxs []int, label func(int) string, prefixLen int, prefix string) []*TreeNode {
	var nodes []*TreeNode

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
		nodes = append(nodes, &TreeNode{Label: rem, Leaf: rest[i], Count: 1}) // leaves need no path
		i++
	}

	// Pass 1 and pass 2 produce two separately-ordered streams; restore a single
	// sorted order with collapsible groups ahead of loose leaves.
	sort.SliceStable(nodes, func(i, j int) bool {
		if a, b := leafRank(nodes[i]), leafRank(nodes[j]); a != b {
			return a < b
		}
		return nodes[i].Label < nodes[j].Label
	})
	return nodes
}

// sharesSeg reports whether full (at prefixLen) begins with seg and has seg as its
// own first segment under fn — i.e. it belongs in the same group.
func sharesSeg(full string, prefixLen, sl int, seg string, fn SegFunc) bool {
	return len(full) >= prefixLen+sl && full[prefixLen:prefixLen+sl] == seg && fn(full[prefixLen:]) == sl
}

// scopedGroup builds an internal node for idxs (which all share segment seg),
// recursing for its children, compressing single-child chains and summing counts.
func scopedGroup(idxs []int, label func(int) string, seg string, prefixLen int, prefix string) *TreeNode {
	node := &TreeNode{Label: seg, Path: prefix + seg, Leaf: -1}
	node.Children = buildScopedLevel(idxs, label, prefixLen+len(seg), node.Path)
	compressTree(node)
	for _, c := range node.Children {
		node.Count += c.Count
	}
	return node
}

func buildTreeLevel(idxs []int, label func(int) string, seg SegFunc, prefixLen int, prefix string) []*TreeNode {
	var nodes []*TreeNode
	for i := 0; i < len(idxs); {
		rem := label(idxs[i])[prefixLen:]
		sl := seg(rem)
		if sl < 0 {
			nodes = append(nodes, &TreeNode{Label: rem, Leaf: idxs[i], Count: 1}) // leaves need no path
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
			nodes = append(nodes, &TreeNode{Label: rem, Leaf: idxs[i], Count: 1}) // leaves need no path
			i++
			continue
		}
		node := &TreeNode{Label: segStr, Path: prefix + segStr, Leaf: -1}
		node.Children = buildTreeLevel(idxs[i:j], label, seg, prefixLen+sl, node.Path)
		compressTree(node)
		for _, c := range node.Children {
			node.Count += c.Count
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

func leafRank(n *TreeNode) int {
	if n.Leaf < 0 {
		return 0 // internal (group) node sorts first
	}
	return 1
}

// compressTree folds chains of single internal children into one node, so a run
// of single-child namespaces (a::b::c::) reads as one row instead of three.
func compressTree(n *TreeNode) {
	for len(n.Children) == 1 && n.Children[0].Leaf < 0 {
		c := n.Children[0]
		n.Label += c.Label
		n.Path = c.Path
		n.Children = c.Children
	}
}

// FlattenTree appends the visible rows of nodes to out: every node, plus the
// children of expanded internal nodes (collapsed[path] hides descendants).
func FlattenTree(nodes []*TreeNode, collapsed map[string]bool, depth int, out []TreeRow) []TreeRow {
	for _, n := range nodes {
		out = append(out, TreeRow{Node: n, Depth: depth})
		if n.Leaf < 0 && !collapsed[n.Path] {
			out = FlattenTree(n.Children, collapsed, depth+1, out)
		}
	}
	return out
}

// TreeExpandOne expands the collapsed node at *cur (one level) and moves the
// cursor onto the first item of the now-revealed branch. Returns whether anything
// changed (the caller then rebuilds the flattened rows).
func TreeExpandOne(rows []TreeRow, cur *int, collapsed map[string]bool) bool {
	if *cur < 0 || *cur >= len(rows) {
		return false
	}
	n := rows[*cur].Node
	if n.Leaf >= 0 || !collapsed[n.Path] {
		return false
	}
	delete(collapsed, n.Path)
	*cur++ // land on the first child of the expanded branch
	return true
}

// TreeCollapseOne collapses the node at *cur, or — when it is a leaf or already
// collapsed — the nearest ancestor group above it (moving the cursor onto it).
func TreeCollapseOne(rows []TreeRow, cur *int, collapsed map[string]bool) bool {
	if *cur < 0 || *cur >= len(rows) {
		return false
	}
	row := rows[*cur]
	if row.Node.Leaf < 0 && !collapsed[row.Node.Path] {
		collapsed[row.Node.Path] = true
		return true
	}
	for k := *cur - 1; k >= 0; k-- {
		if rows[k].Depth < row.Depth && rows[k].Node.Leaf < 0 {
			*cur = k
			collapsed[rows[k].Node.Path] = true
			return true
		}
	}
	return false
}

// TreeToggleSubtree expands or collapses the whole subtree under the node at cur:
// collapse-all-below when it is currently expanded, expand-all-below when not.
func TreeToggleSubtree(rows []TreeRow, cur int, collapsed map[string]bool) bool {
	if cur < 0 || cur >= len(rows) || rows[cur].Node.Leaf >= 0 {
		return false
	}
	n := rows[cur].Node
	setSubtreeCollapsed(n, collapsed, !collapsed[n.Path])
	return true
}

// setSubtreeCollapsed collapses (c=true) or expands (c=false) node and every
// internal node beneath it in the given collapse set.
func setSubtreeCollapsed(node *TreeNode, collapsed map[string]bool, c bool) {
	EachInternal([]*TreeNode{node}, func(p string) {
		if c {
			collapsed[p] = true
		} else {
			delete(collapsed, p)
		}
	})
}

// EachInternal calls fn for every internal node's path (used by "collapse all").
func EachInternal(nodes []*TreeNode, fn func(path string)) {
	for _, n := range nodes {
		if n.Leaf < 0 {
			fn(n.Path)
			EachInternal(n.Children, fn)
		}
	}
}
