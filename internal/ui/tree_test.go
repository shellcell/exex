package ui

import (
	"strings"
	"testing"
)

// dumpTree renders the scoped tree as an indented outline ("[label]" for group
// nodes, bare label for leaves) so grouping decisions are easy to assert on.
func dumpTree(nodes []*treeNode, depth int, b *strings.Builder) {
	for _, n := range nodes {
		b.WriteString(strings.Repeat("  ", depth))
		if n.leaf < 0 {
			b.WriteString("[" + n.label + "]\n")
			dumpTree(n.children, depth+1, b)
		} else {
			b.WriteString(n.label + "\n")
		}
	}
}

// scopedOutline builds the scoped tree for names (which must be sorted) and returns
// its outline.
func scopedOutline(names []string) string {
	idxs := make([]int, len(names))
	for i := range idxs {
		idxs[i] = i
	}
	var b strings.Builder
	dumpTree(buildScopedTree(idxs, func(i int) string { return names[i] }), 0, &b)
	return b.String()
}

func TestScopedTreeFolding(t *testing.T) {
	cases := []struct {
		name    string
		names   []string
		want    []string // substrings that must appear
		notWant []string // substrings that must not appear
	}{
		{
			// Each name is unique by scope (the part before the first dot differs), so
			// pass 1 leaves them all as singletons; pass 2 must fold the shared
			// underscore prefix.
			name: "zig is_named_enum_value folds by underscore prefix",
			names: []string{
				"__zig_is_named_enum_value_build.Config.ReleaseChannel",
				"__zig_is_named_enum_value_builtin.OptimizeMode",
				"__zig_is_named_enum_value_c.darwin.E",
				"__zig_is_named_enum_value_fs.File.Kind",
			},
			want: []string{"[__zig_is_named_enum_value_]"},
		},
		{
			// The divergence is inside @typeInfo(...) parens; the first scope dot is
			// past the parens, so again pass 2 underscore folding must catch it.
			name: "zig tag_name folds despite bracketed divergence",
			names: []string{
				`__zig_tag_name_@typeInfo(input.Link.Action).@"union".tag_type.?`,
				`__zig_tag_name_@typeInfo(internal.tess.Tag).@"union".tag_type.?`,
			},
			want: []string{"[__zig_tag_name_]"},
		},
		{
			// A snake_case identifier shared by two names must fold by the dot, not
			// fragment mid-identifier on the underscore.
			name: "snake_case with dot does not fragment",
			names: []string{
				"internal.tess.dashed_plotter.Other",
				"internal.tess.dashed_plotter.Plotter",
			},
			want:    []string{"[internal.tess.dashed_plotter.]"},
			notWant: []string{"[dashed_]"},
		},
		{
			name: "cpp templates fold by scope, overloads by underscore",
			names: []string{
				"std::map::insert",
				"std::vector<int>::push_back",
				"std::vector<int>::push_front",
			},
			want: []string{"[std::]", "[vector<int>::push_]"},
		},
		{
			name: "swift descriptive families unify by spaces",
			names: []string{
				"lazy protocol witness table accessor for type Foo.Bar",
				"lazy protocol witness table cache variable for type Baz.Qux",
			},
			want: []string{"[lazy protocol witness table "},
		},
		{
			// A leading run of underscores must never become an "_"/"__" only node.
			name: "no underscore-only nodes",
			names: []string{
				"_foo",
				"_goo",
			},
			notWant: []string{"[_]", "[__]"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scopedOutline(tc.names)
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("missing %q in:\n%s", w, got)
				}
			}
			for _, nw := range tc.notWant {
				if strings.Contains(got, nw) {
					t.Errorf("unexpected %q in:\n%s", nw, got)
				}
			}
		})
	}
}
