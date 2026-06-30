package binfile

import (
	"slices"
	"strings"
)

// sortSymbolsByName sorts syms by Name in place. Keeping this as a true in-place
// sort avoids a second Symbol-sized backing array on binaries with hundreds of
// thousands of symbols; the allocator/GC cost of that temporary outweighed the
// old parallel merge's CPU win on large debug builds.
func sortSymbolsByName(syms []Symbol) {
	byName := func(a, b Symbol) int { return strings.Compare(a.Name, b.Name) }
	slices.SortFunc(syms, byName)
}
