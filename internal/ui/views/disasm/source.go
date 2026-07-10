package disasm

// The source split pane: the disasm view's second pane showing the DWARF
// source mapped to the code. Two layouts share this state — source-first
// (source left, cursor leads, disasm follows) and disasm-first (disasm left,
// source follows the instruction cursor).

import (
	"github.com/rabarbra/exex/internal/ui/layout"
	"github.com/rabarbra/exex/internal/ui/view"
)

// SourceState is the split pane's slice of the disasm view state: which file
// is open, where the cursors are, and the caches over the (immutable once
// loaded) line-table lookups.
type SourceState struct {
	ShowSource  bool // the split pane is enabled (tab)
	SourceFirst bool // source-first layout: the source cursor leads

	SrcFile string // open source file ("" = no source-first pane)
	SrcCur  int    // 1-based current line in the open file
	SrcTop  int
	// RenderedSrcTop is the top actually drawn by the last render (see
	// State.RenderedTop for why wheel input needs the screen snapshot).
	RenderedSrcTop int
	// RightScroll is the follower (right) pane's extra scroll offset;
	// 0 = auto-follow the leading cursor.
	RightScroll int

	// SrcCodeLines are SrcFile's lines that have machine code mapped to them
	// (the gutter/shadow policy reads it per visible line).
	SrcCodeLines map[int]bool

	srcCodeLineCache map[string]map[int]bool
	srcColumnCache   map[SourceLineKey][]int
	// SrcLineHeightCache memoizes wrapped source-line heights. Layout-only
	// (dropped by the shell on width changes), never colour-bearing.
	SrcLineHeightCache map[SourceLineHeightKey]int
	// SourceAsmRowCache memoizes the follower pane's rendered asm rows. Keyed
	// by instruction index, so SetSpan drops it with the window; colour-bearing,
	// so the shell also drops it on theme changes.
	SourceAsmRowCache layout.RowMemo[SourceAsmRowKey, string]
}

// SourceLineKey identifies cached line-column metadata.
type SourceLineKey struct {
	File string
	Line int
}

// SourceLineHeightKey identifies a cached wrapped source-line height. Source
// content is immutable once loaded, so width is the only layout input.
type SourceLineHeightKey struct {
	File string
	Line int
	W    int
}

// SourceAsmRowKey identifies a cached source/assembly mapping row.
type SourceAsmRowKey struct {
	I    int
	W    int
	File string
	Line int
}

// MappedLines returns the set of file's source lines that have machine code
// mapped to them, cached per file (the line table is immutable).
func (st *State) MappedLines(ctx *view.Context, file string) map[int]bool {
	if file == "" {
		return nil
	}
	if st.srcCodeLineCache != nil {
		if lines, ok := st.srcCodeLineCache[file]; ok {
			return lines
		}
	}
	lines := ctx.File.MappedLines(file)
	if st.srcCodeLineCache == nil {
		st.srcCodeLineCache = make(map[string]map[int]bool)
	}
	st.srcCodeLineCache[file] = lines
	return lines
}

// SourceLineColumns returns the distinct columns of file:line that code maps
// to (the caret positions), cached per line.
func (st *State) SourceLineColumns(ctx *view.Context, file string, line int) []int {
	if file == "" || line <= 0 {
		return nil
	}
	key := SourceLineKey{File: file, Line: line}
	if st.srcColumnCache != nil {
		if cols, ok := st.srcColumnCache[key]; ok {
			return cols
		}
	}
	cols := ctx.File.LineColumns(file, line)
	if st.srcColumnCache == nil {
		st.srcColumnCache = make(map[SourceLineKey][]int)
	}
	st.srcColumnCache[key] = cols
	return cols
}
