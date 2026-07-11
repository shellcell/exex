package disasm

// The source split pane: the disasm view's second pane showing the DWARF
// source mapped to the code. Two layouts share this state — source-first
// (source left, cursor leads, disasm follows) and disasm-first (disasm left,
// source follows the instruction cursor).

import (
	"path/filepath"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/ui/layout"
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
	// SrcPageRows is the page step recorded at the last source-text render, so
	// the shell's pgup/pgdn advance one screen of (possibly wrapped) lines.
	SrcPageRows int

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
func (st *State) MappedLines(f *binfile.File, file string) map[int]bool {
	if file == "" {
		return nil
	}
	if st.srcCodeLineCache != nil {
		if lines, ok := st.srcCodeLineCache[file]; ok {
			return lines
		}
	}
	lines := f.MappedLines(file)
	if st.srcCodeLineCache == nil {
		st.srcCodeLineCache = make(map[string]map[int]bool)
	}
	st.srcCodeLineCache[file] = lines
	return lines
}

// SourceLineColumns returns the distinct columns of file:line that code maps
// to (the caret positions), cached per line.
func (st *State) SourceLineColumns(f *binfile.File, file string, line int) []int {
	if file == "" || line <= 0 {
		return nil
	}
	key := SourceLineKey{File: file, Line: line}
	if st.srcColumnCache != nil {
		if cols, ok := st.srcColumnCache[key]; ok {
			return cols
		}
	}
	cols := f.LineColumns(file, line)
	if st.srcColumnCache == nil {
		st.srcColumnCache = make(map[SourceLineKey][]int)
	}
	st.srcColumnCache[key] = cols
	return cols
}

// ---- source-first navigation: the source cursor leads, the window follows ----

// LoadedAddr reports whether addr is inside the decoded window *and* lands on
// an instruction there.
func (st *State) LoadedAddr(f *binfile.File, addr uint64) bool {
	if len(st.Inst) == 0 {
		return false
	}
	pos, ok := f.ExecImage().PosForAddr(addr)
	if !ok || pos < st.PosLo || pos >= st.PosHi {
		return false
	}
	_, ok = st.IndexForAddr(addr)
	return ok
}

// SyncSourceAsm points the disasm cursor at the address mapped from the
// current source line, so the follower pane tracks the source cursor. h is the
// scroller height the context scroll positions against.
func (st *State) SyncSourceAsm(env Env, h int) {
	if !env.Svc.CanDecode() {
		return
	}
	addr, ok := env.File.LineToAddr(st.SrcFile, st.SrcCur)
	if !ok {
		return
	}
	if _, mapped := env.File.ExecImage().PosForAddr(addr); !mapped {
		return
	}
	// The disasm is windowed; load the span around this line's address if it
	// isn't already loaded. SetSpan leaves the active view alone (the user may
	// be in the Sources view); it just refreshes the instruction window the
	// follower pane renders.
	if !st.LoadedAddr(env.File, addr) {
		st.SetSpan(env.Svc.DecodeSpanAt(addr, env.Svc.LeadBytes()))
	}
	st.Cur = st.IndexAtOrAfter(addr)
	st.ScrollContext(env, 4, h)
}

// OpenSourceFile switches the source-first pane to file at the given 1-based
// line, clamped to the file's extent. Mode selection stays with the shell.
func (st *State) OpenSourceFile(env Env, file string, line, h int) bool {
	src := env.File.SourceLines(file)
	if src == nil {
		env.Host.SetStatus("source file not found: "+filepath.Base(file), true)
		return false
	}
	st.SrcFile = file
	st.SrcCodeLines = st.MappedLines(env.File, file)
	if line < 1 {
		line = 1
	}
	if line > len(src) {
		line = len(src)
	}
	st.SrcCur = line
	st.SrcTop = 0
	st.SyncSourceAsm(env, h)
	return true
}

// GotoMappedLine moves the cursor to the next/previous source line that has
// machine code mapped to it, skipping the shadowed (unmapped) lines.
func (st *State) GotoMappedLine(env Env, forward bool, h int) {
	n := len(env.File.SourceLines(st.SrcFile))
	if forward {
		for ln := st.SrcCur + 1; ln <= n; ln++ {
			if st.SrcCodeLines[ln] {
				st.SrcCur = ln
				st.SyncSourceAsm(env, h)
				return
			}
		}
	} else {
		for ln := st.SrcCur - 1; ln >= 1; ln-- {
			if st.SrcCodeLines[ln] {
				st.SrcCur = ln
				st.SyncSourceAsm(env, h)
				return
			}
		}
	}
	env.Host.SetStatus("no more mapped lines", false)
}

// EnsureSourceForCursor points the source pane at the line mapped from the
// disasm cursor, opening the mapped file if needed. In source-first mode the
// source cursor is authoritative — the asm pane follows it via SyncSourceAsm.
// Re-deriving SrcCur from the disasm cursor here would snap the cursor back
// whenever it moved onto an unmapped (shadow) line, which is why "up"
// sometimes appeared stuck.
func (st *State) EnsureSourceForCursor(f *binfile.File) bool {
	if st.SourceFirst && st.SrcFile != "" && f.SourceLines(st.SrcFile) != nil {
		return true
	}
	if len(st.Inst) == 0 || st.Cur < 0 || st.Cur >= len(st.Inst) {
		return false
	}
	file, line := f.LookupAddr(st.Inst[st.Cur].Addr)
	if file == "" || line == 0 || f.SourceLines(file) == nil {
		return false
	}
	if st.SrcFile != file {
		st.SrcFile = file
		st.SrcCodeLines = st.MappedLines(f, file)
	}
	st.SrcCur = line
	return true
}

// EnsureSourceBelowCursor opens the source mapped to the first instruction
// after the cursor — staying inside the containing function while it lasts —
// for when the cursor's own instruction carries no source mapping.
func (st *State) EnsureSourceBelowCursor(env Env, h int) bool {
	if len(st.Inst) == 0 || st.Cur < 0 || st.Cur >= len(st.Inst) {
		return false
	}
	start := st.Cur + 1
	if start >= len(st.Inst) {
		return false
	}
	if sym, ok := env.File.SymbolAt(st.Inst[st.Cur].Addr); ok && sym.Size > 0 {
		end := sym.Addr + sym.Size
		if st.selectSourceFromRange(env, start, func(addr uint64) bool { return addr < end }, h) {
			return true
		}
		for start < len(st.Inst) && st.Inst[start].Addr < end {
			start++
		}
	}
	return st.selectSourceFromRange(env, start, func(uint64) bool { return true }, h)
}

func (st *State) selectSourceFromRange(env Env, start int, inRange func(uint64) bool, h int) bool {
	for i := start; i < len(st.Inst); i++ {
		addr := st.Inst[i].Addr
		if !inRange(addr) {
			return false
		}
		file, line := env.File.LookupAddr(addr)
		if file == "" || line == 0 || env.File.SourceLines(file) == nil {
			continue
		}
		if st.SrcFile != file {
			st.SrcFile = file
			st.SrcCodeLines = st.MappedLines(env.File, file)
		}
		st.SrcCur = line
		st.SrcTop = 0
		st.SyncSourceAsm(env, h)
		return true
	}
	return false
}
