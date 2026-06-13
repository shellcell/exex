# Roadmap — next plan

Status of the just-finished batch (done): Mach-O `.dSYM` DWARF loading, C++/Rust
symbol demangling, the Strings view, lazy disasm decode, and double-click follow
in disasm. What follows is the next set of work, in priority order.

---

## 1. Stack-frame view of the current function  ⭐ (new)

**Goal.** A view that shows the stack-frame layout of whichever function the
disasm cursor is in, updating as the cursor moves between functions. Answers
"what does this function's frame look like — frame size, saved registers,
return address, locals, arguments, spill slots — and at what offsets?".

**Data sources, best → fallback:**
1. **DWARF (when present, incl. via `.dSYM`).** Walk `DW_TAG_subprogram` for the
   current function; read `DW_AT_frame_base`, then child `DW_TAG_variable` /
   `DW_TAG_formal_parameter` with `DW_AT_location` (`DW_OP_fbreg <off>`) to get
   **named** locals/params and their frame-relative offsets and (via type DIE)
   sizes. This is the richest output: real names + offsets + sizes.
2. **Unwind info.** macOS `__unwind_info` (compact unwind) and `__eh_frame` /
   ELF `.eh_frame` give the canonical frame: CFA rule, frame size, and
   saved-register locations per PC. Robust and present even when stripped.
3. **Prologue analysis (last resort).** Decode the function prologue we already
   have in `disasmInst`:
   - x86-64: `push %rbp; mov %rsp,%rbp; sub $N,%rsp`; `push %reg` → saved regs;
     `mov %reg,-off(%rbp)` → spill/local slots.
   - arm64: `stp x29,x30,[sp,#-N]!` / `sub sp,sp,#N`; `stp/str … ,[sp,#off]`.

**Model.** New package `internal/frame` (keep `binfile` lean): given a `*binfile.File`,
arch, and a function's address range, return a `Frame`:
```
type Slot struct { Offset int64; Size uint64; Name string; Kind SlotKind } // SavedFP, RetAddr, SavedReg, Param, Local, Spill, Pad
type Frame struct { FuncAddr uint64; Size uint64; CFAReg string; Slots []Slot; Source string /* dwarf|unwind|prologue */ }
```

**UI.** Add a `9·Stack` tab (or a toggle that turns the disasm source pane into
a stack pane). It reads `SymbolAt(disasmInst[disasmCur].Addr)` so it always
reflects the function under the cursor. Render a column table: offset (relative
to CFA, high→low), size, kind, name. Header shows frame size + CFA register +
which source produced it. Empty state when the cursor isn't in a known function.

**Tests.** `frame` decode tests with hand-assembled prologues per arch
(mirroring `disasm_test.go`); a DWARF-backed test using a `-g` ELF sample where
available.

**Effort:** medium-large. The prologue + unwind tiers are self-contained; the
DWARF tier is the most code but reuses the existing `*dwarf.Data`.

---

## 2. Cross-references (xrefs)

Accumulate branch/call targets during `ensureDisasm` (we already extract them in
`extractTargetAt`) into an `addr → []callerAddr` index. Show "referenced by" for
the symbol/instruction under the cursor and add an xref-jump key. Turns the tool
from a viewer into an explorer. **Effort:** medium.

## 3. PE/COFF support

Add `internal/binfile/pe.go` using stdlib `debug/pe`, mapping sections/symbols
onto the existing neutral model — rounds out ELF + Mach-O + PE. The abstraction
already exists, so this is mostly a loader + arch mapping. **Effort:** medium.

## 4. Progressive / background disasm decode

Lazy decode (done) fixed startup, but the first open of a huge `.text` still
blocks. Decode in a background `tea.Cmd` with a spinner, or decode incrementally
around the cursor. **Effort:** medium.

## 5. Search

In-view search: byte/string pattern in hex & raw, mnemonic/operand text in
disasm — complements `goto`. A `/`-style prompt reusing the goto modal plumbing.
**Effort:** small-medium.

## 6. Refactors / hardening

- **Split `app.go`** (~900 lines): move Sections/Symbols/Info into
  `view_sections.go` / `view_symbols.go` / `view_info.go` to match the existing
  per-view file layout.
- **Centralize hex row layout.** `clickByte` in `mouse.go` re-derives column
  maths owned by `renderHexRow`; factor the byte↔column mapping into one place
  so clicks can't silently drift if the format changes.
- **Unit tests for pure logic:** `image.go` (`AddrAt`/`PosForAddr` across region
  boundaries and gaps) and the hex click-column mapping — no binary needed.

## 7. Smaller polish

- Help overlay (`?`) listing all keys so footers can be trimmed.
- Make `[`/`]` and copy keys configurable (currently hardcoded per view).
- ELF split-debug: honour `.gnu_debuglink` / `.debug` sidecars, mirroring the
  macOS `.dSYM` support just added.
- Swift demangling fallback (`$s…` via `swift demangle`) — the Itanium/Rust
  demangler doesn't cover Swift.
- Wheel scrolls one line; 3 lines/notch feels more natural.
- Honest naming: the title bar still reads `elf-explorer` though it's now
  format-agnostic.

---

**Suggested order:** **1 (stack view)** and **2 (xrefs)** first — highest
exploration value and they build on what's already decoded — then **3 (PE)**,
with **6 (refactors/tests)** folded in alongside.
