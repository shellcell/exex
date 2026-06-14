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

## 3. PE/COFF support  ✅ done

`internal/binfile/pe.go` via `debug/pe`: sections, symbols (COFF Value resolved
to section-relative VAs), arch/entry, PIE/NX from DllCharacteristics, mapped onto
the neutral model. A tab chip now shows the detected format (ELF/Mach-O/PE).

## 4. Progressive / background disasm decode  ✅ done

The first disasm open decodes the whole executable image in a background
`tea.Cmd`, showing "decoding instructions…" until it lands (cursor then jumps to
the entry). Jumps (goto/follow) still decode synchronously since they target a
specific address.

## 5. Search  ✅ done

In-view search (`/`): hex-byte / "text" / `0x…` patterns in hex & raw, instruction
text + symbol names in disasm, with `n` / `N` to repeat. The goto popup also gained
a live, selectable result list that updates as you type.

## 6. Refactors / hardening

- ✅ **Split `app.go`**: Sections/Symbols/Info live in their own view_*.go files.
- ✅ **Centralized hex row layout** (`hexBodyStart`/`hexColumnToByte` in
  view_hex.go, used by both the renderer and click hit-testing).
- **Unit tests for pure logic:** `image.go` (`AddrAt`/`PosForAddr` across region
  boundaries and gaps) — still worth adding.

## 7. Smaller polish  ✅ done

- ✅ Help overlay (`?`) listing all keys; footers trimmed to essentials.
- ✅ `[`/`]` and copy keys configurable (`keys.next`/`prev`/`copy_*`).
- ✅ ELF split-debug via `.gnu_debuglink` sidecars, mirroring macOS `.dSYM`.
- ✅ Swift demangling via `xcrun swift-demangle` (batched, best-effort).
- ✅ Wheel scrolls 3 lines/notch.
- ✅ Tab bar shows a format chip (ELF/Mach-O/PE) so it's honest about scope.

---

**Suggested order:** **1 (stack view)** and **2 (xrefs)** first — highest
exploration value and they build on what's already decoded — then **3 (PE)**,
with **6 (refactors/tests)** folded in alongside.
