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

## 2. Cross-references (xrefs) ✅ done

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

## 8. Command line options

 - ✅ address or string to pass to goto as third arg (`exex <binary> <addr|symbol>`)
 - ✅ option to provide path to debug symbols file / directory (`-debug`/`-d PATH`,
   ELF .debug companion or Mach-O .dSYM bundle/file)

## 9. Sources view

- ✅ New view shouwing list of source files used in this binary (based on
dwarf / dSYM info).
- ✅ Source files can be open - then go to disasm view (source first
mode with mapping to disasm pane on the right).
- ✅ Sources should be searchable in current source file
- Sources should be searchable across all the sources.
- ✅ Color based on similar prefixes of source pathes with similar colors (the whole path colored in same color though).
- Trim length in the middle if too long.
- ✅ On c copy path.
- Show sources belonging to project itself (not external) on top.
- ✅ Opening of some source file should lead to disasm view with source first mode.
- ✅ w button should wrap lines. cmd up / cmd down on macos should act as page up / page down.
- ✅ Keys configurable in config.

## 10. Disasm view

- ✅ There should be an option to switch panes from disasm first to source fisrt.
- ✅ If source first is selected navigation should be in source file, not in disasm.
- ✅ Same about search. In source first view only line numbers should be dimmed for
not mapped lines, not the whole lines of source code. Same for disasm first view.
- ✅ Also for disasm pane in source first view - not mapped lines of disasm should be dimmed (only address).
- ✅ Show annotation after assembly, now inside.
- ✅ Add annotations also if address is some object symbol - for move instructions etc.
- ✅ Highlight addresses for current symbol on the left to wich there is a jump with same color as address in jump
instruction.
- ✅ Increase history to 30 items.
- ✅ There should be an option to turn of the source pane.
- ✅ w button should wrap long lines.
- ✅ cmd up / cmd down on macos should act as page up / page down.
- ✅ Keys configurable in config.
- ✅ mouse scroll if mouse position is above right pane should scroll the right pane

## 11. Libs view

- ✅ Color pathes by prefix - similar prefix means similar color. The whole path should
be colored in same color.
- ✅ There should be an option to copy lib path on c button.
- ✅ There should be and option go open lib - this should show symbols from this lib used.
- ✅ There should be and option to open this lib as primary (maybe o button) - to
info, sections, symbols, disasm etc. Now there is an error "library path is not directly
openable" - resolution of the path is needed.
- ✅ Assembly column should always fit and never be wrapped.
- ✅ Selection on cursor should be for only current line and only untill assembly - annotation should be not colored,
empty space on next line as well.
- ✅ If no sources available source pane should not be open.
- ✅ Navigation for source-first view is now broken - sometimes it is not possible to go up.
- ✅ w button should wrap lines. cmd up / cmd down on macos should act as page up / page down.
- ✅ Keys configurable in config.

## 12. Symbols view.

- ✅ There should be an option to filter by type.
- ✅ Address should be gray.
- ✅ w button should wrap lines. cmd up / cmd down on macos should act as page up / page down.
- ✅ Keys configurable in config.

## 13. Hex view.

- ✅ Show symbols annotation on the right.
- ✅ Split with sections (now works only partially).
- ✅ d should lead to diasm if this address is executable.
- ✅ w button should wrap lines. cmd up / cmd down on macos should act as page up / page down.
- ✅ Keys configurable in config.
- ✅ shift+[ and shift+] should go to next / prev section. Section separator should be shown on
top of the viewport.
- ✅ The whole section should be below section separator. Even if address is not aligned (make offset on
the line in this case)

## 14. Raw view

- ✅ Split with sections if makes sense.
- ✅ cmd up / cmd down on macos should act as page up / page down.
- ✅ Keys configurable in config.
- ✅ shift+[ and shift+] should go to next / prev section. Section separator should be shown on
top of the viewport.
- ✅ The whole section should be below section separator. Even if address is not aligned (make offset on
the line in this case)

## 15. Sections view

- ✅ Keep numeration gray. Color names and types based on type.
- ✅ Enter should always lead to hex view. d button should lead to disasm view if executable.
- ✅ w button should wrap lines. cmd up / cmd down on macos should act as page up / page down.
- ✅ Keys configurable in config.

## 16. Info view

- ✅ Polish it: grouped section headers (Overview / Hardening / Dynamic linking
/ Toolchain) and checksec-style colouring of the hardening block.
- ✅ Centralize: rendered as a centred, bordered panel.
- ✅ Add more fields: code size as a share of the file.

## 17. String view

- ✅ Offset and address should be gray. String should be always white.
- ✅ w button should wrap lines. cmd up / cmd down on macos should act as page up / page down.
- ✅ Keys configurable in config.

## 18. Search popup (disasm view, hex view, raw view, strings view)

- ✅ There should be clear switch for mode and direction clickable with mouse.
- ✅ Input field should be emptied on open.

## 19. Help popup

- ✅ Fix layout - alignment is broken now. Colors are also bad.
- ✅ Help lists the missing right-pane scroll, section jump, search, and source controls.

## 20. Goto popup

- ✅ Make wider in case of long names in results.
- ✅ If address is not in mapped section go to raw view.

## 21. Themes

- ✅ Implement different themes. Built-in presets selectable via `theme:`
(dark, nord, solarized-dark, solarized-light).
- ✅ All the colors used should be configurable through theme and config -
including hex coloring, highlight of source position etc.
- all the keys / keybindings used should be configurable in config.

## 22. Hex colouring modes.

Different modes how to color hex

## ✅ 23. Segments / load-commands view  (new)

**Goal.** A view listing the program's memory map at the segment level — ELF
program headers (`PT_LOAD`, `PT_DYNAMIC`, `PT_GNU_STACK`, …) and Mach-O load
commands / segments — with permissions (r/w/x), virtual address range, file
offset + size, and alignment. The Info view only *counts* these today
(`info.Segments`); this would show them, explaining the layout the Hex view
stitches together from sections.

**Work.** Retain segment data in the neutral model (currently `ef.Progs` /
`mf.Loads` are read once and discarded). Add a `[]Segment` to `binfile.File`
populated by each loader, a `modeSegments` view + tab, and a table renderer
reusing the existing list/scroll/colour machinery.

## ✅ 24. Copy / export a whole function's disassembly  (new)

**Goal.** The disasm view can copy a single address/symbol; add copying (or
writing to a file) the *entire* current function — the natural unit for bug
reports, diffs, and pasting into an LLM. The range is already known from the
symbol's `Addr`/`Size`.

**Work.** A key in the disasm view that gathers the instructions within the
current symbol's extent (decoding the window if needed), renders them as plain
`addr: bytes  text` lines (ANSI-stripped), and either puts them on the clipboard
or writes `=<symbol>.asm`. Consider a second key for "copy as the rendered,
coloured view".

## ✅ 25. PE import symbols (IAT)  (new)

**Goal.** Bring PE up to ELF/Mach-O parity. ELF and Mach-O synthesise named
symbols for imports (PLT/GOT / stubs) so call targets resolve and the Symbols
view's scope/library filters work; PE does not, so `call [IAT]` stays a bare
address and the `scope:imported` filter is empty on PE.

**Work.** Parse the PE import directory (and delay-import directory): for each
imported function, synthesise a `Symbol` at its IAT slot address with
`Library` set to the owning DLL and `Kind = SymObject` (or `SymFunc` for the
thunk), mirroring `appendELFImportSymbols` / `machoImportSymbols`.

## 26. Sortings / filters for strings view, also one-page view

view all the strings in single page one after other with middle dot separator

## 27. Keyboard / Mouse actions

> **Status: done.** The breaking keymap pass is implemented and exhaustively
> tested (one driving test per binding per view, plus a config-override test):
> copy moved to `⇧a/⇧s/⇧p/⇧c` and copy-whole-row `⇧l` (freeing `a/s`); sort-cycle
> on `s` (was `o`) with reverse `r`; per-column filters on `⌥<letter>`
> (`⌥t/⌥s/⌥b` symbols; `⌥t/⌥f` sections type/flags; `⌥s` strings-section; `⌥a`
> libs/sources availability); tree nav via arrows only (freed `h/l`); cross-view
> jumps `d/h/m` (disasm/hex/raw); hex/raw pointer toggle on `t`; `t` switches the
> fat-Mach-O arch in Info (was `a`); `/` search and `Esc`-clears-everything in all
> five list views (Sections, Symbols, Strings, Libs, Sources); `o` opens a source
> in the disasm source-first view. Page/top/bottom chords match the spec
> (`ctrl/⌥+↑↓` page, `cmd+↑↓` / `ctrl+a,e` top/bottom). The raw-jump uses `m` (not
> `r`, which stays reverse-sort). Every binding is rebindable via `config.Keys`.
> `⌥`/`option` chords are decoded from the key's modifier bits (not its rendered
> string), so they fire however the terminal delivers Option — as Alt, as Alt with
> a composed character (macOS Kitty protocol, e.g. ⌥t → "†"), or as Super/Cmd;
> shift+letter chords arrive as the uppercase letter. All five list views sort
> with `s`/`r` (Sections index/name/addr/size; Symbols name/addr/size; Strings
> offset/address/string; Sources project/name; Libs name) — the full spec below is
> implemented.

== GLOBAL ==

g - goto
q, ctrl+c - quit
w - wrap lines
? - help
, - settings

== CHANGE VIEW ==

1..9 - go to view (tab) by number
d - go to caret addres in disasm view from section / symbol / hex / raw / string
h - go to caret addres in hex view from section / symbol / disasm / string
m - go to caret addres in raw view from section / symbol / disasm / hex / string
    (m, not r: r is reverse-sort in the list views)

== SWITCH MODE ==

t - toggle 
    arches for fat mach-o in info
    sections / segments in sections
    tree / flat in symbols, libs, sources
    ascii / pointers mode in hex, raw
e - collapse / expand args in symbol names in symbols, disasm, hex, raw
tab - turn on / of sources pane in disasm view
shift+tab - switch disasm first / sources first modes in disasm view
o - open lib as primary, open source in disasm source-first view

== NAVIGATION ==

up/down j/k - move line in sections, symbols, disasm, hex, raw, strings, libs, sources
ctrl+up, option+up, pageup - page up in sections, symbols, disasm, hex, raw, strings, libs, sources
ctrl+down, option+down, pagedown - page down in sections, symbols, disasm, hex, raw, strings, libs, sources
home, ctrl+a, cmd+up - go to top in sections, symbols, disasm, hex, raw, strings, libs, sources
end, ctrl+e, cmd+down - got to botton in sections, symbols, disasm, hex, raw, strings, libs, sources
[] -  page down / up in sections, symbols, strings, libs, sources
      next / prev symbol in disasm
      next / prev mapped in source-first view disasm
      next / prev section in hex, raw
shift+[, shift+] - next / prev not empty in hex and raw

== COPY ==

shift+a - copy address in sections, symbols, disasm, hex, raw, strings
shift+s - copy
          section / segment name in sections
          symbol name in symbols, disasm, hex, raw
          string in strings
          library in libs
          path in sources
shift+p - copy pointer in hex, raw view
shift+c - copy symbol (instructions) in disasm view
shift+l - copy whole current row (every column) in sections, segments, symbols,
          disasm, hex, raw, strings, libs, sources

Note: shift+letter chords are delivered by terminals as the uppercase letter
(e.g. shift+a == "A"), which is what the handlers match.

Every binding above is rebindable in config (config.Keys / config.yaml): each
action has a key (copy_address, copy_line, sort, sort_reverse, filter_scope,
filter_bind, filter_section, filter_avail, jump_hex, jump_raw, toggle_mode,
abbrev_args, inspector, xref, open_primary, …). A configured key is added
alongside the built-in default.

== SEARCH MODAL == (disasm, hex, raw)

/ - open search modal
n, N - next / prev occurence in disasm, hex, raw

== SEARCH / FILTER / SORT LISTS == (symbols, sections, strings, libs, sources)

esc - clear search requests, search field and all filters

= search =

/ - search in sections, symbols, strings, libs, sources (think about regexp support)

= filter =

alt+[first letter of column title] / option+[first letter of column title] - 
    switch filter for this column (use option+s for scope in symbols)

sections: by type, flags
symbols: by scope, bind, type
strings: by section
libs: by availability: present on disk / in dyld cache / all
sources: by availability: present / missing / all

= sort =

s - switch sorted by (address, name, size, ...)
r - reverse current sorting in sections, symbols, strings, libs, sources

sections: name, address, size
symbols: name, address, size
strings: offset, address, string
libs: by name
sources: by name

== TREE == (symbols, libs, sources)

right - expand node and move caret to first child
left - collaps parent node
enter - expand all below
+ / - - expand / collapse all

mouse click - expand node (without moving caret to child)
mouse double click - expand all below

== INFO ==

enter / mouse double click - open entry in disasm or hex if not mapped

== SECTIONS ==

enter / mouse double click - open in hex / raw

== SYMBOLS ==

enter / mouse double click on symbol - open in disasm / hex

== DISASM ==

right / left - history forwand / back
enter / mouse double click - follow address
x - find xrefs
shift+up / shift+down - scroll right pane

== HEX / RAW ==

enter / mouse double click - follow pointer
i - data inspector

== STRINGS ==

enter / mouse double click - open in raw

== LIBS == 

enter / mouse double click - open imported symbols (symbols view)

== SOURCES ==

enter / mouse double click - open source file i disasm source-first view


## ✅ 28. Do not use bold font in symbols

Symbols are no longer bold: dropped the global-symbol bold in `styleForSymbol`
(it made most of the table heavy) and the bold on `symbolNameStyle` (disasm
labels). Weak symbols stay italic.

## ✅ 29. Pathes libs presence / openability

Sources and Libs now mark availability and filter on it (`v` cycles the filter):
- **Sources:** files not present on disk are dimmed; `v` cycles all → present →
  missing (`SourceExists` does cheap cached stat resolution).
- **Libs:** libraries served from the dyld shared cache (`·cache`) or not found
  (`·missing`) are dimmed and tagged; on-disk (openable) libs render normally;
  `v` cycles all → on-disk → in-cache (`libAvail` via `explorer.ResolveLibPath`
  / `IsDyldSharedCacheLib`).

## 30. Extract syscalls

Extract all the syscalls used in binary

## 31. Extract pathes

Extract all the pathes from strings

## 32. Search

0x000106b6 should match with $0x106b6

## 33. dyld shared cache resolution

On macOS the system libraries (libsystem_kernel, libc++, the frameworks, the
Swift runtime, …) are not standalone files — they live in the dyld shared cache
(`/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/`, split into a main
cache plus `.1/.2/…` sub-caches). Today that means:

- **Syscalls (#30):** `-o syscalls-full` can't scan the libraries that actually
  contain the `svc` instructions (the app's own code makes no direct syscalls),
  so macOS apps report nothing. The unresolved libraries are currently collapsed
  into a single "in the dyld shared cache — can't be scanned" note.
- **Libs (#29):** cache-resident libraries are tagged `·cache` and can't be
  opened.

Add a reader for the dyld shared cache format — parse its header, mappings (each
maps an address range to a file offset across the cache + sub-caches), and image
list (address → install path) — so a cache-resident dylib can be extracted (its
split segments stitched back via the mappings into a scannable Mach-O image).
Then:

- resolve cache-resident lib paths for `syscalls-full` and scan their `svc`
  sites (giving macOS a real syscall surface);
- let the Libs view open a `·cache` library as primary (its symbols/disasm).

## 34. CPU-feature detection  ✅ (done)

Scan the decoded instruction stream — reusing the syscall scan's infrastructure
(windowed `decodeAcross` over the exec image, parallel, cancellable) — and
classify mnemonics into feature families, so a user can see *what CPU the binary
needs to run*:

- **x86/64:** SSE, SSE2, SSE3/SSSE3, SSE4.1/4.2, AVX/AVX2/AVX-512 (VEX/EVEX
  `v`-prefixed), FMA, BMI1/2, AES, POPCNT, RDRAND, …
- **arm64:** NEON/ASIMD, crypto (AES/SHA), CRC32, LSE atomics, SVE/SVE2,
  pointer-auth, FP16, …

Output the set used and the implied baseline (e.g. x86-64-v3). A sibling to the
syscalls feature: same scan, a per-arch mnemonic→feature table, a modal in the
disasm view plus an `-o cpu-features` dump.

## 35. Requirements panel  ✅ (done)

Consolidate the scattered "what it takes to run this" facts into one block in the
Info view: arch + bits + endianness · OS/ABI (ELF `OSABI`; Mach-O — decode
`LC_BUILD_VERSION` / `LC_VERSION_MIN_*` into the min macOS/iOS/… version, today
only counted) · static/dynamic/PIE · interpreter · needed-library count · CPU
baseline (from #34).

## 36. Find-anything quick jump

Broaden the goto modal (#…/`g`) beyond symbols + addresses to also rank sections
and strings, so one keystroke finds *any* named thing in the binary and jumps to
it — a single fuzzy "jump to anything" entry point.

## 37. Architecture cleanup (internal)

Reduce duplication and the cache-invalidation bug surface in `internal/ui`:

- **`listState[T]` generic** for the five list views (sections, symbols, strings,
  libs, sources) — own the filter text, sort key + direction, cursor/top,
  filtered-index slice and row cache once, with `match`/`less`/`row` hooks.
  Migrate one view at a time. (~1k LOC, fewer drift bugs.)
- **Fold per-view row/height caches** into that generic so invalidation happens
  in one place (filter/sort/width change), shrinking the ~13-cache surface.
- **Shared modal-list helper** (sibling to `listGeometry`) to dedupe
  xref/goto/settings and give xref the syscall modal's filter/sort/colour.
- **UX consistency pass**: a uniform address vocabulary (`synthetic` / `load`
  (LMA) / physical) across disasm/hex/sections/Info, and group the `?` help by
  the same role order as the footer hints.
