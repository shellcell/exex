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
>
> **Update:** the per-column filters were later moved off `⌥<letter>` to **`^<letter>`**
> (`^t/^s/^b` symbols; `^t/^f` sections; `^s` strings; `^t/^s` relocations; `^p`
> libs/sources availability) — gnome-terminal binds `Alt+letter` to its menu
> mnemonics and swallows the keys, so Ctrl chords are now used identically on
> macOS and Linux. Only `⌥↑/⌥↓` survive as page-nav aliases (no menu conflict).

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

## ✅ 30. Extract syscalls

Extract all the syscalls used in binary

## ✅ 31. Extract pathes

Extract all the pathes from strings

## ✅ 32. Search

0x000106b6 should match with $0x106b6

## 33. dyld shared cache resolution  ✅ (done)

On macOS the system libraries (libsystem_kernel, libc++, the frameworks, the
Swift runtime, …) are not standalone files — they live in the dyld shared cache
(`/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/`, split into a main
cache plus `.1/.2/…` sub-caches). Today that means:

- ✅ **Syscalls (#30):** `-o syscalls-full` now extracts the cache-resident
  system libraries and follows the `LC_REEXPORT_DYLIB` chain
  (app → libSystem.B → libsystem_kernel), giving macOS binaries a real syscall
  surface (~460 distinct syscalls for a typical binary).
- ✅ **Libs (#29):** a `·cache` library opens as primary — extracted from the
  shared cache with a compact per-image __LINKEDIT (all symbols, ~hundreds of
  KB), fully browsable (sections/symbols/disasm).

Add a reader for the dyld shared cache format — parse its header, mappings (each
maps an address range to a file offset across the cache + sub-caches), and image
list (address → install path) — so a cache-resident dylib can be extracted (its
split segments stitched back via the mappings into a scannable Mach-O image).
Then:

Both delivered: `internal/dyldcache` (reader + `ExtractImage` un-sharer),
wired into `libopen.go` (open as primary) and `dump/syscalls.go` (transitive
cache-resident scan). Not attempted: reconstructing chained fixups for a cache
dylib (its relocs stay empty — the cache pre-applies them; see item #38 for the
on-disk Mach-O fixups decoder).

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

## ✅ 36. Find-anything quick jump

Broaden the goto modal (#…/`g`) beyond symbols + addresses to also rank sections
and strings, so one keystroke finds *any* named thing in the binary and jumps to
it — a single fuzzy "jump to anything" entry point.

## ✅ 37. Architecture cleanup (internal)

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

## 38. Mach-O dynamic fixups decoder (relocs)  ✅ (done)

The Relocations view was empty for essentially every real macOS binary: a linked
Mach-O carries its relocations not as the per-section relocs `debug/macho` parses
(those exist only in object files) but as dyld metadata, in one of two shapes —
`LC_DYLD_INFO(_ONLY)` compact bind/rebase opcode streams (the classic format, and
what the Go linker still emits) or `LC_DYLD_CHAINED_FIXUPS` in-place pointer
chains (the modern system-toolchain format, e.g. `/bin/ls`).

`internal/binfile/macho_fixups.go` decodes both into the neutral `Reloc` model:
binds become named entries resolved to their imported symbol + library (the
useful part — the image's import table), rebases record the slid pointer slots;
arm64e authenticated pointers surface as `AUTH_BIND` / `AUTH_REBASE`. Wired into
the lazy `relocBuild` hook so it costs nothing until the relocs view/`-o relocs`
is opened, and `machoHasRelocs` reports true off a cheap load-command scan.
Validated byte-for-byte against the system `dyld_info` (exact bind/rebase counts
and addresses for `/bin/ls` chained and a Go binary's DYLD_INFO). Note: dylibs
un-shared from the dyld cache still show empty relocs — the cache already applied
the fixups and un-sharing drops the (now meaningless) fixup commands.

Follow-ups landed with it: reloc bind targets are now demangled (Itanium/Rust
in-process, in both the TUI and `-o relocs`), and the relocs view gained the
shared row-navigation surface — `d`/`h`/`m` jump to the patched address in
disasm/hex/raw, `e` toggles argument abbreviation, double-click follows to hex,
and the text filter matches the demangled spelling.

## 39. Performance / footprint review  (plan)

A whole-binary pass on size, startup, CPU and RAM — recording where things stand
and where the real (vs imagined) headroom is, so future work targets measured
costs, not guesses. Baseline (arm64, Go 1.26, this tree):

- **Binary size** — 15.2 MB dev build; **11.5 MB stripped** (`-s -w`, the default
  release) ; **9.9 MB lite** (drops Chroma). Composition: runtime ~4 MB, reflection
  type metadata ~3.7 MB, `golang.org/x/arch` disassembler 1.25 MB, Chroma +
  regexp2 ~0.8 MB (already `lite`-gated), `uax29` 0.32 MB (terminal width, via
  `x/ansi`/`go-runewidth` — unavoidable), `yaml.v3` 0.32 MB (config), exex ~1 MB.
- **Startup** — ~1 ms warm (`ui.New` 455 KB alloc); parse (cold open) ~7 ms.
- **RAM** — retained-after-load heap **2.9 MB** (excellent); peak-heap-in-use
  ~138 MB and peak RSS ~204 MB, but that is the perfreport *render/decode
  benchmark* churning, not steady state.

So the headline levers (strip, Chroma-gating) are **already done**. Genuine,
ranked opportunities remaining:

1. **Render/decode allocation churn** — ✅ *investigated + first win landed.*
   Profiling (memprofile of the disasm render bench) showed the render path is
   already well-cached (asm-text cache, height cache, `viewCache`): the big
   allocations — `decodeAcross` (~840 MB) and DWARF `loadLines` (~176 MB) — are
   **one-time setup** the profile captures alongside the render, GC-reclaimed, not
   steady-state churn (retained heap stays 2.9 MB). The one demonstrable waste:
   `disasmInstVisualHeight` rendered the *full styled row* (`disasmInstRows`) just
   to count its lines, on every height cache-miss (first paint, every resize/wrap
   toggle, over the whole instruction list). Added `disasmInstRowCount` — the same
   row-splitting decisions with none of the string building — pinned to the real
   renderer by `TestDisasmInstRowCountMatches`. Measured: the height pass over 1024
   instructions dropped **5.53 ms → 0.30 ms, 1.42 MB → 45 KB, 23.9k → 2.8k allocs**
   (~18×), and the warm disasm frame fell ~380 KB → ~339 KB. The remaining 138 MB
   perfreport peak is the one-time `disasm-all` full-image decode (~162 MB) — the
   disassembler stringifying every instruction once — which is inherent to that
   view and not reduced here.
2. **Per-host-arch disasm build** — `x/arch` (1.25 MB) links every arch; an
   opt-in single-arch tag (host only) would shave ~0.5–0.8 MB for distro builds.
   Marginal, and complicates the matrix — low priority.
3. **`yaml.v3` → a smaller config decoder** (~0.3 MB). Config is user-facing, so
   low ROI and some churn risk; only if a hand-rolled reader is otherwise wanted.
4. **Reflection type metadata (~3.7 MB)** is the largest reducible block but the
   hardest — it tracks the reflect/encoding usage across deps; not worth chasing
   without a specific offender identified by `-gcflags=-m`/deadcode analysis.

Not a concern (measured, left alone): startup time, retained heap, `uax29`.

## 40. Cross-view "open caret in…" modal  ✅ (done)

The per-view `d`/`h`/`m` jumps (go to the caret address in disasm/hex/raw) only
covered three destinations and had to be memorised. **Space** (or `>`) now opens a
single discoverable menu from any address-bearing view (disasm, hex, raw,
symbols, sections, strings, relocs): it takes the address under the cursor and
lists every *other* view as a destination. A header shows what the address *is* —
its covering symbol (demangled, with offset) and section, and, when the
pointer-sized word there is itself a mapped address (a GOT slot, a vtable entry),
where it points (`→ 0x… _malloc`). Each row previews its landing — the covering
function (Disasm), section + address (Hex), file offset (Raw), the symbol
(Symbols), the section (Sections), the quoted text of a string at that address
(Strings), or the relocation type + bound symbol (Relocs). Rows carry the target
view's number key as a badge, usable as a shortcut (press `5` → Hex); disabled
rows (e.g. Disasm on a data address, no string here) are dimmed with the reason.
Enter/click/digit navigates; the selection skips unreachable rows. The caret
carries a virtual address *and/or* a file offset, so an offset-only position (a
string in an unmapped section, a raw byte in a file header) still opens in Raw —
and in Strings, matched by offset — while the address-keyed targets dim with "no
virtual address"; the address views light up whenever the offset resolves to one.
The **Info** view has no cursor, so the modal opens on the binary's natural start:
its entry point, else the lowest mapped address. **Libs** and **Sources** are
deliberately excluded — their rows are a library/source path, not an address, and
each already has its full targeted-jump surface on Enter (imported symbols /
source pane) and `o` (open as primary). Shell-side (`internal/ui/jumpto.go`),
reusing the existing jump actions plus small
`CaretAddr`/`SelectByAddr`/`SelectByOffset`/`StringAt`/`StringAtOffset` accessors
on each view; the `d`/`h`/`m` shortcuts stay as fast paths.
