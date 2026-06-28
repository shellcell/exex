# exex

A terminal UI for exploring **ELF, Mach-O and PE** binaries: file header, sections,
symbols, disassembly, hex/raw dumps, strings, dynamic libraries, and
DWARF-driven source mapping — all keyboard- and mouse-driven.

Its standout feature: when a binary has debug info (DWARF, or a Mach-O `.dSYM`),
exex shows the **original source side by side with the disassembly it maps to** —
interactive, navigable both ways, and entirely **static** (no debugger, no
decompiler). That specific combination is uncommon among binary tools — the
nearest analogues are `objdump -S` (same data, but flat text) and `gdb`'s
`layout split` (interactive, but needs a debug session). See
[How exex compares to other tools](#how-exex-compares-to-other-tools).

```
exex [-debug PATH] [-s STRING] [-o [VIEW]] <binary> [goto]
```
![ExEx usage animation](/resources/exex.svg)

## Full vs lite build

There are two builds. They are identical except for syntax highlighting:

| Build | Size (stripped) | Syntax highlighting |
|-------|-----------------|---------------------|
| **full** | ~11 MB | [Chroma](https://github.com/alecthomas/chroma) — full multi-language source highlighting and assembly highlighting |
| **lite** | ~7 MB | a small built-in highlighter (categorized source keywords/function names; categorized asm mnemonics plus registers / immediates / links) |

The lite build drops Chroma and its ~3 MB of embedded lexer/style data. Both
builds honour the same themes and `colors:` config; the built-in highlighter
follows your theme too.

Pick **lite** if you want the smaller binary, **full** for the richest colouring.

## Install

### From a release

Download the asset for your OS/arch from the
[Releases](../../releases) page — add `-lite` to the name for the small build.

```sh
# macOS / Linux
tar -xzf exex-<version>-<os>-<arch>.tar.gz        # or ...-<arch>-lite.tar.gz
chmod +x exex
sudo mv exex /usr/local/bin/

# verify (optional)
shasum -a 256 -c checksums.txt
```

### With `go install`

```sh
go install github.com/rabarbra/exex@latest          # full build
go install -tags lite github.com/rabarbra/exex@latest   # lite build
```

### Build from source

```sh
make build    # full  -> ./exex
make lite     # lite  -> ./exex
make test     # go test + lite vet
make test-cross # cross-compile with Go & Zig for every readable target, then parse/disassemble each (needs go + zig)
```

### Man page and shell completions

A man page (`docs/exex.1`) and bash/zsh/fish completions (`completions/`) ship with
the source and release archives. Completions complete the flags, the `-o` view
names, and the `<binary>` argument with both files and command names on `$PATH`
(so `exex ls<Tab>` works).

```sh
make install-man           # -> $MANPREFIX/man1/exex.1   (sudo for a system prefix)
make install-completions   # -> bash/zsh/fish completion dirs (override *COMPDIR vars)
man exex
```

Or install a single completion by hand:

```sh
# bash: source it, or drop it in a bash-completion dir
source completions/exex.bash
# zsh: put _exex on your $fpath (before compinit), e.g.
cp completions/_exex ~/.zsh/completions/_exex
# fish:
cp completions/exex.fish ~/.config/fish/completions/exex.fish
```

## Usage

```
exex [flags] <binary> [goto]
```

- `<binary>` — path to an ELF/Mach-O/PE file, or a command name found on `$PATH`
  (e.g. `exex ls` opens `/bin/ls`).
- `goto` — optional address (`0x401000`) or symbol name to jump to on open. A
  unique symbol jumps straight to it; an ambiguous one opens the Symbols view
  filtered by it.

Flags (accepted in any position):

| Flag | Description |
|------|-------------|
| `-s STRING` | search printable strings; opens the match in Hex, or the Strings view filtered when several match |
| `-debug PATH` / `-d PATH` | external debug-symbols file or directory (ELF `.debug` companion, or a Mach-O `.dSYM` bundle/file) |
| `-arch NAME` | for a universal (fat) Mach-O, which architecture slice to open (e.g. `x86_64`, `arm64`); defaults to the host arch. The Info view lists all slices; press `t` there to switch |
| `-o VIEW` | print a view to stdout and exit (non-interactive): `info`, `sections`, `segments`, `symbols`, `strings`, `libs`, `sources`, `relocs`, `syscalls`, `syscalls-all`, `syscalls-full`, `disasm`, `disasm-all` |
| `-o` (bare) | print the `goto` symbol/address's function disassembly to stdout and exit |

The `-o` modes make exex scriptable: `exex -o symbols ./bin`, `exex -o disasm ./bin | less`,
`exex -o ./bin main` (disassemble one function). `disasm` covers executable
sections (like `objdump -d`); `disasm-all` covers every section (like `objdump -D`).
Output streams, so `| head` returns immediately even on large binaries.

`relocs` prints the relocation table (like `readelf -r`). `syscalls` summarises
the **distinct** system calls the binary makes — each kernel-entry instruction
(`syscall`/`svc`/`int 0x80`/`ecall`), with the call **number** recovered from the
immediate loaded into the syscall-number register where possible, plus calls to
vDSO helpers (`__vdso_*`); `syscalls-all` lists every site with its address;
`syscalls-full` also scans the binary's directly linked libraries (a dynamically
linked program often makes no *direct* syscalls — they live in libc), tagging
each with the originating object and listing any libraries it couldn't resolve.

### Keys

| Key | Action |
|-----|--------|
| `1`–`9` | switch view (Info, Sections, Symbols, Disasm, Hex, Raw, Strings, Libs, Sources) |
| `↑/↓` `j/k`, `PgUp/PgDn`, `Home/End` | move / page (also `⌘↑`/`⌘↓`, `^A`/`^E` on macOS) |
| `/` | filter / search the current view |
| `Enter` | open / follow / jump |
| `g` | go to address or symbol |
| `[` / `]` | page up / down in list views; previous / next section (Hex/Raw) or symbol (Disasm) |
| `⇧[` / `⇧]` | previous / next non-zero byte (Hex/Raw) |
| `d` / `h` / `m` | go to the address under the cursor in the Disasm / Hex / Raw view |
| `s` / `r` | cycle sort field · reverse it (Sections, Symbols, Strings, Sources, Relocations; `r` reverses Libs by name) |
| `x` / `y` | Disasm: find references (xrefs) · list system calls (number + vDSO calls, scoped to the function / whole binary / unique) |
| `⌥t` / `⌥s` / `⌥b` | Symbols: filter by type / scope / bind · `⌥s` filters Strings by section · `⌥a` filters Libs/Sources by availability (needs Option-as-Alt in the terminal) |
| `t` (or `Tab`) | toggle the view's mode — Symbols/Sources: namespace/path **tree** ↔ flat list; Sections: sections ↔ segments ↔ **header**; Libs: flat ↔ tree ↔ **relocations**; Hex/Raw: ascii ↔ pointer decode; Info: fat-Mach-O arch slice (`Tab` is the source pane in Disasm) |
| `←`/`→` · `Enter` · `+`/`−` | tree: collapse / expand group (`←` on a leaf folds its branch) · expand/collapse all below · all (keys rebindable) |
| `e` / `.` | collapse long `(…)`/`<…>` argument & template lists to `...` (short ones like `<int>` kept) — `e` all (also from Disasm/Hex/Raw, abbreviating their symbol annotations), `.` current Symbols row |
| `⇧a` / `⇧s` / `⇧p` / `⇧c` | copy address / name (section, symbol, string, library, path) / pointer (Hex/Raw) / function disassembly (Disasm) |
| `⇧l` | copy the whole current row (all columns) — every row-based view |
| `w` | toggle long-line wrap |
| `Tab` / `⇧Tab` | show-hide / swap the disasm source pane |
| `?` | full key reference · `q` quit |

The mouse wheel scrolls, click selects, and double-click follows in the disasm view.

### Text scripts

If `<binary>` is not an ELF/Mach-O/PE file but a readable text file — a shell,
Python, or other script (still "executable") — exex opens it in a read-only,
syntax-highlighted text viewer instead of erroring. Two kinds of token are
underlined as openable links, and a menu (`Enter` / `o`) opens the one you pick:

- **filesystem paths** that resolve to a real file — absolute, `~`-relative, or
  relative to the script's own directory, and
- **commands found on `$PATH`** that the script invokes (its interpreters and
  tools, e.g. `bash`, `python3`, `grep`).

Opening a referenced binary switches to the full explorer; opening another text
file shows it in the viewer, with `Esc` to go back.

## Configuration

Config is optional YAML at:

```
$XDG_CONFIG_HOME/exex/config.yaml      # or, if XDG_CONFIG_HOME is unset:
$HOME/.config/exex/config.yaml
```

Every field is optional — unset entries keep their defaults, so you only specify
what you want to change. You can:

- pick a built-in **theme** preset: `theme: nord | dark | solarized-dark | solarized-light`,
- override any individual colour under `colors:` (instruction classes, address
  links, tables, source/asm highlight, the hex byte ramp, path colours, …),
- rebind top-level **keys**,
- set **behaviour** (default view, default wrap, disasm landing target, decode window size).

See [`docs/config.example.yaml`](docs/config.example.yaml) for the full annotated
schema. Colour values are a `#RRGGBB` hex string or an ANSI-256 index (e.g.
`"203"`).

## How exex compares to other tools

exex deliberately overlaps with a handful of classic binary tools: it rolls what
you'd normally get from several one-shot commands into one interactive,
multi-format (ELF/Mach-O/PE) TUI — and can still emit their plain-text output for
scripts via `-o`.

### Classic CLI tools

| Tool | What it does | In exex |
|------|--------------|---------|
| `readelf` | dump ELF header, sections, program headers (segments), symbols, dynamic info, DWARF | Info / Sections / Segments / Symbols / Libs views; `-o info\|sections\|segments\|symbols\|libs`. (`readelf` is ELF-only; exex also reads Mach-O & PE) |
| `objdump -d` / `-D` | disassemble executable (or all) sections | Disasm view (interactive: navigation, xrefs, source mapping); `-o disasm` / `-o disasm-all` for the objdump-style listing |
| `nm` | list symbols | Symbols view (filter, sort by name/addr/size, scope, type/bind); `-o symbols` |
| `c++filt` | demangle mangled names | done inline everywhere (C++/Rust built in, Swift via `swift-demangle`) |
| `strings` | printable strings | Strings view (mapped to address & section); `-o strings`, or the `-s` flag |
| `hexdump` / `xxd` / `od` | hex + ASCII dump | Hex view (virtual-address, section-aware, pointer decode, data inspector) and Raw view (file-offset) |
| `addr2line` | address → source `file:line` via DWARF | live in the source pane and Sources view — address ↔ source, both directions |
| `size` | section/segment sizes | Info, Sections and Segments views |
| `otool` (macOS) / `dumpbin` (Windows) | the Mach-O / PE counterparts of the above | a single tool across ELF, Mach-O and PE |

In one line: those tools each answer one question, print, and exit; exex answers
all of them in one place, lets you **navigate** between them (follow a call into
disasm, jump from a symbol to its hex, map an address to its source line, list a
function's cross-references), and can still print like them with `-o` for a pipe.

### Reverse-engineering platforms

**Binary Ninja, IDA Pro, Ghidra** are full RE/decompilation suites: recursive
analysis, decompilers, type systems, persistent project databases, scripting and
patching. They are powerful and heavy — large, GUI, often commercial. **exex sits
at the opposite end**: a tiny, read-only, instant terminal explorer with no
project, no database, and no decompiler. Reach for them for deep analysis; reach
for exex to *look at* a binary in seconds.

**radare2 / rizin** are the closest in spirit — terminal-based, scriptable,
multi-format — but they are broad frameworks (analysis, patching, debugging,
emulation) with a famously steep command language. exex is far narrower on
purpose: a focused, discoverable, point-and-look explorer, not an analysis or
patching framework.

### Source ↔ disassembly views

When a binary carries debug info (DWARF, or a Mach-O `.dSYM`), exex shows the
original source side by side with the disassembly it maps to — navigable in both
directions (source-first or disasm-first), with carets marking which columns of a
source line map to which instructions. A few other tools combine source and
assembly, but each does it differently:

| Tool | How | vs exex |
|------|-----|---------|
| `objdump -S` / `-dl` | interleaves source lines into the disassembly listing from DWARF | same data, but a flat one-shot text dump — no panes, no navigation, no column mapping |
| `gdb` (`layout split`, `disassemble /s`), `lldb`, IDE disassembly windows (Visual Studio, VS Code, CLion, Xcode) | interactive source + asm, side by side | requires a **debug session** (a launched/attached process); exex needs only the file on disk |
| IDA Pro, Ghidra, Binary Ninja, Hopper, Cutter | disassembly next to **decompiler pseudocode** | they show reconstructed C, not your original source files; DWARF is used mostly for names/types |
| Compiler Explorer (godbolt.org) | colour-linked source ↔ asm | works by *compiling* source, not by reading an existing binary's debug info |

So the specific combination exex offers — interactive, side-by-side, original
source from DWARF/`.dSYM`, on a static binary, no debugger and no decompiler — is
uncommon: the nearest analogues are `objdump -S` (same data, flat text) and gdb's
`layout split` (interactive, but needs a debug session).

So exex is not trying to replace a disassembler-platform or the binutils suite —
it's the fast first look: open any ELF/Mach-O/PE, read its layout and code, follow
references and source mappings interactively, and drop to plain text when you need
to script.

## License

exex is released under the MIT License — see [LICENSE](LICENSE).
