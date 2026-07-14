# exex

A fast terminal UI for exploring **ELF, Mach-O and PE** binaries — header,
sections, segments, symbols, disassembly, hex/raw bytes, strings, libraries,
relocations, syscall sites and DWARF source mapping in one keyboard- and
mouse-driven interface.

Its standout feature: when a binary has debug info (DWARF, or a Mach-O `.dSYM`),
exex shows the **original source side by side with the exact disassembly it maps
to** — navigable both ways, and entirely **static**: no debugger, no running
process, no decompiler.

```
exex [-debug PATH] [-s STRING] [-o [VIEW]] <binary> [goto]
```

![ExEx usage animation](/resources/exex.svg)

## Highlights

- **One explorer for three formats:** ELF, Mach-O, PE and universal/fat Mach-O slices.
- **Source ↔ disassembly:** original source beside machine code, from DWARF or a `.dSYM`.
- **Fast first look:** read-only, no project database, no debugger session.
- **Many views:** symbols, sections, segments, strings, relocations, libraries,
  syscall sites, CPU features, hex/raw bytes and disassembly.
- **Scriptable:** `-o` emits plain text for pipes and automation.
- **Text scripts too:** shell/Python/etc. open in a linked text viewer instead of
  failing as "not a binary".

See [how exex compares to other tools](#how-exex-compares-to-other-tools) for the
tradeoffs against binutils, debuggers and RE platforms.

## Install

```sh
brew install shellcell/tap/exex              # Homebrew
go install github.com/shellcell/exex@latest   # Go
```

Or download the asset for your OS/arch from [Releases](../../releases):

```sh
tar -xzf exex-<version>-<os>-<arch>.tar.gz
chmod +x exex && sudo mv exex /usr/local/bin/
shasum -a 256 -c checksums.txt        # optional
```

Or build from source:

```sh
make build       # -> ./exex
make test        # go test
make test-cross  # cross-compile and parse/disassemble readable targets; needs Go + Zig
```

### Man page and completions

A man page (`docs/exex.1`) and bash/zsh/fish completions (`completions/`) ship
with the source and release archives. Completions cover the flags, the `-o` view
names, and the `<binary>` argument — both files and commands on `$PATH`, so
`exex ls<Tab>` works.

```sh
make install-man           # -> $MANPREFIX/man1/exex.1   (sudo for a system prefix)
make install-completions   # -> bash/zsh/fish completion dirs (override *COMPDIR vars)
```

To install one by hand: `source completions/exex.bash`; copy `completions/_exex`
onto your zsh `$fpath` (before `compinit`); or copy `completions/exex.fish` to
`~/.config/fish/completions/`.

## Usage

```
exex [flags] <binary> [goto]
```

- `<binary>` — an ELF/Mach-O/PE file, or a command name on `$PATH` (`exex ls`
  opens `/bin/ls`).
- `goto` — optional address (`0x401000`) or symbol to jump to on open. A unique
  symbol jumps straight there; an ambiguous one opens Symbols filtered by it.

Flags are accepted in any position:

| Flag | Description |
|------|-------------|
| `-s STRING` | search printable strings; opens the match in Hex, or Strings filtered when several match |
| `-debug PATH` / `-d PATH` | external debug symbols (ELF `.debug` companion, or a Mach-O `.dSYM` bundle/file) |
| `-arch NAME` | which slice of a universal (fat) Mach-O to open (e.g. `x86_64`, `arm64`); defaults to the host arch. Info lists all slices; press `t` there to switch |
| `-o VIEW` | print a view to stdout and exit: `info`, `sections`, `segments`, `symbols`, `strings`, `libs`, `sources`, `relocs`, `syscalls`, `syscalls-all`, `syscalls-full`, `disasm`, `disasm-all` |
| `-o` (bare) | print the `goto` symbol/address's function disassembly and exit |

### Scripting with `-o`

`exex -o symbols ./bin`, `exex -o disasm ./bin | less`, `exex -o ./bin main`
(one function). `disasm` covers executable sections (like `objdump -d`),
`disasm-all` every section (like `objdump -D`). Output streams, so `| head`
returns immediately even on large binaries. `relocs` prints the relocation table
(like `readelf -r`).

The syscall views find each kernel-entry instruction (`syscall`/`svc`/`int
0x80`/`ecall`), recovering the call **number** from the immediate loaded into the
syscall-number register where possible, plus calls to vDSO helpers (`__vdso_*`):

- `syscalls` — the **distinct** calls the binary makes.
- `syscalls-all` — every site, with its address.
- `syscalls-full` — also scans directly linked libraries (a dynamically linked
  program often makes no *direct* syscalls — they live in libc), tagging each
  with its originating object and listing libraries it couldn't resolve.

### Keys

| Key | Action |
|-----|--------|
| `1`–`9` / `0` | switch view (Info, Sections, Symbols, Disasm, Hex, Raw, Strings, Libs, Sources · `0` Relocations) |
| `⇧h` / `⇧f` / `,` / `^o` | raw header overlay · CPU-feature scan · settings · back to the previous file |
| `↑/↓` `j/k`, `PgUp/PgDn`, `Home/End` | move / page (also `⌘↑`/`⌘↓`, `^A`/`^E` on macOS) |
| `/` | filter / search the current view |
| `Enter` | open / follow / jump |
| `g` | go to address or symbol |
| `[` / `]` | page up / down in list views; previous / next section (Hex/Raw) or symbol (Disasm) |
| `⇧[` / `⇧]` | previous / next non-zero byte (Hex/Raw) |
| `d` / `h` / `m` | go to the address under the cursor in the Disasm / Hex / Raw view |
| `s` / `r` | cycle sort field · reverse it (Sections, Symbols, Strings, Sources, Relocations; `r` reverses Libs by name) |
| `x` / `y` | Disasm: find references (xrefs) · list system calls (scoped to the function / whole binary / unique) |
| `^t` / `^s` / `^b` / `^f` / `^p` | column filters — Symbols: type / scope / bind · Sections: type (`^t`) / flags (`^f`) · Strings: section (`^s`) · Relocations: type (`^t`) / section (`^s`) · Libs/Sources: availability (`^p`) |
| `t` (or `Tab`) | toggle the view's mode — Symbols/Sources: **tree** ↔ flat list; Sections: sections ↔ segments; Libs: flat ↔ tree; Hex/Raw: ascii ↔ pointer decode; Info: fat-Mach-O arch slice (`Tab` is the source pane in Disasm) |
| `←`/`→` · `Enter` · `+`/`−` | tree: collapse / expand group (`←` on a leaf folds its branch) · expand/collapse all below · all |
| `e` / `.` | collapse long `(…)`/`<…>` argument & template lists to `...` — `e` all (also from Disasm/Hex/Raw), `.` current Symbols row |
| `⇧a` / `⇧s` / `⇧p` / `⇧c` | copy address / name / pointer (Hex/Raw) / function disassembly (Disasm) |
| `⇧l` | copy the whole current row (all columns) |
| `w` | toggle long-line wrap |
| `Tab` / `⇧Tab` | show-hide / swap the disasm source pane |
| `?` | full key reference · `q` quit |

Keys are rebindable. The mouse wheel scrolls, click selects, and double-click
follows in the disasm view.

## Configuration

Config is optional YAML at `$XDG_CONFIG_HOME/exex/config.yaml` (or
`$HOME/.config/exex/config.yaml` if `XDG_CONFIG_HOME` is unset). Every field is
optional — unset entries keep their defaults. You can:

- pick a built-in **theme**: `theme: nord | dark | solarized-dark | solarized-light`,
- override individual **colours** under `colors:` (instruction classes, address
  links, tables, source/asm highlight, hex byte ramp, paths, …) — a `#RRGGBB`
  string or an ANSI-256 index (e.g. `"203"`),
- rebind top-level **keys**,
- set **behaviour**: default view, default wrap, disasm landing target, decode
  window size.

[`docs/config.example.yaml`](docs/config.example.yaml) has the full annotated schema.

## How exex compares to other tools

exex deliberately overlaps with the classic binary tools: it rolls what you'd
normally get from several one-shot commands into one interactive, multi-format
TUI — and can still emit their plain text for scripts via `-o`.

### Classic CLI tools

| Tool | What it does | In exex |
|------|--------------|---------|
| `readelf` | dump header, sections, program headers, symbols, dynamic info, DWARF | Info / Sections / Segments / Symbols / Libs views; `-o info\|sections\|segments\|symbols\|libs`. (`readelf` is ELF-only; exex also reads Mach-O & PE) |
| `objdump -d` / `-D` | disassemble executable (or all) sections | Disasm view (navigation, xrefs, source mapping); `-o disasm` / `-o disasm-all` for the objdump-style listing |
| `nm` | list symbols | Symbols view (filter, sort by name/addr/size, scope, type/bind); `-o symbols` |
| `c++filt` | demangle mangled names | inline everywhere (C++/Rust built in, Swift via `swift-demangle`) |
| `strings` | printable strings | Strings view (mapped to address & section); `-o strings`, or `-s` |
| `hexdump` / `xxd` / `od` | hex + ASCII dump | Hex view (virtual-address, section-aware, pointer decode, data inspector) and Raw view (file-offset) |
| `addr2line` | address → source `file:line` via DWARF | the source pane and Sources view — address ↔ source, both directions |
| `size` | section/segment sizes | Info, Sections and Segments views |
| `otool` (macOS) / `dumpbin` (Windows) | the Mach-O / PE counterparts of the above | one tool across ELF, Mach-O and PE |
| `dyld_info` (macOS) | a Mach-O's dyld metadata: bind/rebase & chained fixups, dylibs, exports | Relocs view decodes both bind/rebase opcodes and chained fixups into one table (`-o relocs`); Libs view lists dependent dylibs, including re-export/weak/upward variants |
| `dyld_shared_cache_util` (macOS) | list / extract dylibs from the dyld shared cache | opens a cache-resident system dylib straight from Libs (`o`), un-sharing it into a browsable Mach-O — no separate extraction step |
| `dyld_usage` (macOS) | live-trace a process's dyld / shared-cache activity | exex follows a binary's imports through the cache **statically** (e.g. libSystem → libsystem_kernel) to surface the transitive syscall surface (`-o syscalls-full`) — without running the program |

Those tools each answer one question, print, and exit. exex answers all of them
in one place and lets you **navigate** between them — follow a call into disasm,
jump from a symbol to its hex, map an address to its source line, list a
function's xrefs — and can still print like them for a pipe.

### Reverse-engineering platforms

**Binary Ninja, IDA Pro, Ghidra** are full RE/decompilation suites: recursive
analysis, decompilers, type systems, persistent databases, scripting, patching.
They are powerful and heavy. **exex sits at the opposite end**: a tiny,
read-only, instant terminal explorer with no project, no database, no
decompiler. Reach for them for deep analysis; reach for exex to *look at* a
binary in seconds.

**radare2 / rizin** are closest in spirit — terminal-based, scriptable,
multi-format — but they are broad frameworks (analysis, patching, debugging,
emulation) with a steep command language. exex is far narrower on purpose: a
discoverable, point-and-look explorer, not an analysis or patching framework.

### Source ↔ disassembly

exex shows original source beside the disassembly it maps to, navigable in both
directions, with carets marking which columns of a source line map to which
instructions. Other tools combine source and assembly, but differently:

| Tool | How | vs exex |
|------|-----|---------|
| `objdump -S` / `-dl` | interleaves DWARF source lines into the listing | same data, but a flat one-shot dump — no panes, no navigation, no column mapping |
| `gdb` (`layout split`), `lldb`, IDE disassembly windows | interactive source + asm, side by side | requires a **debug session** (a launched/attached process); exex needs only the file on disk |
| IDA Pro, Ghidra, Binary Ninja, Hopper, Cutter | disassembly next to **decompiler pseudocode** | reconstructed C, not your original source; DWARF used mostly for names/types |
| Compiler Explorer (godbolt.org) | colour-linked source ↔ asm | *compiles* source, rather than reading an existing binary's debug info |

So exex isn't trying to replace the binutils suite or a disassembler platform —
it's the fast first look: open any ELF/Mach-O/PE, read its layout and code,
follow references and source mappings interactively, and drop to plain text when
you need to script.

## Architecture

For contributors, [`docs/architecture.md`](docs/architecture.md) describes the
package layering (core `binfile`/`disasm`, domain services, the two frontends),
the TUI's view contract (`view.Context` / `view.Host`) and the rendering &
performance conventions, with diagrams.

## Acknowledgements

exex builds on the Go toolchain and standard library, plus:

- [Bubble Tea](https://github.com/charmbracelet/bubbletea), [Bubbles](https://github.com/charmbracelet/bubbles) and [Lip Gloss](https://github.com/charmbracelet/lipgloss) for the terminal UI foundation.
- [Chroma](https://github.com/alecthomas/chroma) for syntax highlighting.
- [`golang.org/x/arch`](https://pkg.go.dev/golang.org/x/arch) and [`golang.org/x/sys`](https://pkg.go.dev/golang.org/x/sys) for architecture decoders and system interfaces.
- [`github.com/ianlancetaylor/demangle`](https://pkg.go.dev/github.com/ianlancetaylor/demangle) for C++/Rust symbol demangling.
- [`github.com/atotto/clipboard`](https://github.com/atotto/clipboard) for clipboard integration.
- [`gopkg.in/yaml.v3`](https://pkg.go.dev/gopkg.in/yaml.v3) for configuration parsing.

See [`go.mod`](go.mod) for the full dependency list, including transitive packages.

ChatGPT was used as a development and documentation assistant.

## License

exex is released under the MIT License — see [LICENSE](LICENSE).
