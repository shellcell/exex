A fast terminal UI for exploring ELF, Mach-O and PE binaries: headers, sections,
segments, symbols, disassembly, hex/raw bytes, strings, libraries, relocations,
syscall sites and DWARF-driven source mapping.

When debug info is present, exex can show the original source side by side with
the disassembly it maps to, without launching a debugger or creating a project
database.

### Install with Homebrew

```sh
brew install shellcell/tap/exex
```

### Install from this release

Download the archive for your OS/arch from the assets below.

```sh
tar -xzf exex-<version>-<os>-<arch>.tar.gz   # add -lite for the small build
chmod +x exex
sudo mv exex /usr/local/bin/

# optional: verify downloaded assets
shasum -a 256 -c checksums.txt
```

### Which build do I want?

| Build | Size | Syntax highlighting |
|-------|------|---------------------|
| **full** (`exex-…-<os>-<arch>.tar.gz`) | larger | Chroma — full multi-language source + asm highlighting |
| **lite** (`exex-…-<os>-<arch>-lite.tar.gz`) | smaller | built-in minimal highlighter |

Everything else is identical, and both honour the same themes/colours. Exact archive sizes vary by platform and Go/dependency versions. Pick **lite** for the smaller binary, **full** for the richest colouring.

### Usage

```
exex [-debug PATH] [-s STRING] [-o [VIEW]] <binary> [goto]
```

Examples:

```sh
exex ls
exex ./app main
exex -o symbols ./app
exex -o disasm ./app | less
```

Config lives at `$XDG_CONFIG_HOME/exex/config.yaml` (or
`~/.config/exex/config.yaml`). The bundled `README.md`, `docs/exex.1` man page
and `docs/config.example.yaml` document the keys, flags and full colour/theme
schema.

Thanks to the authors and maintainers of exex's dependencies, including
[Bubble Tea](https://github.com/charmbracelet/bubbletea),
[Bubbles](https://github.com/charmbracelet/bubbles),
[Lip Gloss](https://github.com/charmbracelet/lipgloss),
[Chroma](https://github.com/alecthomas/chroma),
[`x/arch`](https://pkg.go.dev/golang.org/x/arch),
[`x/sys`](https://pkg.go.dev/golang.org/x/sys),
[`demangle`](https://pkg.go.dev/github.com/ianlancetaylor/demangle),
[`clipboard`](https://github.com/atotto/clipboard) and
[`yaml.v3`](https://pkg.go.dev/gopkg.in/yaml.v3). Thanks also to ChatGPT as a
development/documentation assistant.
