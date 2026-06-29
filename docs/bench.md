# Benchmarking & performance

exex is expected to stay responsive on large native binaries (hundreds of MB,
hundreds of thousands of symbols). This documents how the performance is measured
and the design rules that keep it fast.

## perfreport

`make perf-report` (or `go run ./tools/perfreport [-runs N] <binary>`) prints a
Markdown table of, for a sample binary:

- **parse (startup)** — `binfile.Open` cost.
- **demangle** — the whole-table Itanium/Rust demangle pass.
- **view: …** — each non-interactive `-o` dump's render time and allocation
  volume (the views process the *whole* binary in one shot).
- **TUI view: …** — each interactive view's full-frame render cost (a 160×48
  frame with background decode completed).
- **TUI startup (ui.New)** and **peak resident memory**.

CI runs it against the freshly built `exex` binary (self-disassembly) and appends
the table to the workflow step summary (`.github/workflows/ci.yml`,
`release.yml`), so a regression shows up per push/release.

“Alloc” is bytes allocated to do the stage (`runtime.MemStats.TotalAlloc` delta),
i.e. GC pressure — not retained memory. Peak RSS is read from `/proc/self/status`
(`VmHWM`) on Linux.

## Go benchmarks

Allocation-sensitive hot paths have benchmarks gated on `EXEX_BENCH_BIN` (a path
to a real binary), so they're skipped in normal `go test` but available for
profiling:

```sh
export EXEX_BENCH_BIN="/path/to/large/binary"

# disasm dump (the dominant allocator)
go test ./internal/dump -run '^$' -bench BenchmarkDisasm$ -benchmem \
    -benchtime=1x -memprofile=/tmp/mem.prof
go tool pprof -top -sample_index=alloc_space /tmp/mem.prof

# parse / startup
go test ./internal/binfile -run '^$' -bench BenchmarkOpen -benchmem \
    -benchtime=5x -cpuprofile=/tmp/cpu.prof
go tool pprof -top /tmp/cpu.prof
```

`BenchmarkDisasm`/`BenchmarkDisasmAll` (dump) and `BenchmarkOpen` (parse) are the
current set; add more next to them as new hot paths appear.

## Design rules (why it stays fast)

- **TUI views render only the visible window.** List/table/hex/disasm views draw
  ~one screen of rows and cache them, so they never allocate proportional to the
  binary. The `-o` dumps, by contrast, materialise the whole view — that's where
  allocation volume lives, and where the hot-path work below is concentrated.
- **The decoder is shared.** `internal/disasm` feeds both the dump and the TUI
  disasm view, so its per-instruction cost (fast-pathed `resolveRelTargets`,
  allocation-free hex formatting) matters to both; the TUI just decodes a small
  window at a time.
- **Streaming where possible.** `dump.DisasmTo` streams per instruction into one
  reused line buffer (no per-line `fmt`/intermediate strings). The other buffered
  dumps (`Strings`, `Symbols`) format into a reused buffer and pre-`Grow` the
  output; converting them to a streaming `…To(w)` form is the next step if their
  buffered output becomes a problem.
- **Defer expensive work off the open path.** The Mach-O compiler-banner scan
  (`File.Compiler`) and DWARF/line tables load lazily on first use, and the CLI
  only runs the whole-table demangle for views that actually show symbol names
  (`dump.ViewNeedsDemangle`). Both keep cold starts and non-symbol dumps cheap.

## What's at the floor

After the above, the remaining large costs are mostly irreducible without bigger
changes: the x/arch decoders (`Inst.String`, `MemImmediate`) on the disasm paths,
the third-party demangler on symbol-heavy binaries, and cold disk I/O paging a
large file in during `Open`.
