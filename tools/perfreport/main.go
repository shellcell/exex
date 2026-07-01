// Command perfreport measures exex against a sample binary and prints a Markdown
// table: the parse/startup cost, every `-o` view's render time and allocation
// volume, each interactive (TUI) view's full-frame render cost, and the process's
// peak resident memory.
//
// It exercises the real code paths (binfile.Open, dump.View/DisasmTo, ui.New), so
// the numbers track what a user actually pays. CI feeds it the freshly built exex
// binary (self-disassembly: always present, a realistic ~10 MB native object), and
// appends the table to the workflow step summary so regressions show up per push.
//
// Usage: perfreport [-runs N] <sample-binary>
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/config"
	"github.com/rabarbra/exex/internal/dump"
	"github.com/rabarbra/exex/internal/ui"
)

// nonDisasmViews are the buffered views (everything dump.View handles). The two
// disasm variants stream and are measured separately.
var nonDisasmViews = []string{"info", "sections", "segments", "symbols", "strings", "libs", "sources", "relocs", "syscalls", "cpu-features"}

func main() {
	runs := flag.Int("runs", 5, "timing runs per stage (the fastest is reported)")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: perfreport [-runs N] <sample-binary>")
		os.Exit(2)
	}
	path := flag.Arg(0)

	info, err := os.Stat(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "perfreport: %v\n", err)
		os.Exit(1)
	}

	// Parse/startup: re-open each run so the timing covers a cold load, then keep
	// the last file only for retained-heap and warm interactive render measurements.
	var loaded *binfile.File
	parse := measure(*runs, func() {
		if loaded != nil {
			loaded.Close()
		}
		var e error
		loaded, e = binfile.Open(path)
		if e != nil {
			fmt.Fprintf(os.Stderr, "perfreport: open %s: %v\n", path, e)
			os.Exit(1)
		}
	})
	defer loaded.Close()
	// Memory retained by a loaded binary — the interactive footprint floor.
	runtime.GC()
	var held runtime.MemStats
	runtime.ReadMemStats(&held)

	// Demangling is measured on a fresh loaded file each run, excluding the open
	// itself, so repeated ApplyDemangled calls do not warm/mutate one shared File.
	demangle := measurePrepared(*runs,
		func() any { return mustOpen(path) },
		func(v any) { v.(*binfile.File).ApplyDemangled(v.(*binfile.File).ComputeDemangled()) },
		func(v any) { v.(*binfile.File).Close() },
	)

	type row struct {
		stage string
		stat  stat
	}
	rows := []row{
		{"parse (cold open)", parse},
		{"demangle (fresh file)", demangle},
	}
	for _, v := range nonDisasmViews {
		view := v
		rows = append(rows, row{"CLI view cold-cache: " + view, measurePrepared(*runs,
			func() any { return mustOpenForView(path, view) },
			func(v any) { runView(v.(*binfile.File), view) },
			func(v any) { v.(*binfile.File).Close() },
		)})
	}
	for _, d := range []struct {
		name string
		all  bool
	}{{"disasm", false}, {"disasm-all", true}} {
		dis := d
		rows = append(rows, row{"CLI view cold-cache: " + dis.name, measurePrepared(*runs,
			func() any { return mustOpen(path) },
			func(v any) {
				if err := dump.DisasmTo(io.Discard, v.(*binfile.File), dis.all); err != nil {
					fmt.Fprintf(os.Stderr, "perfreport: %s: %v\n", dis.name, err)
					os.Exit(1)
				}
			},
			func(v any) { v.(*binfile.File).Close() },
		)})
	}

	// TUI startup: building the model is the interactive launch cost (the event
	// loop never runs, so this needs no terminal).
	cfg, err := config.Load()
	if err != nil {
		cfg = &config.Config{}
	}
	tui := measurePrepared(*runs,
		func() any { return mustOpen(path) },
		func(v any) {
			if _, err := ui.New(v.(*binfile.File), ui.Options{Config: cfg}); err != nil {
				fmt.Fprintf(os.Stderr, "perfreport: ui.New: %v\n", err)
				os.Exit(1)
			}
		},
		func(v any) { v.(*binfile.File).Close() },
	)
	rows = append(rows, row{"TUI startup cold-model (ui.New)", tui})

	// Per-view interactive render cost (a full 160×48 frame, decode completed).
	for _, v := range ui.RenderViewStats(loaded, 160, 48, *runs) {
		rows = append(rows, row{"TUI view warm-cache: " + v.View, stat{dur: v.Dur, alloc: v.Alloc}})
	}

	peak := peakRSS()

	var b strings.Builder
	fmt.Fprintf(&b, "### Performance (sample: %s, %s)\n\n", path, humanBytes(uint64(info.Size())))
	fmt.Fprintf(&b, "Best of %d runs. CLI views use a fresh prepared File per run (open/demangle setup excluded); TUI views are warm-cache repeated renders. Alloc is bytes allocated to do the stage; retained-after-load heap is %s.\n\n",
		*runs, humanBytes(held.HeapAlloc))
	b.WriteString("| stage | time | alloc |\n| --- | ---: | ---: |\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", r.stage, humanDur(r.stat.dur), humanBytes(r.stat.alloc))
	}
	fmt.Fprintf(&b, "\n**Peak resident memory:** %s\n", humanBytes(peak))

	out := b.String()
	fmt.Print(out)
	// Append to the GitHub Actions step summary when running in CI.
	if sum := os.Getenv("GITHUB_STEP_SUMMARY"); sum != "" {
		if fh, err := os.OpenFile(sum, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644); err == nil {
			fh.WriteString("\n" + out)
			fh.Close()
		}
	}
}

// stat is a stage's best wall time and its allocation volume.
type stat struct {
	dur   time.Duration
	alloc uint64
}

// measure times fn over `runs` iterations (reporting the fastest, to suppress
// scheduler/GC noise) and separately records the bytes it allocates on one clean
// run.
func measure(runs int, fn func()) stat {
	if runs < 1 {
		runs = 1
	}
	best := time.Duration(1<<63 - 1)
	for range runs {
		t := time.Now()
		fn()
		if d := time.Since(t); d < best {
			best = d
		}
	}
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	fn()
	runtime.ReadMemStats(&m1)
	return stat{dur: best, alloc: m1.TotalAlloc - m0.TotalAlloc}
}

func measurePrepared(runs int, setup func() any, fn func(any), cleanup func(any)) stat {
	if runs < 1 {
		runs = 1
	}
	best := time.Duration(1<<63 - 1)
	for range runs {
		v := setup()
		t := time.Now()
		fn(v)
		if d := time.Since(t); d < best {
			best = d
		}
		cleanup(v)
	}
	v := setup()
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	fn(v)
	runtime.ReadMemStats(&m1)
	cleanup(v)
	return stat{dur: best, alloc: m1.TotalAlloc - m0.TotalAlloc}
}

func mustOpen(path string, opts ...binfile.Option) *binfile.File {
	f, err := binfile.Open(path, opts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "perfreport: open %s: %v\n", path, err)
		os.Exit(1)
	}
	return f
}

func mustOpenForView(path, view string) *binfile.File {
	var opts []binfile.Option
	if dump.ViewNeedsLayoutOnly(view) {
		opts = append(opts, binfile.WithLayoutOnly())
	}
	f := mustOpen(path, opts...)
	if dump.ViewNeedsDemangle(view) {
		f.ApplyDemangled(f.ComputeDemangled())
	}
	return f
}

func runView(f *binfile.File, view string) {
	if streamed, err := dump.StreamView(io.Discard, f, view); streamed {
		if err != nil {
			fmt.Fprintf(os.Stderr, "perfreport: view %s: %v\n", view, err)
			os.Exit(1)
		}
		return
	}
	if _, err := dump.View(f, view); err != nil {
		fmt.Fprintf(os.Stderr, "perfreport: view %s: %v\n", view, err)
		os.Exit(1)
	}
}

// peakRSS returns the process's peak resident set size. On Linux it reads VmHWM
// from /proc (true peak RSS); elsewhere it falls back to the Go runtime's Sys
// estimate, which is a ceiling rather than a measured peak.
func peakRSS() uint64 {
	if data, err := os.ReadFile("/proc/self/status"); err == nil {
		for line := range strings.SplitSeq(string(data), "\n") {
			if strings.HasPrefix(line, "VmHWM:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					if kb, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
						return kb * 1024
					}
				}
			}
		}
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.Sys
}

func humanBytes(b uint64) string {
	switch {
	case b >= 1<<20:
		return fmt.Sprintf("%.2f MB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func humanDur(d time.Duration) string {
	switch {
	case d >= time.Second:
		return fmt.Sprintf("%.2f s", d.Seconds())
	case d >= time.Millisecond:
		return fmt.Sprintf("%.2f ms", float64(d.Microseconds())/1000)
	default:
		return fmt.Sprintf("%.0f µs", float64(d.Nanoseconds())/1000)
	}
}
