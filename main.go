// SPDX-License-Identifier: MIT

// Command exex is a terminal UI for exploring ELF, Mach-O, and PE binaries:
// header, sections, symbols, disassembly, and DWARF-driven source mapping.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/config"
	"github.com/rabarbra/exex/internal/dump"
	"github.com/rabarbra/exex/internal/ui"
)

func main() {
	var debugPath, searchString, archName string
	flag.StringVar(&debugPath, "debug", "", "path to an external debug-symbols file or directory (ELF .debug / Mach-O .dSYM)")
	flag.StringVar(&debugPath, "d", "", "shorthand for -debug")
	flag.StringVar(&searchString, "s", "", "search printable strings: open the match in Hex, or the Strings view filtered when several match")
	flag.StringVar(&archName, "arch", "", "for a universal (fat) Mach-O, which architecture slice to open (e.g. x86_64, arm64)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [-debug PATH] [-s STRING] [-arch NAME] [-o [VIEW]] <binary> [goto]\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "  <binary>  path to an ELF/Mach-O/PE file, or a command name on $PATH")
		fmt.Fprintln(os.Stderr, "  goto      address (0x…) or symbol name: jump to it on open, or with bare -o disassemble it")
		fmt.Fprintf(os.Stderr, "  -o VIEW   print a view to stdout and exit: %s\n", strings.Join(dump.ViewNames, ", "))
		fmt.Fprintln(os.Stderr, "  -o        bare: print the goto symbol/address's function disassembly to stdout and exit")
		fmt.Fprintln(os.Stderr, "  -arch     for a universal Mach-O, the slice to open (e.g. x86_64, arm64)")
		flag.PrintDefaults()
	}
	// `-o` takes an optional view value, which Go's flag package can't express, so
	// pull it (and any view keyword that follows) out of the args by hand first.
	rawArgs, outputMode, outputView := extractOutput(os.Args[1:])
	// The stdlib flag package stops at the first non-flag argument, so a flag
	// after the binary path (e.g. `exex <binary> -s foo`) would be misread as a
	// positional. Reorder so flags can appear in any position.
	flag.CommandLine.Parse(reorderArgs(rawArgs))

	args := flag.Args()
	if len(args) < 1 || len(args) > 2 {
		flag.Usage()
		os.Exit(2)
	}
	path := resolveTarget(args[0])
	gotoTarget := ""
	if len(args) == 2 {
		gotoTarget = args[1]
	}

	var openOpts []binfile.Option
	if debugPath != "" {
		openOpts = append(openOpts, binfile.WithDebugPath(debugPath))
	}
	if archName != "" {
		openOpts = append(openOpts, binfile.WithArch(archName))
	}
	f, err := binfile.Open(path, openOpts...)
	if err != nil {
		// Not a recognised binary: if it's a readable text file (a shell/python/…
		// script — still "executable"), open it in the text viewer instead, unless
		// a non-interactive -o dump was requested.
		if !outputMode && ui.LooksLikeText(readPrefix(path, 8192)) {
			runTextViewer(path)
			return
		}
		fmt.Fprintf(os.Stderr, "exex: %v\n", err)
		os.Exit(1)
	}

	// Non-interactive output mode: dump a view (`-o VIEW`) or the positional
	// symbol/address's disassembly (bare `-o`) to stdout and exit, no TUI.
	if outputMode {
		// The whole-binary disasm streams (and demangles labels lazily), so it
		// must NOT pay the upfront whole-table demangle that the other views want.
		if d, all := dump.IsDisasm(outputView); d {
			if err := dump.DisasmTo(os.Stdout, f, all); err != nil {
				fmt.Fprintf(os.Stderr, "exex: %v\n", err)
				os.Exit(1)
			}
			return
		}
		// Demangle the whole table only when the output actually uses symbol names:
		// the symbols view, or the bare `-o <symbol>` function dump (which resolves a
		// possibly-demangled name). Skipping it keeps sections/strings/etc. cheap on
		// large C++/Swift binaries, where the pass alone allocates 1+ GB.
		if dump.ViewNeedsDemangle(outputView) || (outputView == "" && gotoTarget != "") {
			f.ApplyDemangled(f.ComputeDemangled()) // readable + matchable names
		}
		var (
			out string
			err error
		)
		switch {
		case outputView != "":
			out, err = dump.View(f, outputView)
		case gotoTarget != "":
			out, err = dump.Function(f, gotoTarget)
		default:
			fmt.Fprintf(os.Stderr, "exex: -o needs a view (%s) or a symbol/address argument (e.g. exex -o <binary> main)\n",
				strings.Join(dump.ViewNames, ", "))
			os.Exit(2)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "exex: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(out)
		return
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "exex: %v\n", err)
		os.Exit(1)
	}

	m, err := ui.New(f, ui.Options{Config: cfg, Goto: gotoTarget, SearchString: searchString})
	if err != nil {
		fmt.Fprintf(os.Stderr, "exex: %v\n", err)
		os.Exit(1)
	}

	p := tea.NewProgram(m)
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "exex: %v\n", err)
		os.Exit(1)
	}
}

// valueFlags are the flags that take a separate value token, so reorderArgs
// keeps the value attached to its flag when moving them ahead of positionals.
var valueFlags = map[string]bool{
	"-s": true, "--s": true,
	"-d": true, "--d": true,
	"-arch": true, "--arch": true,
	"-debug": true, "--debug": true,
}

// extractOutput pulls an optional -o / --o flag (with its optional view value)
// out of args, returning the remaining args, whether output mode is on, and the
// requested view ("" for a bare -o). A bare -o consumes the following token only
// when it's a known view keyword, so `-o sections <bin>` selects the view while
// `-o <bin> main` leaves <bin>/main as positionals (the symbol to disassemble).
func extractOutput(args []string) (rest []string, on bool, view string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-o" || a == "--o":
			on = true
			if i+1 < len(args) && dump.IsView(args[i+1]) {
				view = args[i+1]
				i++
			}
		case strings.HasPrefix(a, "-o="):
			on, view = true, a[len("-o="):]
		case strings.HasPrefix(a, "--o="):
			on, view = true, a[len("--o="):]
		default:
			rest = append(rest, a)
		}
	}
	return rest, on, view
}

// reorderArgs moves all flags (and their values) ahead of positional arguments
// so flags may appear in any position on the command line. Everything after a
// literal "--" is treated as positional.
func reorderArgs(args []string) []string {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			positional = append(positional, args[i+1:]...)
			return append(flags, positional...)
		case a != "-" && strings.HasPrefix(a, "-"):
			flags = append(flags, a)
			// `-s value` / `-debug value`: pull the value along, unless it's the
			// `-s=value` form (already self-contained).
			if !strings.Contains(a, "=") && valueFlags[a] && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		default:
			positional = append(positional, a)
		}
	}
	return append(flags, positional...)
}

// resolveTarget turns the CLI argument into a file path. An existing file (or
// any argument containing a path separator) is used as-is; a bare command name
// is looked up on $PATH like a shell would, so "exex ls" opens /bin/ls. When no
// PATH entry matches, the original argument is returned so binfile.Open reports
// the usual not-found error.
func resolveTarget(arg string) string {
	if st, err := os.Stat(arg); err == nil && !st.IsDir() {
		return arg
	}
	if p, err := exec.LookPath(arg); err == nil {
		return p
	}
	return arg
}

// readPrefix returns up to n bytes from the start of path (nil on error). Used
// to sniff whether an unrecognised file is text.
func readPrefix(path string, n int) []byte {
	fp, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer fp.Close()
	buf := make([]byte, n)
	r, _ := io.ReadFull(fp, buf)
	return buf[:r]
}

// runTextViewer loads path into the text-script viewer and runs it.
func runTextViewer(path string) {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "exex: %v\n", err)
		os.Exit(1)
	}
	tm, err := ui.NewText(path, *cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "exex: %v\n", err)
		os.Exit(1)
	}
	if _, err := tea.NewProgram(tm).Run(); err != nil {
		fmt.Fprintf(os.Stderr, "exex: %v\n", err)
		os.Exit(1)
	}
}
