// Command exex is a terminal UI for exploring ELF, Mach-O, and PE binaries:
// header, sections, symbols, disassembly, and DWARF-driven source mapping.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/config"
	"github.com/rabarbra/exex/internal/ui"
)

func main() {
	var debugPath, searchString string
	flag.StringVar(&debugPath, "debug", "", "path to an external debug-symbols file or directory (ELF .debug / Mach-O .dSYM)")
	flag.StringVar(&debugPath, "d", "", "shorthand for -debug")
	flag.StringVar(&searchString, "s", "", "search printable strings: open the match in Hex, or the Strings view filtered when several match")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [-debug PATH] [-s STRING] <binary> [goto]\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "  <binary>  path to an ELF/Mach-O/PE file, or a command name on $PATH")
		fmt.Fprintln(os.Stderr, "  goto      optional address (0x…) or symbol name to jump to on open")
		flag.PrintDefaults()
	}
	// The stdlib flag package stops at the first non-flag argument, so a flag
	// after the binary path (e.g. `exex <binary> -s foo`) would be misread as a
	// positional. Reorder so flags can appear in any position.
	flag.CommandLine.Parse(reorderArgs(os.Args[1:]))

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
	f, err := binfile.Open(path, openOpts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "exex: %v\n", err)
		os.Exit(1)
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
	"-debug": true, "--debug": true,
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
