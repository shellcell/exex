// Command exex is a terminal UI for exploring ELF, Mach-O, and PE binaries:
// header, sections, symbols, disassembly, and DWARF-driven source mapping.
package main

import (
	"fmt"
	"os"
	"os/exec"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/config"
	"github.com/rabarbra/exex/internal/ui"
)

func main() {
	if len(os.Args) != 2 || os.Args[1] == "-h" || os.Args[1] == "--help" {
		fmt.Fprintf(os.Stderr, "usage: %s <binary>   (path or a command name on $PATH)\n", os.Args[0])
		os.Exit(2)
	}
	path := resolveTarget(os.Args[1])

	f, err := binfile.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "exex: %v\n", err)
		os.Exit(1)
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "exex: %v\n", err)
		os.Exit(1)
	}

	m, err := ui.New(f, ui.Options{Config: cfg})
	if err != nil {
		fmt.Fprintf(os.Stderr, "exex: %v\n", err)
		os.Exit(1)
	}

	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithMouseCellMotion())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "exex: %v\n", err)
		os.Exit(1)
	}
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
