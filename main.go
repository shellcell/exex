// Command elf-explorer is a terminal UI for exploring ELF and Mach-O binaries:
// header, sections, symbols, disassembly, and DWARF-driven source mapping.
package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/psimonen/elf-explorer/internal/binfile"
	"github.com/psimonen/elf-explorer/internal/ui"
)

func main() {
	if len(os.Args) != 2 || os.Args[1] == "-h" || os.Args[1] == "--help" {
		fmt.Fprintf(os.Stderr, "usage: %s <elf-or-macho-binary>\n", os.Args[0])
		os.Exit(2)
	}
	path := os.Args[1]

	f, err := binfile.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "elf-explorer: %v\n", err)
		os.Exit(1)
	}

	m, err := ui.New(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "elf-explorer: %v\n", err)
		os.Exit(1)
	}

	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithMouseCellMotion())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "elf-explorer: %v\n", err)
		os.Exit(1)
	}
}
