//go:build !lite

package ui

import (
	"testing"

	"charm.land/lipgloss/v2"
	"github.com/alecthomas/chroma/v2"

	"github.com/rabarbra/exex/internal/disasm"
)

func TestDisasmChromaDefaultTokenUsesSyntaxForeground(t *testing.T) {
	got := chromaStyleEntryToLipgloss(chroma.StyleEntry{}, "#586e75").Render("x")
	want := lipgloss.NewStyle().Foreground(lipgloss.Color("#586e75")).Render("x")
	if got != want {
		t.Fatalf("default disasm token style = %q, want %q", got, want)
	}
}

func TestDisasmChromaAsmLexerForArch(t *testing.T) {
	tests := []struct {
		arch disasm.Arch
		want string
	}{
		{disasm.ArchX86, "GAS"},
		{disasm.ArchAMD64, "GAS"},
		{disasm.ArchRISCV64, "GAS"},
		{disasm.ArchARM64, "ArmAsm"},
	}
	for _, tt := range tests {
		l := newDisasmAsmLexer(tt.arch)
		if l == nil {
			t.Fatalf("%v: no asm lexer", tt.arch)
		}
		if got := l.Config().Name; got != tt.want {
			t.Fatalf("%v: asm lexer = %q, want %q", tt.arch, got, tt.want)
		}
	}
}
