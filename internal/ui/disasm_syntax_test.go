//go:build !lite

package ui

import (
	"testing"

	"github.com/rabarbra/exex/internal/disasm"
)

// The disasm pane's token→style conversion is syntax.StyleEntryToLipgloss, which
// internal/syntax covers directly (TestChromaDefaultTokenUsesThemeForeground).

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
