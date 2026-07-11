//go:build !lite

package asmhl

import (
	"strings"
	"testing"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/rabarbra/exex/internal/disasm"
)

func TestAsmLexerForArch(t *testing.T) {
	for _, tt := range []struct {
		arch disasm.Arch
		want string
	}{
		{disasm.ArchX86, "GAS"},
		{disasm.ArchAMD64, "GAS"},
		{disasm.ArchRISCV64, "GAS"},
		{disasm.ArchARM64, "ArmAsm"},
	} {
		l := newLexer(tt.arch)
		if l == nil {
			t.Fatalf("%v: no asm lexer", tt.arch)
		}
		if got := l.Config().Name; got != tt.want {
			t.Fatalf("%v: asm lexer = %q, want %q", tt.arch, got, tt.want)
		}
	}
}

// TestUnbundledThemeFallsBackToClassColours: a theme with no bundled Chroma style
// must still colour by instruction class rather than rendering plain text.
func TestUnbundledThemeFallsBackToClassColours(t *testing.T) {
	class := lipgloss.NewStyle().Bold(true)
	st := Styles{Class: func(disasm.InstClass) lipgloss.Style { return class }}

	h := New("definitely-not-a-style", "", disasm.ArchAMD64, st)
	got := h.Render("mov %rsp,%rbp", disasm.ClassOther, nil)
	if want := class.Render("mov %rsp,%rbp"); got != want {
		t.Errorf("fallback = %q, want the class style applied to the whole line", got)
	}
}

// TestBundledThemeTokenisesPerToken: with a real style the line is split into
// tokens, so the output is not one uniform style run.
func TestBundledThemeTokenisesPerToken(t *testing.T) {
	class := lipgloss.NewStyle().Bold(true)
	st := Styles{Class: func(disasm.InstClass) lipgloss.Style { return class }}

	h := New("nord", "#d8dee9", disasm.ArchAMD64, st)
	got := h.Render("mov %rsp,%rbp", disasm.ClassOther, nil)
	if plain := ansi.Strip(got); plain != "mov %rsp,%rbp" {
		t.Fatalf("plain text = %q", plain)
	}
	if got == class.Render("mov %rsp,%rbp") {
		t.Error("a bundled theme rendered the whole line in the class style")
	}
	if !strings.Contains(got, "\x1b[") {
		t.Error("no colour applied")
	}
}
