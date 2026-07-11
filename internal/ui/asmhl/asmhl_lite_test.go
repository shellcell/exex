//go:build lite

package asmhl

import (
	"strings"
	"testing"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/rabarbra/exex/internal/disasm"
)

func liteStyles() (Styles, lipgloss.Style, lipgloss.Style, lipgloss.Style, lipgloss.Style) {
	class := lipgloss.NewStyle().Foreground(lipgloss.Color("#010203"))
	plain := lipgloss.NewStyle().Foreground(lipgloss.Color("#040506"))
	reg := lipgloss.NewStyle().Foreground(lipgloss.Color("#070809"))
	num := lipgloss.NewStyle().Foreground(lipgloss.Color("#0a0b0c"))
	return Styles{
		Class:    func(disasm.InstClass) lipgloss.Style { return class },
		Plain:    plain,
		Register: reg,
		Number:   num,
	}, class, plain, reg, num
}

// TestLiteMnemonicUsesTheClassStyle: the mnemonic is coloured by instruction
// class, the operands by their token kind.
func TestLiteMnemonicUsesTheClassStyle(t *testing.T) {
	st, class, _, reg, num := liteStyles()
	h := New("", "", disasm.ArchAMD64, st)

	got := h.Render("mov %rsp,%rbp", disasm.Classify("mov %rsp,%rbp"), nil)
	if plain := ansi.Strip(got); plain != "mov %rsp,%rbp" {
		t.Fatalf("plain text = %q", plain)
	}
	if !strings.Contains(got, class.Render("mov")) {
		t.Errorf("mnemonic not styled by class: %q", got)
	}
	if !strings.Contains(got, reg.Render("%rsp")) {
		t.Errorf("register not styled: %q", got)
	}

	got = h.Render("add $1,%eax", disasm.Classify("add $1,%eax"), nil)
	if !strings.Contains(got, num.Render("$1")) {
		t.Errorf("immediate not styled as a number: %q", got)
	}
}

// TestLiteOperandKeywordsAreNotRegisters: "qword ptr" reads better plain.
func TestLiteOperandKeywordsAreNotRegisters(t *testing.T) {
	st, _, plain, _, _ := liteStyles()
	h := New("", "", disasm.ArchAMD64, st)
	got := h.Render("mov qword ptr [rax], rbx", disasm.ClassOther, nil)
	for _, kw := range []string{"qword", "ptr"} {
		if !strings.Contains(got, plain.Render(kw)) {
			t.Errorf("%q was not rendered plain: %q", kw, got)
		}
	}
}
