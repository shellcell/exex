package ui

import (
	"strings"
	"testing"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/disasm"
)

func TestFunctionDisasmText(t *testing.T) {
	sym := binfile.Symbol{Name: "main", Addr: 0x1000, Size: 7}
	insts := []disasm.Inst{
		{Addr: 0x1000, Bytes: []byte{0x55}, Text: "push %rbp"},
		{Addr: 0x1001, Bytes: []byte{0x48, 0x89, 0xe5}, Text: "  mov %rsp,%rbp  "},
		{Addr: 0x1004, Bytes: []byte{0xc3}, Text: "ret"},
	}
	out := functionDisasmText(sym, insts, 16)

	if !strings.HasPrefix(out, "main  (0x0000000000001000–0x0000000000001007, 7 bytes)\n") {
		t.Fatalf("header wrong:\n%s", out)
	}
	for _, want := range []string{
		"0x0000000000001000:  55                    push %rbp",
		"0x0000000000001001:  48 89 e5              mov %rsp,%rbp", // trimmed
		"0x0000000000001004:  c3                    ret",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing line %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Fatal("function copy text must be plain (no ANSI)")
	}
}

func TestPlainBytesString(t *testing.T) {
	if got := plainBytesString([]byte{0x48, 0x89, 0xe5}); got != "48 89 e5" {
		t.Fatalf("plainBytesString = %q", got)
	}
	if got := plainBytesString(nil); got != "" {
		t.Fatalf("empty = %q", got)
	}
}
