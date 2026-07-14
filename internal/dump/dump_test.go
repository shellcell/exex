package dump

import (
	"strings"
	"testing"

	"github.com/shellcell/exex/internal/binfile"
	"github.com/shellcell/exex/internal/disasm"
)

func TestFunctionText(t *testing.T) {
	sym := binfile.Symbol{Name: "main", Addr: 0x1000, Size: 7}
	insts := []disasm.Inst{
		{Addr: 0x1000, Bytes: []byte{0x55}, Text: "push %rbp"},
		{Addr: 0x1001, Bytes: []byte{0x48, 0x89, 0xe5}, Text: "  mov %rsp,%rbp  "},
		{Addr: 0x1004, Bytes: []byte{0xc3}, Text: "ret"},
	}
	out := FunctionText(sym, insts, 16)

	if !strings.HasPrefix(out, "main  (0x0000000000001000–0x0000000000001007, 7 bytes)\n") {
		t.Fatalf("header wrong:\n%s", out)
	}
	for _, want := range []string{
		"0x0000000000001000:  55                       push %rbp",
		"0x0000000000001001:  48 89 e5                  mov %rsp,%rbp",
		"0x0000000000001004:  c3                        ret",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing line %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Fatal("function text must be plain (no ANSI)")
	}
}

func TestPlainBytes(t *testing.T) {
	if got := plainBytes([]byte{0x48, 0x89, 0xe5}); got != "48 89 e5" {
		t.Fatalf("plainBytes = %q", got)
	}
	if got := plainBytes(nil); got != "" {
		t.Fatalf("empty = %q", got)
	}
}

func TestParseAddr(t *testing.T) {
	cases := map[string]uint64{"0x1000": 0x1000, "1000": 1000, "dead": 0xdead, "0X40": 0x40}
	for in, want := range cases {
		if got, err := parseAddr(in); err != nil || got != want {
			t.Fatalf("parseAddr(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
}

func TestViewKeywords(t *testing.T) {
	f := &binfile.File{
		Sections: []binfile.Section{{Name: ".text", Addr: 0x1000, Size: 16, TypeName: "PROGBITS", Flags: "AX"}},
		Symbols:  []binfile.Symbol{{Name: "main", Addr: 0x1000, Size: 16, Kind: binfile.SymFunc, Bind: binfile.BindGlobal}},
		Segments: []binfile.Segment{{Name: "LOAD", Addr: 0x1000, Size: 16, R: true, X: true}},
	}
	if out, err := View(f, "sections"); err != nil || !strings.Contains(out, ".text") {
		t.Fatalf("sections dump = %q, %v", out, err)
	}
	if out, err := View(f, "symbols"); err != nil || !strings.Contains(out, "main") || !strings.Contains(out, "FUNC") {
		t.Fatalf("symbols dump = %q, %v", out, err)
	}
	if out, err := View(f, "segments"); err != nil || !strings.Contains(out, "LOAD") || !strings.Contains(out, "r-x") {
		t.Fatalf("segments dump = %q, %v", out, err)
	}
	if _, err := View(f, "nope"); err == nil {
		t.Fatal("unknown view should error")
	}
}

func TestPhysAddrColumns(t *testing.T) {
	// No distinct load address → no LMA/PAddr column.
	plain := &binfile.File{
		Sections: []binfile.Section{{Name: ".text", Addr: 0x1000, Size: 16}},
		Segments: []binfile.Segment{{Name: "LOAD", Addr: 0x1000, Size: 16, R: true, X: true}},
	}
	if out := Sections(plain); strings.Contains(out, "LMA") {
		t.Fatalf("sections should omit LMA when no phys addr:\n%s", out)
	}
	if out := Segments(plain); strings.Contains(out, "PAddr") {
		t.Fatalf("segments should omit PAddr when no phys addr:\n%s", out)
	}

	// Higher-half style: virtual 0xc0101000, load 0x101000.
	hh := &binfile.File{
		Sections: []binfile.Section{{Name: ".text", Addr: 0xc0101000, PhysAddr: 0x101000, Size: 16}},
		Segments: []binfile.Segment{{Name: "LOAD", Addr: 0xc0100000, PhysAddr: 0x100000, Size: 4096, R: true, X: true}},
	}
	secOut := Sections(hh)
	if !strings.Contains(secOut, "LMA") || !strings.Contains(secOut, "00101000") {
		t.Fatalf("sections should show LMA column + load addr:\n%s", secOut)
	}
	segOut := Segments(hh)
	if !strings.Contains(segOut, "PAddr") || !strings.Contains(segOut, "00100000") {
		t.Fatalf("segments should show PAddr column + phys addr:\n%s", segOut)
	}
}

func TestIsView(t *testing.T) {
	for _, v := range []string{"sections", "symbols", "sources", "segments", "info", "strings", "libs"} {
		if !IsView(v) {
			t.Fatalf("IsView(%q) = false", v)
		}
	}
	// A symbol whose name happens to collide must NOT be treated as a view by the
	// CLI — only exact known keywords are views; anything else is a disasm target.
	if IsView("main") || IsView("0x1000") || IsView("section_helper") {
		t.Fatal("non-keyword matched IsView")
	}
	// Every name advertised in ViewNames must be recognised by IsView, and the
	// disasm variants must route to the streaming path — otherwise extractOutput
	// in main would mis-handle them (the disasm-all drift bug).
	for _, v := range ViewNames {
		if !IsView(v) {
			t.Fatalf("ViewNames has %q but IsView rejects it", v)
		}
	}
	if d, all := IsDisasm("disasm"); !d || all {
		t.Fatalf("IsDisasm(disasm) = %v,%v", d, all)
	}
	if d, all := IsDisasm("disasm-all"); !d || !all {
		t.Fatalf("IsDisasm(disasm-all) = %v,%v", d, all)
	}
	if d, _ := IsDisasm("sections"); d {
		t.Fatal("IsDisasm(sections) should be false")
	}
}
