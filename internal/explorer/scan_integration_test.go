package explorer_test

import (
	"strings"
	"testing"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/disasm"
	"github.com/rabarbra/exex/internal/explorer"
	"github.com/rabarbra/exex/internal/testbin"
)

// newFixtureService decodes internal/testbin's hand-built ELF, whose .text is a
// known instruction sequence:
//
//	0x401000  mov  $0x1,%rax
//	0x401007  mov  $0x1,%rdi
//	0x40100e  call 0x401020
//	0x401013  syscall
//	0x401015  ret
//	          nop × 10
//	0x401020  push %rbp        (helper)
//	...
func newFixtureService(t *testing.T) *explorer.DisasmService {
	t.Helper()
	f, err := binfile.Open(testbin.WriteTinyELF64(t))
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	t.Cleanup(func() { f.Close() })
	d, err := disasm.For(f.Arch())
	if err != nil {
		t.Fatalf("disassembler: %v", err)
	}
	return explorer.NewDisasmService(f, d, 1<<20, 0)
}

func addrs(ms []explorer.Match) []uint64 {
	out := make([]uint64, len(ms))
	for i, m := range ms {
		out[i] = m.Addr
	}
	return out
}

// TestScanMatchingFindsInstructions walks the real decode path end to end.
func TestScanMatchingFindsInstructions(t *testing.T) {
	svc := newFixtureService(t)

	got := svc.ScanMatching(func(text string) bool {
		return strings.Contains(text, "syscall")
	}, 500, nil)
	if len(got) != 1 {
		t.Fatalf("syscall matches = %d, want 1: %v", len(got), addrs(got))
	}
	if got[0].Addr != 0x401013 {
		t.Errorf("syscall at 0x%x, want 0x401013", got[0].Addr)
	}
	if got[0].Sym != "_start" {
		t.Errorf("syscall symbol = %q, want _start", got[0].Sym)
	}
	if strings.TrimSpace(got[0].Text) != got[0].Text {
		t.Errorf("match text is not trimmed: %q", got[0].Text)
	}
}

// TestScanMatchingReturnsAscendingAddresses: the modal renders the list in
// address order and its caller relies on that, not on chunk arrival order.
func TestScanMatchingReturnsAscendingAddresses(t *testing.T) {
	svc := newFixtureService(t)
	got := svc.ScanMatching(func(string) bool { return true }, 500, nil)
	if len(got) < 5 {
		t.Fatalf("only %d instructions decoded", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].Addr >= got[i].Addr {
			t.Fatalf("addresses not strictly ascending at %d: 0x%x then 0x%x", i, got[i-1].Addr, got[i].Addr)
		}
	}
}

// TestScanMatchingHonoursLimit: the cap keeps the *lowest* addresses, so a
// limited scan is a prefix of the unlimited one.
func TestScanMatchingHonoursLimit(t *testing.T) {
	svc := newFixtureService(t)
	all := svc.ScanMatching(func(string) bool { return true }, 500, nil)
	if len(all) < 4 {
		t.Fatalf("only %d instructions decoded", len(all))
	}
	got := svc.ScanMatching(func(string) bool { return true }, 3, nil)
	if len(got) != 3 {
		t.Fatalf("limit 3 returned %d matches", len(got))
	}
	for i := range got {
		if got[i].Addr != all[i].Addr {
			t.Errorf("limited[%d] = 0x%x, want 0x%x (the lowest addresses)", i, got[i].Addr, all[i].Addr)
		}
	}
}

func TestScanMatchingEdgeCases(t *testing.T) {
	svc := newFixtureService(t)

	if got := svc.ScanMatching(func(string) bool { return true }, 0, nil); got != nil {
		t.Errorf("limit 0 returned %d matches, want nil", len(got))
	}
	if got := svc.ScanMatching(func(string) bool { return false }, 500, nil); len(got) != 0 {
		t.Errorf("matching nothing returned %d matches", len(got))
	}

	// A cancelled scan must not block or return partial garbage.
	done := make(chan struct{})
	close(done)
	if got := svc.ScanMatching(func(string) bool { return true }, 500, done); len(got) != 0 {
		t.Errorf("pre-cancelled scan returned %d matches", len(got))
	}

	var nilSvc *explorer.DisasmService
	if got := nilSvc.ScanMatching(func(string) bool { return true }, 500, nil); got != nil {
		t.Error("nil service should return nil")
	}
}
