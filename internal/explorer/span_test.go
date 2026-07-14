package explorer_test

import (
	"testing"

	"github.com/shellcell/exex/internal/binfile"
	"github.com/shellcell/exex/internal/disasm"
	"github.com/shellcell/exex/internal/explorer"
	"github.com/shellcell/exex/internal/testbin"
)

func fixtureService(t *testing.T) *binfile.File {
	t.Helper()
	f, err := binfile.Open(testbin.WriteTinyELF64(t))
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func newService(t *testing.T) *explorer.DisasmService {
	t.Helper()
	f := fixtureService(t)
	d, err := disasm.For(f.Arch())
	if err != nil {
		t.Fatalf("disassembler: %v", err)
	}
	return explorer.NewDisasmService(f, d, 1<<20, 0)
}

func TestSpanEmptyAndContains(t *testing.T) {
	var empty explorer.Span
	if !empty.Empty() {
		t.Error("zero Span is not empty")
	}
	s := explorer.Span{Insts: []disasm.Inst{{Addr: 1}}, PosLo: 0x10, PosHi: 0x20}
	if s.Empty() {
		t.Error("a span with instructions reported empty")
	}
	for _, tc := range []struct {
		pos  int
		want bool
	}{{0x0f, false}, {0x10, true}, {0x1f, true}, {0x20, false}} {
		if got := s.Contains(tc.pos); got != tc.want {
			t.Errorf("Contains(%#x) = %v, want %v", tc.pos, got, tc.want)
		}
	}
}

// TestDecodeSpanAtDecodesRealCode walks the fixture's .text, whose first
// instruction is `mov $0x1,%rax` at 0x401000.
func TestDecodeSpanAtDecodesRealCode(t *testing.T) {
	svc := newService(t)
	span := svc.DecodeSpanAt(0x401000, 0)
	if span.Empty() {
		t.Fatal("decoded nothing at the entry point")
	}
	if got := span.Insts[0].Addr; got != 0x401000 {
		t.Errorf("first instruction at %#x, want 0x401000", got)
	}
	if span.PosHi <= span.PosLo {
		t.Errorf("degenerate bounds: PosLo=%d PosHi=%d", span.PosLo, span.PosHi)
	}
}

// TestPosLoIsTheFirstInstructionNotTheWindowStart is the reason Span exists.
//
// Decoding with lead-in context reserves bytes before the target that hold no
// decoded instructions. Anchoring "is there code above" on the raw window start
// would let the view scroll up into that dead lead-in; PosLo pins it to the first
// instruction actually decoded.
func TestPosLoIsTheFirstInstructionNotTheWindowStart(t *testing.T) {
	f := fixtureService(t)
	d, err := disasm.For(f.Arch())
	if err != nil {
		t.Fatalf("disassembler: %v", err)
	}
	svc := explorer.NewDisasmService(f, d, 1<<20, 0)

	// helper() sits at 0x401020, 0x20 into the executable image. Decoding there
	// resyncs from the symbol, so the raw window still starts at 0 while the first
	// decoded instruction is at image position 0x20.
	const helperAddr = 0x401020
	const lead = 0x20

	win, insts := svc.DecodeAt(helperAddr, lead)
	span := svc.DecodeSpanAt(helperAddr, lead)
	if span.Empty() || len(insts) == 0 {
		t.Fatal("decoded nothing at helper")
	}
	if insts[0].Addr != helperAddr {
		t.Fatalf("decode began at %#x, want the symbol %#x", insts[0].Addr, helperAddr)
	}
	firstPos, ok := f.ExecImage().PosForAddr(helperAddr)
	if !ok {
		t.Fatal("helper is not in the executable image")
	}
	if span.PosLo != firstPos {
		t.Errorf("PosLo = %d, want %d (the first decoded instruction's position)", span.PosLo, firstPos)
	}
	// The discriminating assertion: the raw window starts *before* PosLo, on lead-in
	// bytes that decoded to nothing. Using win.Start would let the view scroll up
	// into them.
	if span.PosLo <= win.Start {
		t.Errorf("PosLo (%d) does not exceed the window start (%d); the test no longer distinguishes them",
			span.PosLo, win.Start)
	}
	if span.PosHi != win.End {
		t.Errorf("PosHi = %d, want the window end %d", span.PosHi, win.End)
	}
	// Nothing decoded sits before PosLo.
	for _, in := range span.Insts {
		if p, ok := f.ExecImage().PosForAddr(in.Addr); ok && p < span.PosLo {
			t.Fatalf("instruction at %#x (pos %d) precedes PosLo %d", in.Addr, p, span.PosLo)
		}
	}
}

// TestSpanForUsesAnAlreadyDecodedWindow: the instruction-text search decodes in
// parallel chunks and pairs the result with its bounds afterwards.
func TestSpanForUsesAnAlreadyDecodedWindow(t *testing.T) {
	f := fixtureService(t)
	d, err := disasm.For(f.Arch())
	if err != nil {
		t.Fatalf("disassembler: %v", err)
	}
	svc := explorer.NewDisasmService(f, d, 1<<20, 0)

	img := f.ExecImage()
	win := img.Window(0, img.Len())
	insts := svc.DecodeWindow(win)
	if len(insts) == 0 {
		t.Fatal("decoded nothing")
	}
	span := svc.SpanFor(win, insts)
	if len(span.Insts) != len(insts) {
		t.Errorf("SpanFor dropped instructions: %d vs %d", len(span.Insts), len(insts))
	}
	if span.PosHi != win.End {
		t.Errorf("PosHi = %d, want the window end %d", span.PosHi, win.End)
	}
	// DecodeSpanWindow is SpanFor over a fresh decode of the same window.
	if got := svc.DecodeSpanWindow(win); got.PosLo != span.PosLo || got.PosHi != span.PosHi {
		t.Errorf("DecodeSpanWindow bounds = (%d,%d), want (%d,%d)", got.PosLo, got.PosHi, span.PosLo, span.PosHi)
	}
}

// TestSpanForEmptyDecodeFallsBackToTheWindowStart: with no instructions there is
// no first-instruction position to anchor on.
func TestSpanForEmptyDecodeFallsBackToTheWindowStart(t *testing.T) {
	svc := newService(t)
	win := binfile.Window{Start: 42, End: 99}
	span := svc.SpanFor(win, nil)
	if !span.Empty() {
		t.Error("a nil decode produced a non-empty span")
	}
	if span.PosLo != 42 || span.PosHi != 99 {
		t.Errorf("bounds = (%d,%d), want the raw window (42,99)", span.PosLo, span.PosHi)
	}
}
