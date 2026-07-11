package explorer

import (
	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/disasm"
)

// Span is a decoded, bounded slice of the executable image: the instructions
// themselves plus the image offsets that bound them.
type Span struct {
	Insts []disasm.Inst
	// PosLo is the image position of the *first decoded instruction*, which is
	// what bounds "is there code above / where does it start".
	PosLo int
	// PosHi is the image position just past the decoded window.
	PosHi int
}

// Empty reports whether the span decoded to nothing.
func (s Span) Empty() bool { return len(s.Insts) == 0 }

// Contains reports whether an image position falls inside the decoded span.
func (s Span) Contains(pos int) bool { return pos >= s.PosLo && pos < s.PosHi }

// DecodeSpanAt decodes a bounded window around addr, using `before` bytes of
// lead-in context, and returns it as a Span.
func (s *DisasmService) DecodeSpanAt(addr uint64, before int) Span {
	win, insts := s.DecodeAt(addr, before)
	return s.SpanFor(win, insts)
}

// DecodeSpanWindow decodes an explicit image window as a Span.
func (s *DisasmService) DecodeSpanWindow(win binfile.Window) Span {
	return s.SpanFor(win, s.DecodeWindow(win))
}

// SpanFor pairs an already-decoded window with its bounds, for callers that
// decoded it themselves (the instruction-text search decodes in parallel chunks).
//
// PosLo is the first instruction's position, not the window's start. The two
// differ when DecodeAt began at a symbol (a section or function jump): the window
// reserves lead bytes that hold no decoded instructions, so anchoring "scroll up"
// on win.Start would jump far before the actual preceding code.
func (s *DisasmService) SpanFor(win binfile.Window, insts []disasm.Inst) Span {
	posLo := win.Start
	if len(insts) > 0 && s.file != nil {
		if p, ok := s.file.ExecImage().PosForAddr(insts[0].Addr); ok {
			posLo = p
		}
	}
	return Span{Insts: insts, PosLo: posLo, PosHi: win.End}
}
