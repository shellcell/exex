package rawheader

import (
	"strings"
	"testing"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/testbin"
	"github.com/rabarbra/exex/internal/ui/modal"
)

func ctxFor(t *testing.T, w, h int) modal.Context {
	t.Helper()
	f, err := binfile.Open(testbin.WriteTinyELF64(t))
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	t.Cleanup(func() { f.Close() })
	id := func(s string) string { return s }
	return modal.Context{File: f, Width: w, Height: h, Styles: &modal.Styles{Title: id, Frame: id, Hint: id}}
}

func TestRenderShowsHeaderFields(t *testing.T) {
	var s State
	s.Open()
	out := s.Render(ctxFor(t, 100, 40))
	if !strings.Contains(out, "ELF header") {
		t.Errorf("title missing:\n%s", out)
	}
	// The ELF fixture's header fields, as the table labels them.
	for _, want := range []string{"Type", "ET_EXEC", "Machine", "EM_X86_64", "Entry", "0x401000"} {
		if !strings.Contains(out, want) {
			t.Errorf("field %q missing from the table", want)
		}
	}
}

// TestRenderScrollsWhenTallerThanTheTerminal: the footer switches from the
// static hint to a range indicator only when there is something to scroll.
func TestRenderScrollsWhenTallerThanTheTerminal(t *testing.T) {
	var s State
	s.Open()

	tall := s.Render(ctxFor(t, 100, 200))
	if !strings.Contains(tall, "Esc/⇧H close") {
		t.Errorf("a fitting table should show the static hint:\n%s", tall)
	}
	if s.ScrollOffset() != 0 {
		t.Errorf("scroll = %d in a tall window", s.ScrollOffset())
	}

	short := s.Render(ctxFor(t, 100, 14))
	if !strings.Contains(short, " of ") || !strings.Contains(short, "Esc closes") {
		t.Errorf("a scrolled table should show the range:\n%s", short)
	}
}

// TestEndKeyClampsToTheBottom exercises the sentinel Scroller.Update sets, which
// only Render can resolve.
func TestEndKeyClampsToTheBottom(t *testing.T) {
	var s State
	s.Open()
	s.Update("end")
	s.Render(ctxFor(t, 100, 14))
	if got := s.ScrollOffset(); got == 0 || got >= 1<<20 {
		t.Errorf("end clamped to %d, want a real bottom offset", got)
	}
	if !s.Active() {
		t.Error("end closed the overlay")
	}
}

func TestAnyOtherKeyDismisses(t *testing.T) {
	var s State
	s.Open()
	s.Update("esc")
	if s.Active() {
		t.Error("esc did not dismiss the overlay")
	}
}

// TestRenderEmptyHeader: a format with no raw header fields shows a message
// rather than an empty box.
func TestRenderEmptyHeader(t *testing.T) {
	id := func(s string) string { return s }
	ctx := modal.Context{
		File:   &binfile.File{},
		Width:  100,
		Height: 30,
		Styles: &modal.Styles{Title: id, Frame: id, Hint: id},
	}
	var s State
	s.Open()
	out := s.Render(ctx)
	if !strings.Contains(out, "no raw header fields") {
		t.Errorf("empty header did not explain itself:\n%s", out)
	}
}
