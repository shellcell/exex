package ui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"

	"github.com/rabarbra/exex/internal/config"
	"github.com/rabarbra/exex/internal/dump"
	disasmview "github.com/rabarbra/exex/internal/ui/views/disasm"
)

// TestAsmColumnMatchesTheRenderedPrefix ties Columns.Asm to the row format.
//
// disasmInstRows builds a row's prefix with a format string (" %s  %s  "), not
// from Columns.Asm; Asm is used only to size the assembly truncation and to place
// the annotation. Because the annotation is positioned by a *difference*
// (inlineStart - asmEnd), an off-by-one in Asm cancels out there, and short
// instructions on a wide view never truncate — so a wrong Asm can leave every
// golden frame byte-identical and only misbehave on a narrow pane. This is the
// assertion that would catch it.
func TestAsmColumnMatchesTheRenderedPrefix(t *testing.T) {
	for _, tc := range []struct {
		name        string
		hide, space bool
	}{
		{"bytes shown, compact", false, false},
		{"bytes shown, spaced", false, true},
		{"bytes hidden", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := goldenModel(t)
			m.cfg.Behavior.HideDisasmBytes = tc.hide
			m.cfg.Behavior.SpacedDisasmBytes = tc.space
			enterMode(t, m, modeDisasm)
			if len(m.dasm.Inst) == 0 {
				t.Fatal("fixture decoded no instructions")
			}

			cols := m.disasmColumns()
			inst := m.dasm.Inst[0]
			rows := m.dasm.InstRows(m.viewContextPtr(), inst, m.width, false, nil)
			if len(rows) == 0 {
				t.Fatal("disasmInstRows returned nothing")
			}
			plain := ansi.Strip(rows[0])

			// The assembly *field* begins at Asm; everything before it is the lead
			// space, the address and (maybe) the byte column. The mnemonic itself sits
			// further right, because AlignAsm right-aligns it within the field — so
			// look for the aligned text, not the bare mnemonic.
			aligned := dump.AlignAsm(inst.Text)
			at := strings.Index(plain, aligned)
			if at < 0 {
				t.Fatalf("aligned assembly %q not found in row %q", aligned, plain)
			}
			if at != cols.Asm {
				t.Errorf("assembly field renders at column %d but Columns.Asm says %d\n  row: %q",
					at, cols.Asm, plain)
			}
			// And nothing but padding precedes it beyond the address/byte columns.
			if got := len(plain[:at]); got != cols.Asm {
				t.Errorf("prefix width %d != Asm %d", got, cols.Asm)
			}
		})
	}
}

// TestByteColumnWidthMatchesTheRenderedBytes pins ByteColW to what disasmBytes
// actually prints, in both the compact and spaced spellings.
func TestByteColumnWidthMatchesTheRenderedBytes(t *testing.T) {
	for _, spaced := range []bool{false, true} {
		m := goldenModel(t)
		m.cfg = config.Config{Theme: defaultThemeName}
		m.cfg.Behavior.SpacedDisasmBytes = spaced
		enterMode(t, m, modeDisasm)
		if len(m.dasm.Inst) == 0 {
			t.Fatal("fixture decoded no instructions")
		}
		cols := m.disasmColumns()
		// The longest encoding the column is sized for; a shorter instruction pads
		// to the same width, which is what keeps the assembly column straight.
		for _, inst := range m.dasm.Inst {
			if got := ansi.StringWidth(disasmview.InstBytes(m.viewContextPtr(), inst.Bytes)); got != cols.ByteColW {
				t.Fatalf("spaced=%v: disasmBytes(%d bytes) printed width %d, ByteColW = %d",
					spaced, len(inst.Bytes), got, cols.ByteColW)
			}
		}
	}
}
