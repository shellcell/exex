package disasm

import "testing"

// The four formulas Columns replaced, verbatim from disasm_render.go. The
// equivalence test below sweeps every input the shell can produce and pins the
// new geometry to them; without it, a byte-column or gap change would only show
// up as a shifted golden frame.
func oldByteColW(maxInstLen int, hideBytes, spacedBytes bool) int {
	if hideBytes {
		return 0
	}
	if spacedBytes {
		return maxInstLen*3 - 1
	}
	return maxInstLen * 2
}

func oldAsmCol(addrHexW, maxInstLen int, hideBytes, spacedBytes bool) int {
	col := 1 + 2 + addrHexW + 2
	if bw := oldByteColW(maxInstLen, hideBytes, spacedBytes); bw > 0 {
		col += bw + 2
	}
	return col
}

func oldAnnCol(addrHexW, maxInstLen int, hideBytes, spacedBytes bool, w int) int {
	asm := oldAsmCol(addrHexW, maxInstLen, hideBytes, spacedBytes)
	col := asm + 22
	if hi := w - 12; col > hi {
		col = max(asm+8, hi)
	}
	return col
}

func TestColumnsMatchesTheOriginalFormulas(t *testing.T) {
	// addrHexW: 8 (32-bit) and 16 (64-bit) are real; the rest bracket them.
	// maxInstLen: 4 (RISC), 6 (s390x), 15 (x86-64) are the values disasm returns.
	for _, addrHexW := range []int{4, 8, 16} {
		for _, maxInstLen := range []int{4, 6, 15} {
			for _, hide := range []bool{false, true} {
				for _, spaced := range []bool{false, true} {
					c := NewColumns(addrHexW, maxInstLen, hide, spaced)
					if got, want := c.ByteColW, oldByteColW(maxInstLen, hide, spaced); got != want {
						t.Errorf("ByteColW(%d,%v,%v) = %d, want %d", maxInstLen, hide, spaced, got, want)
					}
					if got, want := c.Asm, oldAsmCol(addrHexW, maxInstLen, hide, spaced); got != want {
						t.Errorf("Asm(%d,%d,%v,%v) = %d, want %d", addrHexW, maxInstLen, hide, spaced, got, want)
					}
					// Widths from a 1-column terminal up past the widest sensible pane,
					// which is where Annotation's clamp switches branches.
					for w := 1; w <= 200; w++ {
						want := oldAnnCol(addrHexW, maxInstLen, hide, spaced, w)
						if got := c.Annotation(w); got != want {
							t.Errorf("Annotation(w=%d) with (%d,%d,%v,%v) = %d, want %d",
								w, addrHexW, maxInstLen, hide, spaced, got, want)
						}
					}
				}
			}
		}
	}
}

func TestByteColumnWidth(t *testing.T) {
	for _, tc := range []struct {
		name        string
		maxInstLen  int
		hide, space bool
		want        int
	}{
		{"x86 compact", 15, false, false, 30},
		{"x86 spaced drops the trailing space", 15, false, true, 44},
		{"arm64 compact", 4, false, false, 8},
		{"arm64 spaced", 4, false, true, 11},
		{"hidden beats spaced", 15, true, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := NewColumns(16, tc.maxInstLen, tc.hide, tc.space).ByteColW; got != tc.want {
				t.Errorf("ByteColW = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestHidingBytesRemovesTheColumnAndItsGap: the byte column's trailing gap must
// disappear with it, or the assembly sits two columns too far right.
func TestHidingBytesRemovesTheColumnAndItsGap(t *testing.T) {
	shown := NewColumns(16, 15, false, false)
	hidden := NewColumns(16, 15, true, false)
	if hidden.Asm != 1+2+16+2 {
		t.Errorf("hidden Asm = %d, want %d", hidden.Asm, 1+2+16+2)
	}
	if got, want := shown.Asm-hidden.Asm, shown.ByteColW+colGap; got != want {
		t.Errorf("showing bytes moved Asm by %d, want the column plus its gap (%d)", got, want)
	}
}

// TestAnnotationPrefersAFixedGapThenPullsLeft covers both branches of the clamp
// and the floor that stops it from crossing the assembly.
func TestAnnotationPrefersAFixedGapThenPullsLeft(t *testing.T) {
	c := NewColumns(16, 4, true, false) // Asm = 21
	if c.Asm != 21 {
		t.Fatalf("Asm = %d, want 21 (the test's arithmetic assumes it)", c.Asm)
	}
	for _, tc := range []struct {
		name string
		w    int
		want int
	}{
		// Wide enough for the full gap: Asm+22 = 43, and 43 <= w-12.
		{"wide view uses the preferred gap", 100, 43},
		{"exactly wide enough", 55, 43},
		// Narrower: pulled left to w-12, but never nearer than Asm+8 = 29.
		{"narrow view pulls left to the margin", 54, 42},
		{"narrower still", 45, 33},
		{"at the floor", 41, 29},
		{"below the floor stays at the floor", 20, 29},
		{"degenerate width stays at the floor", 1, 29},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := c.Annotation(tc.w); got != tc.want {
				t.Errorf("Annotation(%d) = %d, want %d", tc.w, got, tc.want)
			}
		})
	}
}

// TestAnnotationNeverCrossesTheAssembly: at any width, the annotation column has
// to leave room for at least a little assembly, or rows would overprint.
func TestAnnotationNeverCrossesTheAssembly(t *testing.T) {
	for _, addrHexW := range []int{8, 16} {
		for _, maxInstLen := range []int{4, 15} {
			for _, hide := range []bool{false, true} {
				c := NewColumns(addrHexW, maxInstLen, hide, false)
				for w := 1; w <= 300; w++ {
					if got := c.Annotation(w); got < c.Asm+annMinGap {
						t.Fatalf("Annotation(%d) = %d, which is nearer than Asm+%d (%d)",
							w, got, annMinGap, c.Asm+annMinGap)
					}
				}
			}
		}
	}
}
