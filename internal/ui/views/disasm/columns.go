// Package disasm implements the disassembly view: the column geometry the rows
// are laid out on, and the rendering built over it.
package disasm

// Columns is the horizontal layout of a disassembly row:
//
//	 0x0000000000401020  48 c7 c0 01 00 00 00  mov $0x1,%rax        ; <helper>
//	^^                  ^                      ^                    ^
//	lead                byte column            Asm                  Annotation(w)
//
// Everything left of the assembly is fixed for a given file and settings, so a
// Columns is built once per frame and shared by every row. It used to be four
// methods on the shell that each recomputed the whole chain — including the
// arch's max instruction length — for every instruction, on every frame, and
// again for the whole list whenever a resize or wrap toggle rewarmed the
// row-height cache.
type Columns struct {
	// AddrHexW is the number of hex digits in an address, after "0x".
	AddrHexW int
	// InstByteW is the number of instruction bytes the byte column is sized for:
	// the arch's longest encoding, so fixed-length RISC ISAs get a tight column
	// instead of x86's wide one.
	InstByteW int
	// ByteColW is the printed width of the instruction-byte column, or 0 when it
	// is hidden (behavior.hide_disasm_bytes).
	ByteColW int
	// Asm is the column the assembly text starts at.
	Asm int
}

const (
	leadSpace = 1 // the row's leading margin
	hexPrefix = 2 // "0x"
	colGap    = 2 // between the address, byte and assembly columns

	// annGap is how far after the assembly column an annotation prefers to sit:
	// close to the code, rather than drifting to mid-pane on a wide, source-off
	// view. A long instruction pushes its own annotation further right.
	annGap = 22
	// annMinGap is the smallest gap tolerated when the view is too narrow for
	// annGap, and annMargin is the room kept at the right edge.
	annMinGap = 8
	annMargin = 12
)

// NewColumns computes the row geometry. maxInstLen is the architecture's longest
// instruction encoding (disasm.MaxInstLen); hideBytes and spacedBytes are the
// behaviour settings. Spaced bytes print a space between each pair of hex
// digits, less the trailing one.
func NewColumns(addrHexW, maxInstLen int, hideBytes, spacedBytes bool) Columns {
	c := Columns{AddrHexW: addrHexW, InstByteW: maxInstLen}
	if !hideBytes {
		if spacedBytes {
			c.ByteColW = maxInstLen*3 - 1
		} else {
			c.ByteColW = maxInstLen * 2
		}
	}
	c.Asm = leadSpace + hexPrefix + addrHexW + colGap
	if c.ByteColW > 0 {
		c.Asm += c.ByteColW + colGap
	}
	return c
}

// Annotation returns the preferred column for the annotation text at a view
// width of w, pulled left when w cannot afford the full gap.
func (c Columns) Annotation(w int) int {
	col := c.Asm + annGap
	if hi := w - annMargin; col > hi {
		col = max(c.Asm+annMinGap, hi)
	}
	return col
}
