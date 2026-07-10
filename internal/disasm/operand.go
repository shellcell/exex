package disasm

import "strconv"

// FindAddrOperand finds the first 0x-prefixed hex literal in an instruction's
// operand text at or after `from`, returning its value and the byte range it
// occupies. It is the primitive under address highlighting, target annotation,
// branch following and the xref scan, all of which then ask the binary whether
// the value is actually mapped.
//
// A "0x…" immediately preceded by '#' is an ARM immediate ("[sp,#0x8]", "mov
// x0,#0x10"), never an address, and is skipped. Nothing else is filtered here:
// an x86 AT&T immediate is written "$0x401000" and genuinely can be an address
// load, so the caller's mapped-address check is what separates the two.
func FindAddrOperand(text string, from int) (addr uint64, start, end int, ok bool) {
	search := from
	var idx int
	for {
		rel := indexFrom(text, search)
		if rel < 0 {
			return 0, 0, 0, false
		}
		idx = rel
		if idx > 0 && text[idx-1] == '#' {
			search = idx + 2 // ARM immediate, not an address — keep looking
			continue
		}
		break
	}
	rest := text[idx+2:]
	n := 0
	for n < len(rest) && isHexDigit(rest[n]) {
		n++
	}
	if n == 0 {
		return 0, 0, 0, false
	}
	v, err := strconv.ParseUint(rest[:n], 16, 64)
	if err != nil {
		return 0, 0, 0, false
	}
	return v, idx, idx + 2 + n, true
}

// indexFrom returns the absolute index of the next "0x" at or after `from`, or
// -1. A `from` at or past the end finds nothing, which is what the skip-ahead
// above relies on when the text ends in "#0x".
func indexFrom(text string, from int) int {
	for i := from; i+1 < len(text); i++ {
		if text[i] == '0' && text[i+1] == 'x' {
			return i
		}
	}
	return -1
}
