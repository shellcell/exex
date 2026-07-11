package disasm

import "sort"

// Address lookups over a decoded, address-ordered instruction slice.
//
// Every caller holds such a slice — the disassembly view's window, a function's
// extent, a search result — and asks the same three questions of it. The answers
// are pure functions of the slice, with boundary cases (an address inside an
// instruction's bytes, an address past the last one) that are easy to get subtly
// wrong, so they live here with the type rather than in whoever needs them.
//
// All three assume insts is sorted by Addr, which every decode path produces.

// IndexForAddr finds the instruction covering addr, or the nearest one at a lower
// address. ok reports whether addr actually falls within the returned
// instruction's bytes (or is exactly its start).
//
// When addr precedes every instruction, it returns (0, false).
func IndexForAddr(insts []Inst, addr uint64) (idx int, ok bool) {
	if len(insts) == 0 {
		return 0, false
	}
	i := sort.Search(len(insts), func(i int) bool { return insts[i].Addr > addr })
	if i == 0 {
		return 0, false
	}
	j := i - 1
	in := insts[j]
	if addr >= in.Addr && addr < in.Addr+uint64(len(in.Bytes)) {
		return j, true
	}
	return j, in.Addr == addr
}

// IndexAtOrAfter returns the first instruction at or after addr, falling back to
// the last preceding instruction when there is no later one — so a caller
// scrolling to an address past the decoded window still lands on real code.
func IndexAtOrAfter(insts []Inst, addr uint64) int {
	if len(insts) == 0 {
		return 0
	}
	if idx, ok := IndexForAddr(insts, addr); ok {
		return idx
	}
	if i := sort.Search(len(insts), func(i int) bool { return insts[i].Addr >= addr }); i < len(insts) {
		return i
	}
	return len(insts) - 1
}

// HasExact reports whether an instruction starts exactly at addr. It is stricter
// than IndexForAddr's ok, which also accepts an address inside an instruction's
// bytes.
func HasExact(insts []Inst, addr uint64) bool {
	i := sort.Search(len(insts), func(i int) bool { return insts[i].Addr >= addr })
	return i < len(insts) && insts[i].Addr == addr
}
