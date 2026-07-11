package disasm

import "testing"

// insts: 0x1000 (4 bytes), 0x1004 (2 bytes), 0x1010 (1 byte).
// The gap between 0x1006 and 0x1010 is deliberate: an address there is covered by
// no instruction, but the nearest preceding one is still the useful answer.
func testInsts() []Inst {
	return []Inst{
		{Addr: 0x1000, Bytes: make([]byte, 4)},
		{Addr: 0x1004, Bytes: make([]byte, 2)},
		{Addr: 0x1010, Bytes: make([]byte, 1)},
	}
}

func TestIndexForAddr(t *testing.T) {
	insts := testInsts()
	for _, tc := range []struct {
		name    string
		addr    uint64
		wantIdx int
		wantOK  bool
	}{
		{"exact first", 0x1000, 0, true},
		{"inside first", 0x1002, 0, true},
		{"last byte of first", 0x1003, 0, true},
		{"exact second", 0x1004, 1, true},
		{"inside second", 0x1005, 1, true},
		{"just past second", 0x1006, 1, false}, // in the gap: nearest below, not covered
		{"in the gap", 0x100c, 1, false},
		{"exact third", 0x1010, 2, true},
		{"past the end", 0x2000, 2, false},
		{"before the start", 0x0fff, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idx, ok := IndexForAddr(insts, tc.addr)
			if idx != tc.wantIdx || ok != tc.wantOK {
				t.Errorf("IndexForAddr(%#x) = (%d, %v), want (%d, %v)", tc.addr, idx, ok, tc.wantIdx, tc.wantOK)
			}
		})
	}
}

func TestIndexForAddrEmpty(t *testing.T) {
	if idx, ok := IndexForAddr(nil, 0x1000); idx != 0 || ok {
		t.Errorf("IndexForAddr(nil) = (%d, %v), want (0, false)", idx, ok)
	}
}

func TestIndexAtOrAfter(t *testing.T) {
	insts := testInsts()
	for _, tc := range []struct {
		name string
		addr uint64
		want int
	}{
		{"exact", 0x1004, 1},
		{"inside an instruction", 0x1005, 1},
		{"in the gap rounds up", 0x1008, 2},
		{"before the start rounds up", 0x0fff, 0},
		// Past the last instruction there is nothing later, so the caller lands on
		// the last one rather than an out-of-range index.
		{"past the end clamps", 0x9999, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := IndexAtOrAfter(insts, tc.addr); got != tc.want {
				t.Errorf("IndexAtOrAfter(%#x) = %d, want %d", tc.addr, got, tc.want)
			}
		})
	}
}

func TestIndexAtOrAfterEmpty(t *testing.T) {
	if got := IndexAtOrAfter(nil, 0x1000); got != 0 {
		t.Errorf("IndexAtOrAfter(nil) = %d, want 0", got)
	}
}

// TestHasExactIsStricterThanIndexForAddr: an address inside an instruction's
// bytes is "covered" but is not an instruction start.
func TestHasExactIsStricterThanIndexForAddr(t *testing.T) {
	insts := testInsts()
	for _, tc := range []struct {
		addr uint64
		want bool
	}{
		{0x1000, true},
		{0x1002, false}, // inside the first instruction
		{0x1004, true},
		{0x1006, false}, // the gap
		{0x1010, true},
		{0x2000, false},
	} {
		if got := HasExact(insts, tc.addr); got != tc.want {
			t.Errorf("HasExact(%#x) = %v, want %v", tc.addr, got, tc.want)
		}
		if _, ok := IndexForAddr(insts, tc.addr); tc.addr == 0x1002 && !ok {
			t.Error("IndexForAddr should accept an address inside an instruction")
		}
	}
	if HasExact(nil, 0x1000) {
		t.Error("HasExact(nil) reported a hit")
	}
}
