package disasm

import (
	"strconv"
	"strings"
	"testing"
)

func TestFindAddrOperand(t *testing.T) {
	for _, tc := range []struct {
		name  string
		text  string
		from  int
		addr  uint64
		start int
		end   int
		ok    bool
	}{
		{name: "no hex at all", text: "ret", ok: false},
		{name: "bare call target", text: "call 0x401020", addr: 0x401020, start: 5, end: 13, ok: true},
		{name: "x86 AT&T immediate is a candidate", text: "mov $0x401000,%rax", addr: 0x401000, start: 5, end: 13, ok: true},
		{name: "uppercase hex digits", text: "jmp 0xDEADBEEF", addr: 0xdeadbeef, start: 4, end: 14, ok: true},

		// The ARM rule: '#' immediately before "0x" marks an immediate.
		{name: "arm immediate skipped", text: "ldr x0,[sp,#0x8]", ok: false},
		{name: "arm immediate skipped, real target after", text: "ldr x0,[sp,#0x8]; b 0x1000", addr: 0x1000, start: 20, end: 26, ok: true},
		{name: "hash not adjacent is not an immediate", text: "b # 0x1000", addr: 0x1000, start: 4, end: 10, ok: true},
		{name: "trailing arm immediate does not run off the end", text: "mov x0,#0x", ok: false},
		{name: "arm immediate at the very end", text: "add sp,sp,#0x10", ok: false},

		// "0x" with no digits after it is not a number.
		{name: "0x with no digits", text: "0x", ok: false},
		{name: "0x followed by a separator", text: "0x,", ok: false},
		{name: "0x then non-hex letter", text: "0xz1", ok: false},
		{name: "0x then 0x", text: "0x0x10", addr: 0x0, start: 0, end: 3, ok: true},

		// `from` positioning: callers loop by passing back the previous `end`.
		{name: "from skips the first", text: "cmp 0x10,0x20", from: 8, addr: 0x20, start: 9, end: 13, ok: true},
		{name: "from past the end", text: "call 0x10", from: 99, ok: false},
		{name: "from exactly at the end", text: "call 0x10", from: 9, ok: false},
		{name: "from at the last byte", text: "call 0x10", from: 8, ok: false},

		{name: "value overflows 64 bits", text: "0x1ffffffffffffffff", ok: false},
		{name: "max uint64", text: "0xffffffffffffffff", addr: 1<<64 - 1, start: 0, end: 18, ok: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, start, end, ok := FindAddrOperand(tc.text, tc.from)
			if ok != tc.ok {
				t.Fatalf("FindAddrOperand(%q, %d) ok = %v, want %v", tc.text, tc.from, ok, tc.ok)
			}
			if !ok {
				return
			}
			if addr != tc.addr || start != tc.start || end != tc.end {
				t.Errorf("FindAddrOperand(%q, %d) = (%#x, %d, %d), want (%#x, %d, %d)",
					tc.text, tc.from, addr, start, end, tc.addr, tc.start, tc.end)
			}
			// The returned range must actually delimit the literal, since callers
			// use it both to colour the span and to resume scanning.
			if got := tc.text[start:end]; got != "0x"+strings.TrimPrefix(got, "0x") || !strings.HasPrefix(got, "0x") {
				t.Errorf("range %d:%d = %q, which is not a 0x literal", start, end, got)
			}
		})
	}
}

// TestFindAddrOperandLoopTerminates: every caller drives this in a `from = end`
// loop, so a call that reports ok must always advance.
func TestFindAddrOperandLoopTerminates(t *testing.T) {
	for _, text := range []string{
		"call 0x10", "0x0x0x0", "mov $0x1,%rax; jmp 0x2", "ldr x0,[sp,#0x8]", "0x", "#0x1 0x2",
	} {
		from, n := 0, 0
		for {
			_, _, end, ok := FindAddrOperand(text, from)
			if !ok {
				break
			}
			if end <= from {
				t.Fatalf("%q: from=%d did not advance (end=%d)", text, from, end)
			}
			from = end
			if n++; n > len(text)+2 {
				t.Fatalf("%q: loop did not terminate", text)
			}
		}
	}
}

// original is the implementation this was extracted from, verbatim. The fuzz
// test below pins the rewrite to it: the inner "0x" scan was rewritten from a
// strings.Index-on-a-suffix to an absolute index walk, and only a differential
// check proves that did not change what the view highlights.
func original(text string, from int) (addr uint64, start, end int, ok bool) {
	search := from
	var idx int
	for {
		rel := strings.Index(text[search:], "0x")
		if rel < 0 {
			return 0, 0, 0, false
		}
		idx = search + rel
		if idx > 0 && text[idx-1] == '#' {
			search = idx + 2
			continue
		}
		break
	}
	rest := text[idx+2:]
	n := 0
	for n < len(rest) {
		c := rest[n]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			n++
			continue
		}
		break
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

func FuzzFindAddrOperandMatchesOriginal(f *testing.F) {
	for _, s := range []string{
		"call 0x401020", "ldr x0,[sp,#0x8]", "mov $0x1,%rax", "0x", "#0x", "0x0x10",
		"b # 0x1000", "add sp,sp,#0x10", "0xffffffffffffffff", "jmp 0xDEADBEEF", "",
	} {
		for _, from := range []int{0, 1, 2, 5} {
			f.Add(s, from)
		}
	}
	f.Fuzz(func(t *testing.T, text string, from int) {
		// The original panics on a negative or past-the-end `from`; callers never
		// pass one. Match the contract, not the crash.
		if from < 0 || from > len(text) {
			return
		}
		wAddr, wStart, wEnd, wOK := original(text, from)
		gAddr, gStart, gEnd, gOK := FindAddrOperand(text, from)
		if gOK != wOK || gAddr != wAddr || gStart != wStart || gEnd != wEnd {
			t.Fatalf("FindAddrOperand(%q, %d) = (%#x,%d,%d,%v), original = (%#x,%d,%d,%v)",
				text, from, gAddr, gStart, gEnd, gOK, wAddr, wStart, wEnd, wOK)
		}
	})
}
