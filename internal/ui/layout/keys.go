package layout

import "strings"

// CtrlKeys renders a Ctrl-chord list as "^t" / "^t/^f": each key gets a caret,
// joined with "/". Compact and identical on every platform.
func CtrlKeys(keys ...string) string {
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = "^" + k
	}
	return strings.Join(parts, "/")
}

// AppendAddr writes "0x" + addr, zero-padded to digits hex chars, into dst —
// what fmt.Sprintf("0x%0*x", digits, addr) produces, without fmt's boxing and
// its intermediate string. The hex and disasm views format an address for every
// visible row, on every frame.
func AppendAddr(dst []byte, addr uint64, digits int) []byte {
	const hexDigits = "0123456789abcdef"
	var tmp [16]byte // a uint64 is at most 16 hex digits
	n := 0
	for {
		tmp[n] = hexDigits[addr&0xf]
		n++
		addr >>= 4
		if addr == 0 {
			break
		}
	}
	dst = append(dst, '0', 'x')
	for i := n; i < digits; i++ {
		dst = append(dst, '0')
	}
	for i := n - 1; i >= 0; i-- {
		dst = append(dst, tmp[i])
	}
	return dst
}
