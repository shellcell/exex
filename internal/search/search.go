package search

import (
	"bytes"
	"strconv"
	"strings"
)

// Mode controls how a query is interpreted when searching byte-oriented views.
type Mode uint8

const (
	ModeAuto Mode = iota
	ModeText
	ModeHex
)

func (m Mode) String() string {
	switch m {
	case ModeText:
		return "text"
	case ModeHex:
		return "hex"
	default:
		return "auto"
	}
}

func NextMode(m Mode) Mode {
	return (m + 1) % 3
}

// ParsePattern interprets a query as bytes or text:
//   - "quoted text"   -> literal bytes of the text
//   - hex digits / 0x -> byte pattern (spaces allowed: "de ad be ef")
//   - anything else   -> literal text bytes
func ParsePattern(q string, mode Mode) []byte {
	trimmed := strings.TrimSpace(q)
	if mode == ModeText {
		if len(trimmed) >= 2 && trimmed[0] == '"' && trimmed[len(trimmed)-1] == '"' {
			return []byte(trimmed[1 : len(trimmed)-1])
		}
		return []byte(q)
	}
	if mode == ModeHex {
		compact := strings.TrimPrefix(strings.ReplaceAll(trimmed, " ", ""), "0x")
		return parseHexPattern(compact)
	}
	if len(trimmed) >= 2 && trimmed[0] == '"' && trimmed[len(trimmed)-1] == '"' {
		return []byte(trimmed[1 : len(trimmed)-1])
	}
	compact := strings.TrimPrefix(strings.ReplaceAll(trimmed, " ", ""), "0x")
	if q == trimmed && len(compact) >= 2 && len(compact)%2 == 0 && isHexStr(compact) {
		return parseHexPattern(compact)
	}
	return []byte(q)
}

func parseHexPattern(compact string) []byte {
	if len(compact)%2 != 0 || !isHexStr(compact) {
		return nil
	}
	b := make([]byte, len(compact)/2)
	for i := range b {
		v, _ := strconv.ParseUint(compact[2*i:2*i+2], 16, 8)
		b[i] = byte(v)
	}
	return b
}

// FindBytes returns the index of pat in data at or after (forward) / at or
// before (backward) start, or -1.
func FindBytes(data, pat []byte, start int, forward bool) int {
	if len(pat) == 0 || len(pat) > len(data) {
		return -1
	}
	if forward {
		if start < 0 {
			start = 0
		}
		if start > len(data)-len(pat) {
			return -1
		}
		if j := bytes.Index(data[start:], pat); j >= 0 {
			return start + j
		}
		return -1
	}
	end := start + len(pat)
	if end > len(data) {
		end = len(data)
	}
	if end < len(pat) {
		return -1
	}
	return bytes.LastIndex(data[:end], pat)
}

func isHexStr(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
