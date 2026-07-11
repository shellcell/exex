// Package bytesearch turns UI search queries into byte patterns and scans byte
// slices in either direction.
package bytesearch

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

// String returns the user-facing name of the search mode.
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

// NextMode cycles Auto -> Text -> Hex -> Auto.
func NextMode(m Mode) Mode {
	return (m + 1) % 3
}

// kind is how a query is to be interpreted, decided once by classify.
type kind uint8

const (
	kindQuoted kind = iota // "quoted text" -> the bytes between the quotes
	kindText               // literal text bytes of the raw query
	kindHex                // hex byte pattern
)

// classify decides how q is read under mode. ParsePattern and IsTextPattern both
// consult it, so the two can't disagree about what a query means — they used to
// duplicate this rule set, and a change to one silently skipped the other.
//
// It returns the trimmed query and its compacted hex form so callers don't
// recompute them.
func classify(q string, mode Mode) (k kind, trimmed, compact string) {
	trimmed = strings.TrimSpace(q)
	quoted := len(trimmed) >= 2 && trimmed[0] == '"' && trimmed[len(trimmed)-1] == '"'

	switch mode {
	case ModeText:
		if quoted {
			return kindQuoted, trimmed, ""
		}
		return kindText, trimmed, ""
	case ModeHex:
		return kindHex, trimmed, compactHexPattern(trimmed)
	}

	// ModeAuto: quotes force text; otherwise an untrimmed-clean, even-length run
	// of hex digits is a byte pattern. Requiring q == trimmed means a query with
	// surrounding spaces stays a text search (the spaces are searchable).
	if quoted {
		return kindQuoted, trimmed, ""
	}
	compact = compactHexPattern(trimmed)
	if q == trimmed && len(compact) >= 2 && len(compact)%2 == 0 && isHexStr(compact) {
		return kindHex, trimmed, compact
	}
	return kindText, trimmed, compact
}

// ParsePattern interprets a query as bytes or text:
//   - "quoted text"   -> literal bytes of the text
//   - hex digits / 0x -> byte pattern (spaces allowed: "de ad be ef")
//   - anything else   -> literal text bytes
func ParsePattern(q string, mode Mode) []byte {
	switch k, trimmed, compact := classify(q, mode); k {
	case kindQuoted:
		return []byte(trimmed[1 : len(trimmed)-1])
	case kindHex:
		return parseHexPattern(compact)
	default:
		return []byte(q)
	}
}

// IsTextPattern reports whether ParsePattern would treat q as literal text (so
// case-folding is meaningful) rather than a hex byte pattern (where it isn't).
func IsTextPattern(q string, mode Mode) bool {
	k, _, _ := classify(q, mode)
	return k != kindHex
}

// compactHexPattern removes whitespace and an optional 0x/0X prefix.
func compactHexPattern(s string) string {
	compact := strings.Join(strings.Fields(s), "")
	compact = strings.TrimPrefix(compact, "0x")
	compact = strings.TrimPrefix(compact, "0X")
	return compact
}

// parseHexPattern decodes an even-length string of hex digits.
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

// FindBytesFold is FindBytes with optional ASCII case-insensitive matching. With
// fold=false it is FindBytes (the fast exact bytes.Index). With fold=true it
// matches letters ignoring ASCII case — for text patterns; a byte-value pattern
// (hex) simply won't contain letters to fold, so callers can always pass the
// view's case flag.
func FindBytesFold(data, pat []byte, start int, forward, fold bool) int {
	if !fold {
		return FindBytes(data, pat, start, forward)
	}
	if len(pat) == 0 || len(pat) > len(data) {
		return -1
	}
	if forward {
		if start < 0 {
			start = 0
		}
		for i := start; i <= len(data)-len(pat); i++ {
			if equalFoldASCII(data[i:i+len(pat)], pat) {
				return i
			}
		}
		return -1
	}
	end := start + len(pat)
	if end > len(data) {
		end = len(data)
	}
	for i := end - len(pat); i >= 0; i-- {
		if equalFoldASCII(data[i:i+len(pat)], pat) {
			return i
		}
	}
	return -1
}

// equalFoldASCII reports whether a and b are equal ignoring ASCII letter case.
func equalFoldASCII(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if lowerASCII(a[i]) != lowerASCII(b[i]) {
			return false
		}
	}
	return true
}

func lowerASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

// isHexStr reports whether s is non-empty and contains only hex digits.
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
