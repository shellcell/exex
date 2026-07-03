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
