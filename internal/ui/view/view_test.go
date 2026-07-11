package view

import (
	"testing"
	"unsafe"
)

// TestContextStaysSmall locks in the size budget behind the Context/Styles
// split: Context is passed by value through every view helper, often per
// visible row, so everything outside the embedded *Styles pointer must stay a
// few machine words. Growing Context past this bound reintroduces the ~13 KB
// per-row copy the split removed (a measured ~60% hex-render slowdown); new
// styles, closures, and settings belong on Styles instead.
func TestContextStaysSmall(t *testing.T) {
	const maxContextBytes = 64
	if got := unsafe.Sizeof(Context{}); got > maxContextBytes {
		t.Fatalf("view.Context = %d bytes (budget %d): move new fields to view.Styles, not Context", got, maxContextBytes)
	}
}
