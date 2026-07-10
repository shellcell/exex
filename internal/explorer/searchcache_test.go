package explorer_test

import (
	"testing"

	"github.com/rabarbra/exex/internal/explorer"
)

// hits builds a cache pre-loaded with the given addresses, in one Add.
func hitsAt(addrs ...uint64) []explorer.SearchHit {
	out := make([]explorer.SearchHit, len(addrs))
	for i, a := range addrs {
		out[i] = explorer.SearchHit{Addr: a, Text: "mov"}
	}
	return out
}

func hitAddrs(hs []explorer.SearchHit) []uint64 {
	out := make([]uint64, len(hs))
	for i, h := range hs {
		out[i] = h.Addr
	}
	return out
}

func sameAddrs(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestResetClearsEverything(t *testing.T) {
	var c explorer.SearchCache
	c.Reset("mov")
	c.Add(hitsAt(1, 2), true)
	c.NoteCoverage(0, 100)
	c.SetExhausted(true)

	c.Reset("call")
	if c.Query() != "call" {
		t.Errorf("Query() = %q, want %q", c.Query(), "call")
	}
	if len(c.Hits()) != 0 {
		t.Errorf("Reset kept %d hits", len(c.Hits()))
	}
	if c.Exhausted(true) || c.Exhausted(false) {
		t.Error("Reset kept an exhaustion flag")
	}
	// scannedLo must go back to -1, not 0: 0 means "the image start was scanned",
	// which would let Complete() pass over an unscanned image.
	if lo, hi := c.Coverage(); lo != -1 || hi != 0 {
		t.Errorf("Coverage() = (%d,%d), want (-1,0)", lo, hi)
	}
	if c.Complete(1000) {
		t.Error("a freshly reset cache reported Complete")
	}
}

func TestEnsureQueryResetsOnlyOnChange(t *testing.T) {
	var c explorer.SearchCache
	c.Reset("mov")
	c.Add(hitsAt(1, 2), true)

	if c.EnsureQuery("mov") {
		t.Error("EnsureQuery reported a reset for the same query")
	}
	if len(c.Hits()) != 2 {
		t.Fatalf("the same query dropped hits: %d", len(c.Hits()))
	}
	if !c.EnsureQuery("call") {
		t.Error("EnsureQuery did not report a reset for a new query")
	}
	if len(c.Hits()) != 0 {
		t.Errorf("a new query kept %d hits", len(c.Hits()))
	}
}

// TestAddSortsAndDedupes: chunks arrive out of order and overlap at their seams,
// so the same address can be reported twice.
func TestAddSortsAndDedupes(t *testing.T) {
	var c explorer.SearchCache
	c.Reset("mov")
	c.Add(hitsAt(0x30, 0x10, 0x20), true)
	c.Add(hitsAt(0x20, 0x05, 0x40), true) // 0x20 is a duplicate from the seam

	want := []uint64{0x05, 0x10, 0x20, 0x30, 0x40}
	if got := hitAddrs(c.Hits()); !sameAddrs(got, want) {
		t.Errorf("Hits() = %#x, want %#x", got, want)
	}
	if c.Overflow() {
		t.Error("five hits overflowed a cache of 100")
	}
}

func TestAddEmptyIsANoop(t *testing.T) {
	var c explorer.SearchCache
	c.Reset("mov")
	c.Add(nil, true)
	if len(c.Hits()) != 0 || c.Overflow() {
		t.Error("adding nothing changed the cache")
	}
}

// TestOverflowIsSetOnlyPastTheCap: exactly CacheCap distinct hits still hold
// *every* hit, so the cache is complete and Complete() may return true.
func TestOverflowIsSetOnlyPastTheCap(t *testing.T) {
	var c explorer.SearchCache
	c.Reset("mov")
	full := make([]uint64, explorer.CacheCap)
	for i := range full {
		full[i] = uint64(i + 1)
	}
	c.Add(hitsAt(full...), true)
	if c.Overflow() {
		t.Fatalf("exactly %d hits set the overflow flag", explorer.CacheCap)
	}
	if len(c.Hits()) != explorer.CacheCap {
		t.Fatalf("kept %d hits, want %d", len(c.Hits()), explorer.CacheCap)
	}

	// A duplicate is not a new hit and must not trip overflow.
	c.Add(hitsAt(1), true)
	if c.Overflow() {
		t.Error("re-adding a cached address set the overflow flag")
	}

	c.Add(hitsAt(uint64(explorer.CacheCap+1)), true)
	if !c.Overflow() {
		t.Error("exceeding the cap did not set the overflow flag")
	}
}

// TestAddTrimsTowardTheDirectionOfTravel is why Add takes `forward`: past the cap
// the useful hits are the ones the user is walking toward.
func TestAddTrimsTowardTheDirectionOfTravel(t *testing.T) {
	n := explorer.CacheCap + 10
	all := make([]uint64, n)
	for i := range all {
		all[i] = uint64(i + 1) // 1 .. cap+10
	}

	t.Run("forward keeps the highest addresses", func(t *testing.T) {
		var c explorer.SearchCache
		c.Reset("mov")
		c.Add(hitsAt(all...), true)
		got := hitAddrs(c.Hits())
		if len(got) != explorer.CacheCap {
			t.Fatalf("kept %d hits, want %d", len(got), explorer.CacheCap)
		}
		if got[0] != 11 || got[len(got)-1] != uint64(n) {
			t.Errorf("kept [%d..%d], want the top window [11..%d]", got[0], got[len(got)-1], n)
		}
	})

	t.Run("backward keeps the lowest addresses", func(t *testing.T) {
		var c explorer.SearchCache
		c.Reset("mov")
		c.Add(hitsAt(all...), false)
		got := hitAddrs(c.Hits())
		if len(got) != explorer.CacheCap {
			t.Fatalf("kept %d hits, want %d", len(got), explorer.CacheCap)
		}
		if got[0] != 1 || got[len(got)-1] != uint64(explorer.CacheCap) {
			t.Errorf("kept [%d..%d], want the bottom window [1..%d]", got[0], got[len(got)-1], explorer.CacheCap)
		}
	})
}

func TestNoteCoverageWidensAndClamps(t *testing.T) {
	var c explorer.SearchCache
	c.Reset("mov")

	c.NoteCoverage(100, 200)
	if lo, hi := c.Coverage(); lo != 100 || hi != 200 {
		t.Fatalf("Coverage() = (%d,%d), want (100,200)", lo, hi)
	}
	// A narrower range must not shrink the covered span.
	c.NoteCoverage(120, 180)
	if lo, hi := c.Coverage(); lo != 100 || hi != 200 {
		t.Errorf("a narrower range shrank coverage to (%d,%d)", lo, hi)
	}
	c.NoteCoverage(50, 300)
	if lo, hi := c.Coverage(); lo != 50 || hi != 300 {
		t.Errorf("Coverage() = (%d,%d), want (50,300)", lo, hi)
	}
	// A chunk's lead-in can start before the image; it clamps rather than
	// poisoning scannedLo with a negative.
	c.NoteCoverage(-64, 10)
	if lo, _ := c.Coverage(); lo != 0 {
		t.Errorf("negative lo left scannedLo = %d, want 0", lo)
	}
	// An inverted range collapses to a point instead of moving hi backwards.
	c.NoteCoverage(400, 350)
	if _, hi := c.Coverage(); hi != 400 {
		t.Errorf("inverted range left scannedHi = %d, want 400", hi)
	}
}

// TestCompleteNeedsTheWholeImageAndNoDrops: Complete() is what lets a repeat
// search skip scanning entirely, so every one of its three conditions matters.
func TestCompleteNeedsTheWholeImageAndNoDrops(t *testing.T) {
	const imgLen = 1000

	t.Run("whole image, nothing dropped", func(t *testing.T) {
		var c explorer.SearchCache
		c.Reset("mov")
		c.NoteCoverage(0, imgLen)
		if !c.Complete(imgLen) {
			t.Error("a fully scanned, non-overflowing cache is not Complete")
		}
	})

	t.Run("a scan that never reached the image start", func(t *testing.T) {
		var c explorer.SearchCache
		c.Reset("mov")
		c.NoteCoverage(1, imgLen)
		if c.Complete(imgLen) {
			t.Error("Complete ignored the unscanned prefix")
		}
	})

	t.Run("a scan that never reached the image end", func(t *testing.T) {
		var c explorer.SearchCache
		c.Reset("mov")
		c.NoteCoverage(0, imgLen-1)
		if c.Complete(imgLen) {
			t.Error("Complete ignored the unscanned suffix")
		}
	})

	t.Run("a full scan that dropped hits", func(t *testing.T) {
		var c explorer.SearchCache
		c.Reset("mov")
		c.NoteCoverage(0, imgLen)
		over := make([]uint64, explorer.CacheCap+1)
		for i := range over {
			over[i] = uint64(i + 1)
		}
		c.Add(hitsAt(over...), true)
		if !c.Overflow() {
			t.Fatal("the setup did not overflow")
		}
		if c.Complete(imgLen) {
			t.Error("an overflowed cache reported Complete; a repeat search would skip real hits")
		}
	})

	t.Run("nothing scanned", func(t *testing.T) {
		var c explorer.SearchCache
		c.Reset("mov")
		if c.Complete(imgLen) {
			t.Error("an unscanned cache reported Complete")
		}
		// The empty image is the one case where scanning nothing suffices, but only
		// once coverage has actually been recorded.
		if c.Complete(0) {
			t.Error("scannedLo == -1 reported Complete even for an empty image")
		}
	})
}

func TestExhaustedIsPerDirection(t *testing.T) {
	var c explorer.SearchCache
	c.Reset("mov")
	if c.Exhausted(true) || c.Exhausted(false) {
		t.Fatal("a fresh cache is exhausted")
	}
	c.SetExhausted(true)
	if !c.Exhausted(true) {
		t.Error("forward exhaustion did not stick")
	}
	if c.Exhausted(false) {
		t.Error("forward exhaustion leaked into the backward direction")
	}
	c.SetExhausted(false)
	if !c.Exhausted(false) {
		t.Error("backward exhaustion did not stick")
	}
}

func TestNextOnAnEmptyCache(t *testing.T) {
	var c explorer.SearchCache
	c.Reset("mov")
	for _, forward := range []bool{true, false} {
		if _, ok := c.Next(0x100, explorer.CursorAtMatch, forward, true); ok {
			t.Errorf("forward=%v: an empty cache answered Next", forward)
		}
	}
}

// TestNextFromAMatch covers the interesting axis: `inclusive` decides whether a
// hit sitting exactly on the cursor counts. The initial Enter says yes; n and N
// say no, so they step off the current match instead of finding it again.
func TestNextFromAMatch(t *testing.T) {
	var c explorer.SearchCache
	c.Reset("mov")
	c.Add(hitsAt(0x10, 0x20, 0x30), true)

	for _, tc := range []struct {
		name      string
		cur       uint64
		forward   bool
		inclusive bool
		want      uint64
		wantOK    bool
	}{
		{"forward, inclusive, on a hit stays put", 0x20, true, true, 0x20, true},
		{"forward, exclusive, on a hit steps past", 0x20, true, false, 0x30, true},
		{"forward, between hits", 0x18, true, false, 0x20, true},
		{"forward, past the last hit", 0x30, true, false, 0, false},
		{"forward, inclusive on the last hit", 0x30, true, true, 0x30, true},
		{"forward, before the first hit", 0x00, true, false, 0x10, true},

		{"backward, inclusive, on a hit stays put", 0x20, false, true, 0x20, true},
		{"backward, exclusive, on a hit steps past", 0x20, false, false, 0x10, true},
		{"backward, between hits", 0x28, false, false, 0x20, true},
		{"backward, before the first hit", 0x10, false, false, 0, false},
		{"backward, inclusive on the first hit", 0x10, false, true, 0x10, true},
		{"backward, past the last hit", 0x99, false, false, 0x30, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hit, ok := c.Next(tc.cur, explorer.CursorAtMatch, tc.forward, tc.inclusive)
			if ok != tc.wantOK || (ok && hit.Addr != tc.want) {
				t.Errorf("Next(%#x, forward=%v, inclusive=%v) = (%#x, %v), want (%#x, %v)",
					tc.cur, tc.forward, tc.inclusive, hit.Addr, ok, tc.want, tc.wantOK)
			}
		})
	}
}

// TestNextWrapsWhenTheCursorRanOffAnEnd: after a forward search hit the end,
// searching backward must land on the last hit rather than measuring against a
// cursor address that no longer means anything. This is the whole reason
// CursorMode exists.
func TestNextWrapsWhenTheCursorRanOffAnEnd(t *testing.T) {
	var c explorer.SearchCache
	c.Reset("mov")
	c.Add(hitsAt(0x10, 0x20, 0x30), true)

	t.Run("after the end, backward lands on the last hit", func(t *testing.T) {
		// cur is deliberately below every hit: were the mode ignored, the exclusive
		// backward walk would find nothing.
		hit, ok := c.Next(0x00, explorer.CursorAfterEnd, false, false)
		if !ok || hit.Addr != 0x30 {
			t.Errorf("Next = (%#x, %v), want (0x30, true)", hit.Addr, ok)
		}
	})

	t.Run("before the start, forward lands on the first hit", func(t *testing.T) {
		hit, ok := c.Next(0x99, explorer.CursorBeforeStart, true, false)
		if !ok || hit.Addr != 0x10 {
			t.Errorf("Next = (%#x, %v), want (0x10, true)", hit.Addr, ok)
		}
	})

	// The mode only overrides the *opposite* direction. Continuing forward after
	// running off the end still finds nothing, which is what makes the search
	// report "not found" rather than silently wrapping.
	t.Run("after the end, forward still finds nothing", func(t *testing.T) {
		if hit, ok := c.Next(0x30, explorer.CursorAfterEnd, true, false); ok {
			t.Errorf("Next found %#x past the end", hit.Addr)
		}
	})

	t.Run("before the start, backward still finds nothing", func(t *testing.T) {
		if hit, ok := c.Next(0x10, explorer.CursorBeforeStart, false, false); ok {
			t.Errorf("Next found %#x before the start", hit.Addr)
		}
	})
}

func TestBoundary(t *testing.T) {
	var c explorer.SearchCache
	c.Reset("mov")
	if _, ok := c.Boundary(true); ok {
		t.Error("an empty cache has a boundary")
	}
	c.Add(hitsAt(0x30, 0x10, 0x20), true)

	if got, ok := c.Boundary(true); !ok || got != 0x30 {
		t.Errorf("Boundary(forward) = (%#x, %v), want (0x30, true)", got, ok)
	}
	if got, ok := c.Boundary(false); !ok || got != 0x10 {
		t.Errorf("Boundary(backward) = (%#x, %v), want (0x10, true)", got, ok)
	}
}
