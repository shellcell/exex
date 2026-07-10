package explorer

import (
	"math/rand"
	"slices"
	"testing"
)

// pushAll feeds addrs through the bounded heap the way ScanMatching does:
// consult wants first, then push.
func pushAll(limit int, addrs []uint64) lowestMatches {
	best := make(lowestMatches, 0, limit)
	for _, a := range addrs {
		if !best.wants(a, limit) {
			continue
		}
		best.push(Match{Addr: a}, limit)
	}
	return best
}

func sortedAddrs(h lowestMatches) []uint64 {
	out := make([]uint64, len(h))
	for i, hit := range h {
		out[i] = hit.Addr
	}
	slices.Sort(out)
	return out
}

// TestLowestMatchesNeverExceedsLimit is the memory bound: retained matches are
// capped by limit, not by the number of matches. ScanMatching used to accumulate
// every match (~98k for "mov" over a 15 MB binary) before truncating to 500.
func TestLowestMatchesNeverExceedsLimit(t *testing.T) {
	const limit = 500
	best := make(lowestMatches, 0, limit)
	rng := rand.New(rand.NewSource(1))
	for range 100_000 {
		a := rng.Uint64()
		if !best.wants(a, limit) {
			continue
		}
		best.push(Match{Addr: a}, limit)
		if len(best) > limit {
			t.Fatalf("heap grew to %d, limit %d", len(best), limit)
		}
	}
	if len(best) != limit {
		t.Errorf("heap holds %d matches, want %d", len(best), limit)
	}
	if cap(best) != limit {
		t.Errorf("heap reallocated: cap %d, want %d", cap(best), limit)
	}
}

// TestLowestMatchesKeepsGloballyLowest is the correctness fix. The old merge
// truncated in chunk-arrival order before sorting, so a low address discovered
// late lost to a high address discovered early. Feeding descending addresses
// (worst case for arrival order) must still yield the lowest `limit`.
func TestLowestMatchesKeepsGloballyLowest(t *testing.T) {
	const limit = 10
	var descending []uint64
	for a := uint64(100); a > 0; a-- {
		descending = append(descending, a)
	}
	got := sortedAddrs(pushAll(limit, descending))
	for i, a := range got {
		if want := uint64(i + 1); a != want {
			t.Fatalf("addr[%d] = %d, want %d (heap did not keep the globally lowest)", i, a, want)
		}
	}
}

// TestLowestMatchesOrderIndependent: the result must not depend on the order
// workers happen to report matches in, which is nondeterministic across chunks.
func TestLowestMatchesOrderIndependent(t *testing.T) {
	const limit = 50
	addrs := make([]uint64, 1000)
	for i := range addrs {
		addrs[i] = uint64(i) * 7 % 1000
	}
	want := sortedAddrs(pushAll(limit, addrs))

	rng := rand.New(rand.NewSource(7))
	for trial := range 20 {
		shuffled := slices.Clone(addrs)
		rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		got := sortedAddrs(pushAll(limit, shuffled))
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("trial %d: addr[%d] = %d, want %d", trial, i, got[i], want[i])
			}
		}
	}
}

func TestDedupeByAddr(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []uint64
		want []uint64
	}{
		{"empty", nil, nil},
		{"no dupes", []uint64{1, 2, 3}, []uint64{1, 2, 3}},
		{"adjacent dupes", []uint64{1, 1, 2, 2, 2, 3}, []uint64{1, 2, 3}},
		{"all same", []uint64{4, 4, 4}, []uint64{4}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hits := make([]Match, len(tc.in))
			for i, a := range tc.in {
				hits[i] = Match{Addr: a}
			}
			got := dedupeByAddr(hits)
			if len(got) != len(tc.want) {
				t.Fatalf("got %d matches, want %d", len(got), len(tc.want))
			}
			for i, h := range got {
				if h.Addr != tc.want[i] {
					t.Errorf("addr[%d] = %d, want %d", i, h.Addr, tc.want[i])
				}
			}
		})
	}
}

func TestCancelled(t *testing.T) {
	if cancelled(nil) {
		t.Error("nil done reported cancelled")
	}
	open := make(chan struct{})
	if cancelled(open) {
		t.Error("open done reported cancelled")
	}
	closed := make(chan struct{})
	close(closed)
	if !cancelled(closed) {
		t.Error("closed done not reported cancelled")
	}
}
