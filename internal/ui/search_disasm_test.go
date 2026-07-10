package ui

import "testing"

func TestDirectionalHitBufferBoundsForwardHits(t *testing.T) {
	b := directionalHitBuffer{forward: true, limit: 4}
	for addr := uint64(1); addr <= 6; addr++ {
		b.add(disasmSearchHit{addr: addr})
	}
	got := b.ordered()
	if len(got) != 4 {
		t.Fatalf("len = %d, want 4", len(got))
	}
	for i, want := range []uint64{1, 2, 3, 4} {
		if got[i].addr != want {
			t.Fatalf("hit %d = %d, want %d", i, got[i].addr, want)
		}
	}
}

func TestDirectionalHitBufferBoundsBackwardHits(t *testing.T) {
	b := directionalHitBuffer{forward: false, limit: 4}
	for addr := uint64(1); addr <= 6; addr++ {
		b.add(disasmSearchHit{addr: addr})
	}
	got := b.ordered()
	if len(got) != 4 {
		t.Fatalf("len = %d, want 4", len(got))
	}
	for i, want := range []uint64{6, 5, 4, 3} {
		if got[i].addr != want {
			t.Fatalf("hit %d = %d, want %d", i, got[i].addr, want)
		}
	}
}

func TestAppendDirectionalHitsNeverExceedsLimit(t *testing.T) {
	dst := []disasmSearchHit{{addr: 1}, {addr: 2}}
	src := []disasmSearchHit{{addr: 3}, {addr: 4}, {addr: 5}}
	got := appendDirectionalHits(dst, src, 4)
	if len(got) != 4 || got[3].addr != 4 {
		t.Fatalf("got %+v, want four hits ending at address 4", got)
	}
}
