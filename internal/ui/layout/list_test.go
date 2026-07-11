package layout

import "testing"

func TestNavKey(t *testing.T) {
	cur := 5
	// down/up move by one, clamped to [0, n-1].
	if !NavKey(&cur, 10, 4, "down") || cur != 6 {
		t.Fatalf("down: cur=%d", cur)
	}
	if !NavKey(&cur, 10, 4, "up") || cur != 5 {
		t.Fatalf("up: cur=%d", cur)
	}
	// paging clamps at the ends.
	NavKey(&cur, 10, 4, "pgdown")
	if cur != 9 {
		t.Fatalf("pgdown clamp: cur=%d, want 9", cur)
	}
	NavKey(&cur, 10, 4, "home")
	if cur != 0 {
		t.Fatalf("home: cur=%d", cur)
	}
	NavKey(&cur, 10, 4, "end")
	if cur != 9 {
		t.Fatalf("end: cur=%d", cur)
	}
	// `[`/`]` page too; unknown keys are not consumed.
	if NavKey(&cur, 10, 4, "x") {
		t.Fatalf("unexpectedly consumed unknown key")
	}
	// empty list stays at 0.
	cur = 0
	NavKey(&cur, 0, 4, "down")
	if cur != 0 {
		t.Fatalf("empty list: cur=%d", cur)
	}
}

func TestContainsFold(t *testing.T) {
	if !ContainsFold("HelloWorld", "world") {
		t.Error("case-insensitive substring not found")
	}
	if ContainsFold("abc", "xyz") {
		t.Error("false positive")
	}
	if !ContainsFold("anything", "") {
		t.Error("empty needle should match")
	}
	if !ContainsFoldBytes([]byte("libSYSTEM.dylib"), "system") {
		t.Error("byte variant case-insensitive match failed")
	}
}

func TestCycleStringList(t *testing.T) {
	on, cur := false, ""
	list := []string{"a", "b", "c"}
	CycleStringList(&on, &cur, list) // off -> first
	if !on || cur != "a" {
		t.Fatalf("first: on=%v cur=%q", on, cur)
	}
	CycleStringList(&on, &cur, list) // a -> b
	CycleStringList(&on, &cur, list) // b -> c
	if cur != "c" {
		t.Fatalf("advance: cur=%q, want c", cur)
	}
	CycleStringList(&on, &cur, list) // c -> off
	if on {
		t.Fatalf("last should turn off, on=%v", on)
	}
	// empty list is a no-op.
	on, cur = true, "keep"
	CycleStringList(&on, &cur, nil)
	if !on || cur != "keep" {
		t.Fatalf("empty list mutated state: on=%v cur=%q", on, cur)
	}
}

func TestRowMemo(t *testing.T) {
	var m RowMemo[int, string]
	calls := 0
	build := func() string { calls++; return "v" }
	if got := m.Get(1, build); got != "v" || calls != 1 {
		t.Fatalf("first get: %q calls=%d", got, calls)
	}
	if got := m.Get(1, build); got != "v" || calls != 1 {
		t.Fatalf("cached get rebuilt: calls=%d", calls)
	}
	// Overflow flushes wholesale, then repopulates.
	for i := 0; i < RowMemoCap+1; i++ {
		m.Get(1000+i, func() string { return "x" })
	}
	if len(m) > RowMemoCap {
		t.Fatalf("memo exceeded cap: len=%d", len(m))
	}
}
