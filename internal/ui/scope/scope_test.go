package scope

import "testing"

// TestCountIsPastTheLastScope: Next/Prev use Count as the modulus, so a scope
// added without moving Count would be unreachable by the cycle keys.
func TestCountIsPastTheLastScope(t *testing.T) {
	if Count != Addr+1 {
		t.Fatalf("Count = %d, want %d (one past the last scope)", Count, Addr+1)
	}
}

func TestEveryScopeHasADistinctName(t *testing.T) {
	seen := map[string]Scope{}
	for s := Scope(0); s < Count; s++ {
		name := s.String()
		if name == "" {
			t.Errorf("scope %d has no name", s)
		}
		if prev, dup := seen[name]; dup {
			t.Errorf("scopes %d and %d share the name %q", prev, s, name)
		}
		seen[name] = s
	}
}

func TestNextCyclesThroughEveryScope(t *testing.T) {
	s := All
	visited := map[Scope]bool{s: true}
	for range int(Count) - 1 {
		s = Next(s)
		if visited[s] {
			t.Fatalf("Next revisited %v before covering every scope", s)
		}
		visited[s] = true
	}
	if s = Next(s); s != All {
		t.Errorf("Next from the last scope = %v, want All (wrap)", s)
	}
	if len(visited) != int(Count) {
		t.Errorf("Next visited %d scopes, want %d", len(visited), Count)
	}
}

func TestPrevIsNextInverted(t *testing.T) {
	for s := Scope(0); s < Count; s++ {
		if got := Prev(Next(s)); got != s {
			t.Errorf("Prev(Next(%v)) = %v", s, got)
		}
		if got := Next(Prev(s)); got != s {
			t.Errorf("Next(Prev(%v)) = %v", s, got)
		}
	}
	if got := Prev(All); got != Addr {
		t.Errorf("Prev(All) = %v, want Addr (wrap backwards)", got)
	}
}
