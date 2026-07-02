package chromastyles

import "testing"

func TestCuratedStyles(t *testing.T) {
	for _, name := range []string{"swapoff", "nord", "catppuccin-mocha", "dracula", "solarized-dark", "solarized-light"} {
		if st := Get(name); st == nil {
			t.Fatalf("Get(%q) returned nil", name)
		}
	}
}

func TestCuratedStyleFallback(t *testing.T) {
	if Fallback == nil {
		t.Fatal("Fallback is nil")
	}
	if _, ok := Lookup("definitely-not-a-style"); ok {
		t.Fatalf("unknown style unexpectedly bundled")
	}
	if got := Get("definitely-not-a-style"); got != Fallback {
		t.Fatalf("unknown style did not return Fallback")
	}
}

func TestCuratedStyleNames(t *testing.T) {
	names := Names()
	if len(names) == 0 {
		t.Fatal("Names returned no styles")
	}
	for i := 1; i < len(names); i++ {
		if names[i-1] > names[i] {
			t.Fatalf("Names not sorted: %q before %q", names[i-1], names[i])
		}
	}
}
