package binfile

import "testing"

func TestDemangleName(t *testing.T) {
	cases := []struct {
		in   string
		want string // "" means: expect no demangling
	}{
		{"_ZN3foo3barEv", "foo::bar()"},  // Itanium C++
		{"__ZN3foo3barEv", "foo::bar()"}, // Mach-O extra underscore
		{"_main", ""},                    // plain C
		{"main", ""},
		{"", ""},
		{"_ZSt4cout", ""}, // data symbol that Filter leaves as-is or resolves; tolerate either
	}
	for _, c := range cases {
		got := demangleName(c.in)
		if c.want == "" {
			// For the std::cout-style case we don't pin an exact value; only the
			// clearly-not-mangled inputs must come back empty.
			if c.in == "_main" || c.in == "main" || c.in == "" {
				if got != "" {
					t.Errorf("demangleName(%q) = %q, want empty", c.in, got)
				}
			}
			continue
		}
		if got != c.want {
			t.Errorf("demangleName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDemangleWorkers(t *testing.T) {
	for _, tc := range []struct {
		procs int
		want  int
	}{
		{0, 1},
		{1, 1},
		{4, 4},
		{8, 8},
		{16, 8},
	} {
		if got := demangleWorkers(tc.procs); got != tc.want {
			t.Errorf("demangleWorkers(%d) = %d, want %d", tc.procs, got, tc.want)
		}
	}
}
