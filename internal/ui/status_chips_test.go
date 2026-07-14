package ui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"

	"github.com/shellcell/exex/internal/binfile"
	"github.com/shellcell/exex/internal/config"
	"github.com/shellcell/exex/internal/ui/view"
)

// chipsFor renders a view and returns the chips its status line published.
func chipsFor(t *testing.T, m *Model, md mode) []view.StatusChip {
	t.Helper()
	enterMode(t, m, md)
	_ = frame(m)
	switch md {
	case modeSections:
		return m.sections.Chips
	case modeSymbols:
		return m.symbols.Chips
	case modeStrings:
		return m.strs.Chips
	case modeSources:
		return m.sources.Chips
	case modeLibs:
		return m.libs.Chips
	case modeRelocs:
		return m.relocs.Chips
	}
	return nil
}

// TestEveryTableViewHasClickableChips pins the uniformity the status line is
// for: each table view publishes chips, and a click on one is that chip's key
// arriving by mouse. Only Symbols used to be clickable — the rest rendered
// look-alike text that did nothing.
func TestEveryTableViewHasClickableChips(t *testing.T) {
	path := firstExisting("/bin/ls", "/usr/bin/true", "/bin/cat")
	if path == "" {
		t.Skip("no system binary available")
	}
	f, err := binfile.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()

	for _, md := range []mode{modeSections, modeSymbols, modeStrings, modeLibs, modeRelocs} {
		t.Run(md.String(), func(t *testing.T) {
			m, err := New(f, Options{Config: &config.Config{Theme: defaultThemeName}})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			m.resize(160, 40)
			m.applyThemeChange()

			chips := chipsFor(t, m, md)
			if len(chips) == 0 {
				t.Fatalf("%v published no status chips", md)
			}

			// Every chip must lie inside the row and carry a key.
			for _, c := range chips {
				if c.Key == "" {
					t.Errorf("chip at [%d,%d) has no key", c.Start, c.End)
				}
				if c.Start < 0 || c.End > m.width || c.Start >= c.End {
					t.Errorf("chip %q spans [%d,%d), outside the %d-column row", c.Key, c.Start, c.End, m.width)
				}
			}

			// Clicking the first chip must change the status line — i.e. the click
			// reached the view's own key handler.
			before := ansi.Strip(strings.Split(frame(m), "\n")[1+statusRowOf(t, m, md)])
			c := chips[0]
			m.handleClick((c.Start+c.End)/2, statusRowOf(t, m, md)+1) // +1: body starts at y=1
			after := ansi.Strip(strings.Split(frame(m), "\n")[1+statusRowOf(t, m, md)])
			if before == after {
				t.Errorf("clicking the %q chip changed nothing\n  row: %s", c.Key, before)
			}
		})
	}
}

func statusRowOf(t *testing.T, m *Model, md mode) int {
	t.Helper()
	r := m.viewFor(md).statusRow()
	if r < 0 {
		t.Fatalf("%v has no status row", md)
	}
	return r
}
