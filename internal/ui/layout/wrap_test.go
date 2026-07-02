package layout

import (
	"strings"
	"testing"

	"charm.land/lipgloss/v2"
)

// TestWrappedRowsKeepColour guards the fix for colour loss across wrapped lines:
// a styled span split by wrapping must re-emit its SGR on every continuation row
// (after the hanging indent), because the cell renderer resets style per line.
func TestWrappedRowsKeepColour(t *testing.T) {
	style := lipgloss.NewStyle().Foreground(lipgloss.Color("51"))
	line := "head " + style.Render("a-long-coloured-token-that-must-wrap-across-several-lines-xyz")
	rows := RenderLineRowsIndented(line, 24, true, 6)
	if len(rows) < 2 {
		t.Fatalf("expected the line to wrap, got %d row(s)", len(rows))
	}
	// Every continuation row that has visible content must carry the colour.
	for i, row := range rows[1:] {
		if strings.TrimSpace(stripANSIcodes(row)) == "" {
			continue // blank padding row
		}
		if !strings.Contains(row, "\x1b[38;5;51m") {
			t.Fatalf("continuation row %d lost its colour: %q", i+1, row)
		}
	}
}

func TestLastOpenSGR(t *testing.T) {
	if got := LastOpenSGR("", "\x1b[38;5;51mhi"); got != "\x1b[38;5;51m" {
		t.Fatalf("open after colour = %q", got)
	}
	if got := LastOpenSGR("\x1b[38;5;51m", "done\x1b[0m"); got != "" {
		t.Fatalf("reset should clear open, got %q", got)
	}
	if got := LastOpenSGR("\x1b[1m", "plain text no codes"); got != "\x1b[1m" {
		t.Fatalf("carry should persist with no SGR in row, got %q", got)
	}
}

// stripANSIcodes removes SGR escapes for the blank-row check above.
func stripANSIcodes(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
