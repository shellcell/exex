package ui

import (
	"testing"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/config"
)

func TestSettingsCycleAndPersist(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	m := &Model{theme: DefaultTheme(), file: &binfile.File{}}

	m.openSettings()
	if !m.settings.Active() {
		t.Fatal("openSettings did not activate the popup")
	}

	// Field 0: theme — right cycles off the default.
	m.settings.Update(m, "right")
	if m.cfg.Theme == "" || m.cfg.Theme == defaultThemeName {
		t.Fatalf("theme did not cycle, got %q", m.cfg.Theme)
	}

	// Field 1: background — space toggles it on.
	m.settings.Update(m, "down")
	m.settings.Update(m, " ")
	if !m.cfg.Behavior.Background {
		t.Fatal("background toggle did not turn on")
	}

	// Field 2: default wrap — space toggles it on and applies it for the session.
	m.settings.Update(m, "down")
	m.settings.Update(m, " ")
	if !m.cfg.Behavior.DefaultWrap || !m.wrap {
		t.Fatal("default wrap toggle did not turn on")
	}

	// Field 3: default view — right cycles to a non-empty view name.
	m.settings.Update(m, "down")
	m.settings.Update(m, "right")
	if m.cfg.Behavior.DefaultView == "" {
		t.Fatal("default view did not cycle")
	}

	// Enter persists and closes.
	m.settings.Update(m, "enter")
	if m.settings.Active() {
		t.Fatal("Enter should close the popup")
	}
	c, err := config.Load()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if c.Theme != m.cfg.Theme || !c.Behavior.Background || !c.Behavior.DefaultWrap || c.Behavior.DefaultView != m.cfg.Behavior.DefaultView {
		t.Fatalf("persisted config mismatch: %+v", c)
	}
}

// TestSettingsNewFields exercises the four added settings: disasm target, the
// demangle toggle, compact addresses and hex bytes-per-row — confirming each
// updates the live model/file and round-trips through Save/Load.
func TestSettingsNewFields(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	m := &Model{theme: DefaultTheme(), file: &binfile.File{}}

	// Disasm target (field 4): cycling lands on a known strategy and updates the
	// live target used for default landings.
	m.settings.SetCur(4)
	m.CycleSetting(m.settings.Cur(), 1)
	if m.cfg.Behavior.DefaultDisasmTarget == "" || m.disasmTarget != m.cfg.Behavior.DefaultDisasmTarget {
		t.Fatalf("disasm target not applied live: cfg=%q live=%q",
			m.cfg.Behavior.DefaultDisasmTarget, m.disasmTarget)
	}

	// Demangle (field 10): toggling flips the (negated) preference.
	m.settings.SetCur(10)
	m.CycleSetting(m.settings.Cur(), 1)
	if !m.cfg.Behavior.NoDemangle {
		t.Fatal("demangle toggle did not set NoDemangle")
	}

	// Compact addresses (field 14): toggling sets the flag and pushes it to the file.
	m.settings.SetCur(14)
	m.CycleSetting(m.settings.Cur(), 1)
	if !m.cfg.Behavior.CompactAddresses {
		t.Fatal("compact-addresses toggle did not set the flag")
	}

	// Hex bytes/row (field 15): cycles 16 → 32.
	m.settings.SetCur(15)
	m.CycleSetting(m.settings.Cur(), 1)
	if m.cfg.Behavior.HexBytesPerRow != 32 {
		t.Fatalf("hex bytes/row = %d, want 32", m.cfg.Behavior.HexBytesPerRow)
	}

	// Persist and reload: every new field round-trips.
	m.PersistSettings()
	c, err := config.Load()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if c.Behavior.DefaultDisasmTarget != m.cfg.Behavior.DefaultDisasmTarget ||
		!c.Behavior.NoDemangle || !c.Behavior.CompactAddresses ||
		c.Behavior.HexBytesPerRow != 32 {
		t.Fatalf("new settings did not persist: %+v", c.Behavior)
	}
}
