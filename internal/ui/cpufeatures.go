package ui

// CPU-feature detection: scan the executable image, classify each instruction
// into the CPU-feature families it requires (SSE/AVX/NEON/…), and show the set
// plus the implied baseline in a modal.
//
// The overlay itself lives in internal/ui/modals/cpufeat. What stays here is the
// async orchestration — launching the scan as a tea.Cmd, guarding its result
// against a stale file or a superseded sequence number, and cancelling it — all
// of which is the shell's job because only the shell owns the event loop.

import (
	"fmt"

	tea "charm.land/bubbletea/v2"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/dump"
)

// cpufeatState holds the CPU-feature scan's async bookkeeping. The overlay's own
// state (the result, the selection, the scroll) lives on m.cpufeat.
type cpufeatState struct {
	cpufeatRunning bool
	cpufeatSeq     int
	cpufeatCancel  chan struct{}
}

type cpufeatDoneMsg struct {
	file *binfile.File
	seq  int
	set  dump.CPUFeatureSet
	err  error
}

// startCPUFeatScan kicks off a CPU-feature scan (no-op + status when unsupported).
func (m *Model) startCPUFeatScan() tea.Cmd {
	if m.dis == nil {
		m.setStatus("no disassembler for this architecture", true)
		return nil
	}
	if m.cpufeat.Scanned() {
		m.cpufeat.Open(m.cpufeat.Set())
		m.setStatus(fmt.Sprintf("%d CPU features (cached)", len(m.cpufeat.Features())), false)
		return nil
	}
	m.stopCPUFeatScan()
	m.cpufeatSeq++
	m.cpufeatRunning = true
	seq := m.cpufeatSeq
	file := m.file
	done := make(chan struct{})
	m.cpufeatCancel = done
	m.setStatus("scanning for CPU features … (Esc cancels)", false)
	return m.backgroundCmd(func() tea.Msg {
		set, err := dump.ScanCPUFeaturesCancel(file, done)
		return cpufeatDoneMsg{file: file, seq: seq, set: set, err: err}
	})
}

func (m *Model) handleCPUFeatDone(msg cpufeatDoneMsg) (tea.Model, tea.Cmd) {
	if msg.file != m.file || !m.cpufeatRunning || msg.seq != m.cpufeatSeq {
		return m, nil
	}
	m.cpufeatRunning = false
	m.cpufeatCancel = nil
	if msg.err != nil {
		m.setStatus(msg.err.Error(), true)
		return m, nil
	}
	m.cpufeat.Open(msg.set)
	base := ""
	if msg.set.Baseline != "" {
		base = " · " + msg.set.Baseline
	}
	m.setStatus(fmt.Sprintf("%d CPU features%s", len(m.cpufeat.Features()), base), false)
	return m, nil
}

func (m *Model) cancelCPUFeat() {
	m.cpufeatSeq++
	m.cpufeatRunning = false
	m.stopCPUFeatScan()
	m.setStatus("CPU-feature scan cancelled", false)
}

func (m *Model) stopCPUFeatScan() {
	if m.cpufeatCancel != nil {
		close(m.cpufeatCancel)
		m.cpufeatCancel = nil
	}
}
