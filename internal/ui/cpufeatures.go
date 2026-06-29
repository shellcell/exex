package ui

// CPU-feature detection: scan the executable image, classify each instruction
// into the CPU-feature families it requires (SSE/AVX/NEON/…), and show the set
// plus the implied baseline in a modal. Enter jumps to the first use of the
// selected feature. The scan runs off the UI goroutine and is cancellable, like
// the cross-reference / syscall scans.

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/rabarbra/exex/internal/dump"
)

// cpufeatState holds the CPU-feature scan + modal state.
type cpufeatState struct {
	cpufeatActive  bool
	cpufeatRunning bool
	cpufeatSeq     int
	cpufeatSet     dump.CPUFeatureSet
	cpufeatFeats   []string // feature names in display order
	cpufeatSel     int
	cpufeatTop     int
}

type cpufeatDoneMsg struct {
	seq int
	set dump.CPUFeatureSet
	err error
}

// startCPUFeatScan kicks off a CPU-feature scan (no-op + status when unsupported).
func (m *Model) startCPUFeatScan() tea.Cmd {
	if m.dis == nil {
		m.setStatus("no disassembler for this architecture", true)
		return nil
	}
	m.cpufeatSeq++
	m.cpufeatRunning = true
	seq := m.cpufeatSeq
	file := m.file
	m.setStatus("scanning for CPU features … (Esc cancels)", false)
	return func() tea.Msg {
		set, err := dump.ScanCPUFeatures(file)
		return cpufeatDoneMsg{seq: seq, set: set, err: err}
	}
}

func (m *Model) handleCPUFeatDone(msg cpufeatDoneMsg) (tea.Model, tea.Cmd) {
	if !m.cpufeatRunning || msg.seq != m.cpufeatSeq {
		return m, nil
	}
	m.cpufeatRunning = false
	if msg.err != nil {
		m.setStatus(msg.err.Error(), true)
		return m, nil
	}
	m.cpufeatSet = msg.set
	m.cpufeatFeats = msg.set.SortedFeatures()
	m.cpufeatSel, m.cpufeatTop = 0, 0
	m.cpufeatActive = true
	base := ""
	if msg.set.Baseline != "" {
		base = " · " + msg.set.Baseline
	}
	m.setStatus(fmt.Sprintf("%d CPU features%s", len(m.cpufeatFeats), base), false)
	return m, nil
}

func (m *Model) cancelCPUFeat() {
	m.cpufeatSeq++
	m.cpufeatRunning = false
	m.setStatus("CPU-feature scan cancelled", false)
}

// updateCPUFeatModal: navigate the feature list, Enter jumps to the first use of
// the selected feature, Esc closes.
func (m *Model) updateCPUFeatModal(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc":
		m.cpufeatActive = false
	case "up", "k":
		if m.cpufeatSel > 0 {
			m.cpufeatSel--
		}
	case "down", "j":
		if m.cpufeatSel < len(m.cpufeatFeats)-1 {
			m.cpufeatSel++
		}
	case "enter":
		return m.cpufeatJump()
	}
	return m, nil
}

func (m *Model) cpufeatJump() (tea.Model, tea.Cmd) {
	if m.cpufeatSel < 0 || m.cpufeatSel >= len(m.cpufeatFeats) {
		return m, nil
	}
	addr, ok := m.cpufeatSet.FirstUse[m.cpufeatFeats[m.cpufeatSel]]
	if !ok {
		return m, nil
	}
	m.cpufeatActive = false
	m.loadDisasmAt(addr)
	return m, nil
}

func (m *Model) renderCPUFeatModal() string {
	var sb strings.Builder
	rowW := modalListWidth(m.width)
	addrW := m.file.AddrHexWidth()
	visible := clamp(m.height-9, 3, 40)

	sb.WriteString(m.theme.modalTitle("CPU features"))
	sb.WriteString("\n")
	sub := fmt.Sprintf("%d instructions scanned", m.cpufeatSet.Total)
	if m.cpufeatSet.Baseline != "" {
		sub = m.theme.warnStyle.Render(m.cpufeatSet.Baseline) + m.theme.modalHint("   ·   "+sub)
	} else {
		sub = m.theme.modalHint(sub)
	}
	sb.WriteString(fitANSIWidth(sub, rowW))
	sb.WriteString("\n\n")
	m.modalListRow = 3

	if len(m.cpufeatFeats) == 0 {
		sb.WriteString(" " + m.theme.srcShadowStyle.Render("only base instructions — no optional CPU features detected") + "\n")
	}
	nameW := 0
	for _, f := range m.cpufeatFeats {
		nameW = max(nameW, len(f))
	}
	nameW = clamp(nameW, 8, 28)
	top := visualTop(m.cpufeatSel, m.cpufeatTop, len(m.cpufeatFeats), visible, func(int) int { return 1 })
	m.cpufeatTop = top
	end := min(top+visible, len(m.cpufeatFeats))
	for i := top; i < end; i++ {
		f := m.cpufeatFeats[i]
		line := fmt.Sprintf(" %s  %s ×   %s",
			m.theme.infoStyle.Render(padVisual(f, nameW)),
			padVisual(fmt.Sprintf("%d", m.cpufeatSet.Counts[f]), 8),
			m.theme.srcShadowStyle.Render(fmt.Sprintf("first at 0x%0*x", addrW, m.cpufeatSet.FirstUse[f])))
		line = padRight(line, rowW)
		if i == m.cpufeatSel {
			line = m.theme.tableSelStyle.Render(ansi.Strip(line))
		}
		sb.WriteString(line)
		sb.WriteString("\n")
	}
	sb.WriteString("\n")
	sb.WriteString(m.theme.modalHint(fmt.Sprintf("↑/↓ select · ↵ jump to first use · Esc close   (%d/%d)",
		min(m.cpufeatSel+1, len(m.cpufeatFeats)), len(m.cpufeatFeats))))
	return m.theme.modalStyle.Render(sb.String())
}
