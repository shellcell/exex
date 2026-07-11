package ui

import tea "charm.land/bubbletea/v2"

type backgroundState struct {
	generation   uint64
	inFlight     int
	closePending bool
}

type backgroundDoneMsg struct {
	owner      *Model
	generation uint64
	msg        tea.Msg
}

// backgroundCmd tracks physical command completion separately from logical
// running flags, which cancellation clears before worker goroutines have exited.
func (m *Model) backgroundCmd(cmd tea.Cmd) tea.Cmd {
	if cmd == nil {
		return nil
	}
	generation := m.background.generation
	m.background.inFlight++
	return func() tea.Msg {
		return backgroundDoneMsg{owner: m, generation: generation, msg: cmd()}
	}
}

func (m *Model) handleBackgroundDone(msg backgroundDoneMsg) (tea.Model, tea.Cmd) {
	owner := msg.owner
	if owner == nil {
		return m, nil
	}
	if owner.background.inFlight > 0 {
		owner.background.inFlight--
	}
	owner.closeRetiredFile()
	if owner != m || msg.generation != m.background.generation || msg.msg == nil {
		return m, nil
	}
	return m.Update(msg.msg)
}

// suspendBackground invalidates model-owned completions and requests prompt
// cancellation. The file stays open because a suspended model may be restored.
func (m *Model) suspendBackground() {
	m.background.generation++

	m.findSeq++
	m.stopFindSearch()
	m.findResults.StopScan()

	m.searchSeq++
	m.searchRunning = false
	m.searchCancelable = false
	m.stopDisasmSearch()

	m.xrefSeq++
	m.xrefRunning = false
	m.stopXrefScan()

	m.syscallSeq++
	m.syscallRunning = false
	m.stopSyscallScan()
	m.syscallFullSeq++
	m.syscallFullRunning = false
	m.syscalls.SetFullRunning(false)
	m.stopSyscallFullScan()

	m.cpufeatSeq++
	m.cpufeatRunning = false
	m.stopCPUFeatScan()

	m.dasm.Decoding = false
	m.dasm.PendingAddr = 0
	m.pendingWheel = 0
	m.wheelTicking = false
	m.pendingKey = ""
	m.pendingKeyN = 0
	m.keyTicking = false
}

func (m *Model) retireFile() {
	m.suspendBackground()
	m.background.closePending = true
	m.closeRetiredFile()
}

func (m *Model) closeRetiredFile() {
	if !m.background.closePending || m.background.inFlight != 0 || m.file == nil {
		return
	}
	_ = m.file.Close()
	m.background.closePending = false
}
