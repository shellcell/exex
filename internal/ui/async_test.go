package ui

import (
	"testing"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/disasm"
	"github.com/rabarbra/exex/internal/dump"
)

func TestAsyncMessagesIgnoreStaleFile(t *testing.T) {
	oldFile := &binfile.File{Symbols: []binfile.Symbol{{Name: "old"}}}
	curFile := &binfile.File{Symbols: []binfile.Symbol{{Name: "cur"}}}

	m := &Model{file: curFile}
	model, _ := m.Update(demangleDoneMsg{file: oldFile, names: []string{"stale"}})
	m = model.(*Model)
	if got := curFile.Symbols[0].Demangled; got != "" {
		t.Fatalf("stale demangle mutated current file: %q", got)
	}

	m.disasmDecoding = true
	m.disasmPendingAddr = 0x1000
	if _, _ = m.handleDisasmReady(disasmReadyMsg{file: oldFile, addr: 0x1000, insts: []disasm.Inst{{Addr: 0x1000}}}); !m.disasmDecoding || len(m.disasmInst) != 0 {
		t.Fatalf("stale disasm ready was applied: decoding=%v insts=%d", m.disasmDecoding, len(m.disasmInst))
	}

	m.searchRunning = true
	m.searchSeq = 1
	if _, _ = m.handleDisasmSearchProgress(disasmSearchProgressMsg{file: oldFile, seq: 1, done: true}); !m.searchRunning {
		t.Fatal("stale disasm search progress stopped current search")
	}

	m.xrefRunning = true
	m.xrefSeq = 1
	if _, _ = m.handleXrefDone(xrefDoneMsg{file: oldFile, seq: 1, target: 0x1000, hits: []xrefHit{{addr: 0x1000}}}); !m.xrefRunning || m.xrefActive {
		t.Fatalf("stale xref result was applied: running=%v active=%v", m.xrefRunning, m.xrefActive)
	}

	m.syscallRunning = true
	m.syscallSeq = 1
	if _, _ = m.handleSyscallDone(syscallDoneMsg{file: oldFile, seq: 1, sites: []dump.SyscallSite{{Addr: 0x1000}}}); !m.syscallRunning || m.syscallActive {
		t.Fatalf("stale syscall result was applied: running=%v active=%v", m.syscallRunning, m.syscallActive)
	}

	m.cpufeatRunning = true
	m.cpufeatSeq = 1
	if _, _ = m.handleCPUFeatDone(cpufeatDoneMsg{file: oldFile, seq: 1, set: dump.CPUFeatureSet{Counts: map[string]int{"AVX": 1}}}); !m.cpufeatRunning || m.cpufeatDone {
		t.Fatalf("stale CPU-feature result was applied: running=%v done=%v", m.cpufeatRunning, m.cpufeatDone)
	}

	m.syscallFullRunning = true
	m.syscallFullSeq = 1
	if _, _ = m.handleSyscallFullDone(syscallFullDoneMsg{file: oldFile, seq: 1, sites: []dump.SyscallSite{{Addr: 0x1000}}, objs: 2}); !m.syscallFullRunning || m.syscallFullDone {
		t.Fatalf("stale full syscall result was applied: running=%v done=%v", m.syscallFullRunning, m.syscallFullDone)
	}
}

func TestCancelSyscallFullScanClosesChannelAndIgnoresLateResult(t *testing.T) {
	f := &binfile.File{}
	done := make(chan struct{})
	m := &Model{file: f}
	m.syscallFullRunning = true
	m.syscallFullSeq = 7
	m.syscallFullCancel = done

	m.cancelSyscallFullScan()
	if m.syscallFullRunning {
		t.Fatal("full syscall scan still marked running after cancel")
	}
	if m.syscallFullCancel != nil {
		t.Fatal("full syscall cancel channel still retained after cancel")
	}
	if m.syscallFullSeq != 8 {
		t.Fatalf("full syscall seq = %d, want 8", m.syscallFullSeq)
	}
	select {
	case <-done:
	default:
		t.Fatal("full syscall cancel channel was not closed")
	}

	if _, _ = m.handleSyscallFullDone(syscallFullDoneMsg{file: f, seq: 7, sites: []dump.SyscallSite{{Addr: 0x1000}}, objs: 2}); m.syscallFullDone || len(m.syscallFull) != 0 {
		t.Fatalf("late cancelled full syscall result was applied: done=%v sites=%d", m.syscallFullDone, len(m.syscallFull))
	}
}
