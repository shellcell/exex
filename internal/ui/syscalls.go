package ui

// System-call extraction: scan the executable image for every instruction that
// enters the kernel directly (syscall / svc / int 0x80 / ecall) plus calls to
// vDSO/__kernel_ helpers, and open a jump-to modal listing them. Sites inside
// the function under the cursor are marked and the selection lands on the first
// of them, so the modal answers both "syscalls in this function" and "syscalls
// in the whole binary" at once. The scan mirrors the cross-reference scan: it
// runs off the UI goroutine over the decode cache and is cancellable.

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	tea "charm.land/bubbletea/v2"

	"github.com/shellcell/exex/internal/binfile"
	"github.com/shellcell/exex/internal/dump"
	syscallsmodal "github.com/shellcell/exex/internal/ui/modals/syscalls"
)

// syscallMaxHits caps how many syscall sites are collected (the modal scrolls).
const syscallMaxHits = 2000

// syscallLead matches the cross-reference scan's resync context (a 4-multiple to
// keep arm64/riscv instruction alignment across contiguous chunks).
const syscallLead = 1 << 10

// syscallScanBack is how many preceding instructions are scanned for the load of
// the syscall-number register (matches dump's recovery window).
const syscallScanBack = 32

// syscallState holds the syscall scans' async bookkeeping and the direct scan's
// result cache. The overlay's own state lives on m.syscalls
// (internal/ui/modals/syscalls).
type syscallState struct {
	syscallRunning bool // direct scan in flight
	syscallSeq     int  // guards against stale async results
	syscallCancel  chan struct{}
	syscallCached  map[bool][]dump.SyscallSite // key: file.DisasmAll()

	// Full scope (binary + linked libraries), scanned lazily off-thread.
	syscallFullRunning bool
	syscallFullSeq     int
	syscallFullCancel  chan struct{}
}

// syscallDoneMsg delivers a finished syscall scan.
type syscallDoneMsg struct {
	file  *binfile.File
	seq   int
	sites []dump.SyscallSite
}

// startSyscallScan launches a syscall-site scan over the executable image,
// remembering the function under the cursor so its sites can be highlighted.
func (m *Model) startSyscallScan() tea.Cmd {
	if m.dis == nil || len(m.dasm.Inst) == 0 {
		m.setStatus("no disassembly to scan", true)
		return nil
	}
	var lo, hi uint64
	var name string
	addr := m.dasm.Inst[m.dasm.Cur].Addr
	if sym, ok := m.file.SymbolAt(addr); ok && sym.Size > 0 {
		lo, hi, name = sym.Addr, sym.Addr+sym.Size, sym.Display()
	}
	m.syscalls.SetFunc(lo, hi, name)
	m.stopSyscallScan()
	m.syscallSeq++
	m.syscallRunning = false
	all := m.file.DisasmAll()
	if sites, ok := m.syscallCached[all]; ok {
		if len(sites) == 0 {
			return m.openSyscallFullFallback()
		}
		m.syscalls.Open(sites)
		m.setSyscallStatus(sites)
		return nil
	}
	m.syscallRunning = true
	done := make(chan struct{})
	m.syscallCancel = done
	m.setStatus("scanning for syscalls … (Esc cancels)", false)
	return m.backgroundCmd(m.syscallScanCmd(m.syscallSeq, done))
}

// syscallScanCmd decodes the executable image in parallel chunks (reusing the
// decode cache) off the UI goroutine and collects syscall sites.
func (m *Model) syscallScanCmd(seq int, done <-chan struct{}) tea.Cmd {
	svc := m.disasmService()
	img := m.file.ExecImage()
	file := m.file
	arch := m.file.Arch()
	symAt := dump.VDSOSymAt(file) // nil unless the binary has vDSO symbols
	chunk := m.disasmSearchChunkBytes()
	return func() tea.Msg {
		var starts []int
		for pos := 0; pos < img.Len(); {
			win := img.Window(pos, chunk)
			if len(win.Data) == 0 || win.End <= pos {
				break
			}
			starts = append(starts, pos)
			pos = win.End
		}

		results := make([][]dump.SyscallSite, len(starts))
		workers := svc.SearchWorkersFor(len(starts))
		sem := make(chan struct{}, workers)
		var wg sync.WaitGroup
		for i, start := range starts {
			if scanCancelled(done) {
				break
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(i, start int) {
				defer wg.Done()
				defer func() { <-sem }()
				var hits []dump.SyscallSite
				if scanCancelled(done) {
					return
				}
				decoded := svc.DecodeRange(start, chunk, syscallLead)
				for p, inst := range decoded {
					if scanCancelled(done) {
						return
					}
					ok, vdso := dump.ClassifySyscallSite(inst, symAt)
					if !ok {
						continue
					}
					sym := ""
					if s, ok := file.SymbolAt(inst.Addr); ok {
						sym = s.Display()
					}
					h := dump.SyscallSite{
						Addr: inst.Addr,
						Text: strings.TrimSpace(inst.Text),
						Sym:  sym,
						VDSO: vdso,
					}
					if !vdso {
						lo := p - syscallScanBack
						if lo < 0 {
							lo = 0
						}
						if n, ok := dump.ResolveSyscallNum(decoded[lo:p], arch); ok {
							h.Num, h.HasNum = n, true
						}
					}
					hits = append(hits, h)
				}
				results[i] = hits
			}(i, start)
		}
		wg.Wait()

		seen := map[uint64]bool{}
		var sites []dump.SyscallSite
		for _, rs := range results {
			for _, h := range rs {
				if seen[h.Addr] {
					continue
				}
				seen[h.Addr] = true
				sites = append(sites, h)
			}
			if len(sites) >= syscallMaxHits {
				break
			}
		}
		sort.Slice(sites, func(i, j int) bool { return sites[i].Addr < sites[j].Addr })
		if len(sites) > syscallMaxHits {
			sites = sites[:syscallMaxHits]
		}
		// Resolve names the same way the dump does (the modal runs its own scan).
		for i := range sites {
			if sites[i].HasNum {
				if name, ok := dump.SyscallName(file, sites[i].Num); ok {
					sites[i].Name = name
				}
			}
		}
		return syscallDoneMsg{file: file, seq: seq, sites: sites}
	}
}

// handleSyscallDone stores a finished scan and opens the modal (or reports none),
// landing the selection on the first site inside the function under the cursor.
func (m *Model) handleSyscallDone(msg syscallDoneMsg) (tea.Model, tea.Cmd) {
	if msg.file != m.file || !m.syscallRunning || msg.seq != m.syscallSeq {
		return m, nil // cancelled or superseded
	}
	m.syscallRunning = false
	m.syscallCancel = nil
	if m.syscallCached == nil {
		m.syscallCached = map[bool][]dump.SyscallSite{}
	}
	m.syscallCached[m.file.DisasmAll()] = msg.sites
	if len(msg.sites) == 0 {
		return m, m.openSyscallFullFallback()
	}
	m.syscalls.Open(msg.sites)
	m.setSyscallStatus(msg.sites)
	return m, nil
}

// openSyscallFullFallback opens the modal straight in full (binary + libs) scope
// when the image itself has no direct syscall sites. A macOS executable never
// traps to the kernel itself — its syscalls live in libsystem_kernel, reached
// through the dyld shared cache — so rather than a bare "none found" that hides
// where the syscalls actually are, we surface the transitive scan (a statically
// linked ELF with none of its own works the same way against its libraries).
func (m *Model) openSyscallFullFallback() tea.Cmd {
	needsScan := m.syscalls.OpenFull()
	if m.syscalls.FullDone() {
		m.setStatus("no direct syscalls — showing libraries · "+m.syscalls.ScopeLabel(), false)
		return nil
	}
	m.setStatus("no direct syscalls — scanning libraries … (Esc cancels)", false)
	if needsScan {
		return m.StartFullScan()
	}
	return nil
}

func (m *Model) setSyscallStatus(sites []dump.SyscallSite) {
	capped := ""
	if len(sites) >= syscallMaxHits {
		capped = "+"
	}
	inFn := m.syscalls.CountInFunc(sites)
	if inFn > 0 && m.syscalls.FuncName() != "" {
		m.setStatus(fmt.Sprintf("%d%s syscalls · %d in %s (t: scope)", len(sites), capped, inFn, m.syscalls.FuncName()), false)
	} else {
		m.setStatus(fmt.Sprintf("%d%s syscalls (t: scope)", len(sites), capped), false)
	}
}

// cancelSyscall abandons an in-flight scan (its result is ignored by seq).
func (m *Model) cancelSyscall() {
	m.syscallSeq++
	m.syscallRunning = false
	m.stopSyscallScan()
	m.CancelFullScan()
	m.setStatus("syscall scan cancelled", false)
}

func (m *Model) stopSyscallScan() {
	if m.syscallCancel != nil {
		close(m.syscallCancel)
		m.syscallCancel = nil
	}
}

// syscallFullDoneMsg delivers a finished full (binary + libs) scan.
type syscallFullDoneMsg struct {
	file  *binfile.File
	seq   int
	sites []dump.SyscallSite
	objs  int
	notes []string
}

// startSyscallFullScan scans the binary and its linked libraries off the UI
// goroutine (opening and decoding each library is I/O- and CPU-heavy, so it must
// not block rendering). The result feeds the modal's full scope.
// StartFullScan satisfies syscalls.Host: the overlay asks for the library scan
// the first time its full scope is selected.
func (m *Model) StartFullScan() tea.Cmd {
	m.stopSyscallFullScan()
	m.syscallFullSeq++
	m.syscallFullRunning = true
	m.syscalls.SetFullRunning(true)
	seq := m.syscallFullSeq
	file := m.file
	done := make(chan struct{})
	m.syscallFullCancel = done
	return m.backgroundCmd(func() tea.Msg {
		sites, objs, notes := dump.CollectSyscallsFullCancel(file, done)
		return syscallFullDoneMsg{file: file, seq: seq, sites: sites, objs: objs, notes: notes}
	})
}

func (m *Model) stopSyscallFullScan() {
	if m.syscallFullCancel != nil {
		close(m.syscallFullCancel)
		m.syscallFullCancel = nil
	}
}

// CancelFullScan satisfies syscalls.Host: the overlay abandons the library scan
// when it leaves the full scope, or jumps away.
func (m *Model) CancelFullScan() {
	if m.syscallFullRunning || m.syscallFullCancel != nil {
		m.syscallFullSeq++
		m.syscallFullRunning = false
		m.syscalls.SetFullRunning(false)
		m.stopSyscallFullScan()
	}
}

// handleSyscallFullDone stores a finished full scan and refreshes the rows if the
// modal is still in full scope.
func (m *Model) handleSyscallFullDone(msg syscallFullDoneMsg) (tea.Model, tea.Cmd) {
	if msg.file != m.file || !m.syscallFullRunning || msg.seq != m.syscallFullSeq {
		return m, nil // superseded
	}
	m.syscallFullRunning = false
	m.syscallFullCancel = nil
	m.syscalls.SetFullResults(msg.sites, msg.notes, msg.objs)
	if m.syscalls.Active() && m.syscalls.Scope() == syscallsmodal.ScopeFull {
		m.setStatus("syscalls: "+m.syscalls.ScopeLabel(), false)
	}
	return m, nil
}
