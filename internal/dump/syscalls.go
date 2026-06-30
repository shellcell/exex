package dump

// Syscall-site extraction: every instruction that enters the kernel directly
// (syscall / svc / int 0x80 / ecall), plus a heuristic for calls to
// vDSO-resolved helpers (__vdso_* / __kernel_*). Where possible the system-call
// number is recovered by tracking the immediate most recently loaded into the
// architecture's syscall-number register (rax/eax on x86, x8 on arm64, a7 on
// RISC-V, r7 on 32-bit ARM). Shared by the `-o syscalls` dump and the
// disassembly view's syscall modal.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/disasm"
	"github.com/rabarbra/exex/internal/explorer"
	"github.com/rabarbra/exex/internal/syscalls"
)

// syscallScanBack is how many preceding instructions are scanned for the load
// of the syscall-number register.
const syscallScanBack = 32

// SyscallSite is one located system-call (or vDSO) site.
type SyscallSite struct {
	Addr   uint64 // address of the instruction
	Text   string // its trimmed assembly text
	Sym    string // enclosing symbol's display name, or ""
	VDSO   bool   // true for a vDSO/__kernel_ call rather than a real syscall insn
	Num    int64  // resolved syscall number, when recoverable
	HasNum bool   // whether Num was recovered
	Name   string // resolved syscall name (os/arch table), when known
	Origin string // object the site came from (full scan), e.g. "libc.so.6"; "" = this binary
}

// SyscallName resolves a syscall number to its name for f's os/arch, consulting
// any loaded override tables. Exposed so the TUI's syscall modal resolves names
// the same way the dump does.
func SyscallName(f *binfile.File, num int64) (string, bool) {
	return syscalls.Name(syscalls.Key(string(f.Format), f.Arch()), num)
}

// IsVDSOName reports whether a symbol name is a vDSO / kernel-helper entry point,
// i.e. a userspace call that services what would otherwise be a system call.
func IsVDSOName(name string) bool {
	return strings.HasPrefix(name, "__vdso_") || strings.HasPrefix(name, "__kernel_")
}

// ClassifySyscallSite reports whether inst is a syscall site and, if so, whether
// it is a vDSO call. The symAt lookup resolves an instruction's branch target to
// a symbol for the vDSO heuristic; it may be nil to disable that heuristic.
func ClassifySyscallSite(inst disasm.Inst, symAt func(uint64) (binfile.Symbol, bool)) (site bool, vdso bool) {
	if isSyscallInstr(inst.Text) {
		return true, false
	}
	if inst.Class == disasm.ClassCall {
		// The Linux i386 vsyscall trampoline — `call *%gs:0x10` — dispatches to the
		// kernel's __kernel_vsyscall. Static musl routes almost every syscall this
		// way (only TLS/fork/sigreturn startup uses a bare int 0x80), so without
		// this a static i386 binary looks like it makes ~no syscalls. The number is
		// still in eax, so it resolves like any other.
		if isVsyscallCall(inst.Text) {
			return true, false
		}
		if symAt != nil {
			if target, ok := firstAddrOperand(inst.Text); ok {
				if sym, ok := symAt(target); ok && IsVDSOName(sym.Name) {
					return true, true
				}
			}
		}
	}
	return false, false
}

// isVsyscallCall reports whether a call instruction is the i386 vsyscall
// trampoline — an indirect call through the thread pointer (`call *%gs:0x10`).
// On i386 Linux %gs is the TCB and a *call* through it is the vsyscall entry
// (ordinary %gs:offset accesses are data loads, never calls), so this is
// specific.
func isVsyscallCall(text string) bool {
	return strings.Contains(text, "gs:") && strings.Contains(text, "call")
}

// isSyscallInstr reports whether an instruction is a genuine kernel-entry system
// call — not a breakpoint or debug trap. The decoder's ClassSyscall is broader
// (it also tags int3 / brk / ebreak so they get coloured), but those are padding
// or breakpoints, not syscalls, and would otherwise flood the listing. The real
// kernel entries are syscall / sysenter (x86), svc (ARM), ecall (RISC-V) and the
// legacy int 0x80 / int 0x2e software-interrupt gates.
func isSyscallInstr(text string) bool {
	text = strings.TrimSpace(text)
	sp := strings.IndexAny(text, " \t")
	op := text
	if sp >= 0 {
		op = text[:sp]
	}
	switch strings.ToLower(op) {
	case "syscall", "sysenter", "svc", "ecall", "scall":
		return true
	case "int":
		arg := ""
		if sp >= 0 {
			arg = strings.ToLower(strings.TrimSpace(text[sp+1:]))
		}
		return arg == "$0x80" || arg == "0x80" || arg == "$0x2e" || arg == "0x2e"
	}
	return false
}

// ResolveSyscallNum recovers the system-call number for the site at prev[len-1]'s
// successor by scanning the preceding instructions (oldest..newest) for the last
// immediate written to the architecture's syscall-number register. prev must end
// just before the syscall instruction. It is best-effort: a number set in a
// register, computed, or out of the scan window stays unresolved.
func ResolveSyscallNum(prev []disasm.Inst, a disasm.Arch) (int64, bool) {
	regs, attSyntax, ok := syscallNumRegs(a)
	if !ok {
		return 0, false
	}
	lo := 0
	if len(prev) > syscallScanBack {
		lo = len(prev) - syscallScanBack
	}
	for i := len(prev) - 1; i >= lo; i-- {
		t := prev[i].Text
		// A call (cdecl clobbers eax) or a prior syscall (returns in eax) ends the
		// window: the number register's value before it is irrelevant.
		if isCallText(t) || isSyscallInstr(t) {
			return 0, false
		}
		// Stop at the first instruction that writes the number register: if it's an
		// immediate load we have the number, otherwise it's computed/loaded and we
		// can't recover it — either way, don't scan past it (which would wrongly
		// pick up an earlier, unrelated value, e.g. a `xor %eax,%eax`).
		if !writesReg(t, regs, attSyntax) {
			continue
		}
		v, ok := immToRegister(t, regs, attSyntax)
		if ok && plausibleSyscallNum(v) {
			return v, true
		}
		return 0, false
	}
	return 0, false
}

// isCallText reports whether an instruction is a call.
func isCallText(text string) bool {
	text = strings.TrimSpace(text)
	sp := strings.IndexAny(text, " \t")
	op := text
	if sp >= 0 {
		op = text[:sp]
	}
	return strings.HasPrefix(strings.ToLower(op), "call")
}

// writesReg reports whether an instruction's destination is one of regs (the
// last operand in AT&T syntax, the first otherwise). Implicit-destination
// instructions (cdq, mul, …) are not detected, but those rarely precede a
// syscall and the call/syscall barrier above bounds the scan regardless.
func writesReg(text string, regs []string, att bool) bool {
	text = strings.TrimSpace(text)
	sp := strings.IndexAny(text, " \t")
	if sp < 0 {
		return false
	}
	ops := splitOperands(text[sp+1:])
	if len(ops) == 0 {
		return false
	}
	dst := ops[0]
	if att {
		dst = ops[len(ops)-1]
	}
	return matchReg(stripReg(dst), regs)
}

// plausibleSyscallNum rejects values that can't be a Linux/BSD syscall number —
// negatives (e.g. a -1 sentinel loaded into the number register) and absurdly
// large immediates — so a non-number immediate isn't reported as a syscall.
func plausibleSyscallNum(v int64) bool { return v >= 0 && v <= 0xfff }

// syscallNumRegs returns the register names that hold the syscall number for an
// architecture and whether its assembly is AT&T syntax (x86: "$imm,%dst", dest
// last; otherwise "dst, #imm", dest first). ok is false for unhandled arches.
func syscallNumRegs(a disasm.Arch) (regs []string, att bool, ok bool) {
	switch a {
	case disasm.ArchAMD64, disasm.ArchX86:
		return []string{"eax", "rax"}, true, true
	case disasm.ArchARM64:
		// Linux passes the number in x8; Apple/Darwin uses x16. Both are listed
		// because the resolver keeps the *most recent* immediate write before the
		// syscall, which is whichever register that platform actually set.
		return []string{"x8", "w8", "x16", "w16"}, false, true
	case disasm.ArchARM:
		return []string{"r7"}, false, true
	case disasm.ArchRISCV64:
		return []string{"a7", "x17"}, false, true
	}
	return nil, false, false
}

// immToRegister returns the immediate an instruction loads into one of regs, if
// it is a recognised immediate-load. It also handles the x86 "xor %reg,%reg"
// zero idiom (syscall 0). regs are bare names (no %/# prefix).
func immToRegister(text string, regs []string, att bool) (int64, bool) {
	text = strings.TrimSpace(text)
	sp := strings.IndexAny(text, " \t")
	if sp < 0 {
		return 0, false
	}
	mnem := strings.ToLower(text[:sp])
	ops := splitOperands(text[sp+1:])
	if len(ops) < 2 {
		return 0, false
	}

	if att {
		// AT&T: "<mnem> $imm,%dst" — dest is the last operand.
		dst := stripReg(ops[len(ops)-1])
		if !matchReg(dst, regs) {
			return 0, false
		}
		switch {
		case strings.HasPrefix(mnem, "mov"):
			if v, ok := parseImmText(ops[0]); ok {
				return v, true
			}
		case strings.HasPrefix(mnem, "xor"):
			// xor %r,%r  → 0
			if len(ops) == 2 && stripReg(ops[0]) == dst {
				return 0, true
			}
		}
		return 0, false
	}

	// Dest-first syntax (ARM/RISC-V): "<mnem> dst, #imm" / "dst, src, imm".
	dst := stripReg(ops[0])
	if !matchReg(dst, regs) {
		return 0, false
	}
	switch mnem {
	case "mov", "movz", "movs", "li":
		if v, ok := parseImmText(ops[len(ops)-1]); ok {
			return v, true
		}
	case "addi", "add":
		// addi a7, zero, N  (RISC-V li expansion)
		if len(ops) == 3 {
			src := stripReg(ops[1])
			if src == "zero" || src == "x0" {
				if v, ok := parseImmText(ops[2]); ok {
					return v, true
				}
			}
		}
	}
	return 0, false
}

// splitOperands splits an operand list on commas, trimming spaces.
func splitOperands(s string) []string {
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// stripReg normalises a register operand ("%eax", "w8", "x8!") to its bare name.
func stripReg(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "%")
	s = strings.TrimSuffix(s, "!")
	return strings.ToLower(s)
}

// matchReg reports whether bare register name r is one of regs.
func matchReg(r string, regs []string) bool {
	for _, x := range regs {
		if r == x {
			return true
		}
	}
	return false
}

// parseImmText parses an immediate operand ("$0x1", "#0x1", "#1", "0x1", "1").
func parseImmText(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "$")
	s = strings.TrimPrefix(s, "#")
	neg := false
	if strings.HasPrefix(s, "-") {
		neg, s = true, s[1:]
	}
	var v uint64
	var err error
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, err = parseHex(s[2:])
	} else {
		for i := 0; i < len(s); i++ {
			if s[i] < '0' || s[i] > '9' {
				return 0, false
			}
			v = v*10 + uint64(s[i]-'0')
		}
		if s == "" {
			return 0, false
		}
	}
	if err != nil {
		return 0, false
	}
	n := int64(v)
	if neg {
		n = -n
	}
	return n, true
}

// Syscalls dumps the binary's syscall usage. By default it summarises the
// *unique* system calls invoked (one row per distinct number, with a count and
// an example location); with full=true it lists every site with its address,
// like `objdump`-style output.
func Syscalls(f *binfile.File, full bool) string {
	dis, err := disasm.For(f.Arch())
	if err != nil || dis == nil {
		return "no disassembler for this architecture\n"
	}
	sites := collectSyscalls(f, dis)
	if len(sites) == 0 {
		return "no syscall sites found\n"
	}
	if full {
		return syscallsFull(f, sites)
	}
	return syscallsUnique(sites)
}

// SyscallsFull summarises the system calls of the binary *and its directly
// linked libraries* — the real syscall surface of a dynamically linked program,
// whose own code often makes no direct syscalls (they live in libc). The output
// is one merged unique list, each row tagged with the originating object(s).
func SyscallsFull(f *binfile.File) string {
	sites, objs, notes := CollectSyscallsFull(f)
	var b strings.Builder
	fmt.Fprintf(&b, "binary + %d libraries scanned\n", objs-1)
	writeSyscallsUniqueOrigin(&b, sites)
	// On macOS the system libraries (including libsystem_kernel, which holds the
	// actual svc instructions) live in the dyld shared cache rather than as files,
	// so they can't be opened and scanned — and app/framework code itself almost
	// never makes direct syscalls. Collapse the per-library spam into one note.
	if f.Format == binfile.FormatMachO && len(notes) > 0 {
		fmt.Fprintf(&b, "· %d system libraries are in the dyld shared cache (not standalone files) — their syscalls can't be scanned\n", len(notes))
	} else {
		for _, n := range notes {
			b.WriteString(n)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// CollectSyscallsFull scans the binary and its directly linked libraries for
// syscall sites, tagging each with the object it came from. It returns the sites,
// the number of objects scanned, and notes about libraries that couldn't be
// scanned. Shared by the `syscalls-full` dump and the TUI's full scope.
func CollectSyscallsFull(f *binfile.File) (sites []SyscallSite, objects int, notes []string) {
	return CollectSyscallsFullCancel(f, nil)
}

// CollectSyscallsFullCancel is CollectSyscallsFull with cooperative cancellation.
// When done is closed it stops scheduling new library/object work and asks active
// decode workers to exit early. Partial results may be returned; UI callers guard
// cancelled results by sequence/file identity.
func CollectSyscallsFullCancel(f *binfile.File, done <-chan struct{}) (sites []SyscallSite, objects int, notes []string) {
	if scanCancelled(done) {
		return sites, objects, notes
	}
	sites = append(sites, scanObjectCancel(f, "this binary", done)...)
	objects = 1
	if f.Info == nil || scanCancelled(done) {
		return sites, objects, notes
	}
	seen := map[string]bool{}
	for _, lib := range f.Info.DynamicLibs {
		if scanCancelled(done) {
			break
		}
		path, ok := explorer.ResolveLibPath(lib, f.Path, f.Info, nil)
		if !ok {
			notes = append(notes, "· "+lib+" — not resolved on disk")
			continue
		}
		if seen[path] {
			continue
		}
		seen[path] = true
		lf, err := binfile.Open(path)
		if err != nil {
			notes = append(notes, "· "+lib+" — open failed: "+err.Error())
			continue
		}
		sites = append(sites, scanObjectCancel(lf, lib, done)...)
		objects++
		lf.Close()
	}
	return sites, objects, notes
}

// SyscallsArchive summarises the system calls provided by a static-library (ar)
// archive, scanning every object member and tagging each syscall with the member
// it came from. With full=false it prints the merged unique list; with full=true
// it lists every site (its member as the symbol column).
func SyscallsArchive(members []binfile.ArchiveMember, full bool) string {
	var sites []SyscallSite
	scanned := 0
	for _, mem := range members {
		mf, err := binfile.OpenBytes(mem.Name, mem.Data)
		if err != nil {
			continue // non-object member (or unsupported format)
		}
		ms := scanObject(mf, mem.Name)
		for i := range ms {
			ms[i].Sym = mem.Name + ":" + ms[i].Sym
		}
		sites = append(sites, ms...)
		scanned++
	}
	if scanned == 0 {
		return "no scannable object members in archive\n"
	}
	if len(sites) == 0 {
		return fmt.Sprintf("%d object members scanned · no syscall sites found\n", scanned)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d object members scanned\n", scanned)
	if full {
		writeSyscallsUnique(&b, sites) // members are the origin; keep it compact
	} else {
		writeSyscallsUniqueOrigin(&b, sites)
	}
	return b.String()
}

// scanObject collects one object's syscall sites, tagging each with origin.
func scanObject(f *binfile.File, origin string) []SyscallSite {
	return scanObjectCancel(f, origin, nil)
}

func scanObjectCancel(f *binfile.File, origin string, done <-chan struct{}) []SyscallSite {
	dis, err := disasm.For(f.Arch())
	if err != nil || dis == nil {
		return nil
	}
	sites := collectSyscallsCancel(f, dis, done)
	for i := range sites {
		sites[i].Origin = origin
	}
	return sites
}

// writeSyscallsUniqueOrigin writes a merged unique-syscall summary tagged with
// the originating object(s) for each number.
func writeSyscallsUniqueOrigin(b *strings.Builder, sites []SyscallSite) {
	type agg struct {
		num     int64
		hasNum  bool
		vdso    bool
		name    string
		text    string
		count   int
		origins []string
		seen    map[string]bool
	}
	order := []string{}
	byKey := map[string]*agg{}
	for _, s := range sites {
		var k string
		switch {
		case s.HasNum:
			k = fmt.Sprintf("n%d", s.Num)
		case s.VDSO:
			k = "v" + s.Text
		default:
			k = "u" + s.Text
		}
		a := byKey[k]
		if a == nil {
			a = &agg{num: s.Num, hasNum: s.HasNum, vdso: s.VDSO, name: s.Name, text: s.Text, seen: map[string]bool{}}
			byKey[k] = a
			order = append(order, k)
		}
		a.count++
		if o := s.Origin; o != "" && !a.seen[o] {
			a.seen[o] = true
			a.origins = append(a.origins, o)
		}
	}
	aggs := make([]*agg, 0, len(order))
	for _, k := range order {
		aggs = append(aggs, byKey[k])
	}
	sort.Slice(aggs, func(i, j int) bool {
		ai, aj := aggs[i], aggs[j]
		if ai.hasNum != aj.hasNum {
			return ai.hasNum
		}
		if ai.hasNum {
			return ai.num < aj.num
		}
		if ai.vdso != aj.vdso {
			return ai.vdso
		}
		return ai.text < aj.text
	})
	fmt.Fprintf(b, "%d distinct system calls\n", len(aggs))
	for _, a := range aggs {
		origin := strings.Join(a.origins, ", ")
		if origin == "" {
			origin = "—"
		}
		fmt.Fprintf(b, "%-20s %4d×  %-32s %s\n", syscallLabel(a.name, a.num, a.hasNum, a.vdso), a.count, truncASCII(origin, 32), a.text)
	}
}

// syscallsFull lists every syscall site with its address, number and symbol.
func syscallsFull(f *binfile.File, sites []SyscallSite) string {
	addrW := f.AddrHexWidth()
	var b strings.Builder
	for _, s := range sites {
		sym := s.Sym
		if sym == "" {
			sym = "—"
		}
		num := ""
		switch {
		case s.Name != "":
			num = s.Name
		case s.HasNum:
			num = fmt.Sprintf("#%d", s.Num)
		}
		tag := ""
		if s.VDSO {
			tag = "  (vdso)"
		}
		fmt.Fprintf(&b, "0x%0*x  %-16s %-28s %s%s\n", addrW, s.Addr, num, truncASCII(sym, 28), AlignAsm(s.Text), tag)
	}
	return b.String()
}

// syscallsUnique summarises the distinct system calls invoked: one row per
// number (or per vDSO/unresolved site kind), with a use count and an example
// symbol, sorted by number. Sites whose number could not be recovered are
// grouped at the end.
func syscallsUnique(sites []SyscallSite) string {
	var b strings.Builder
	writeSyscallsUnique(&b, sites)
	return b.String()
}

// writeSyscallsUnique writes the unique-syscall summary for sites to b. Shared by
// the `syscalls` view and the per-object `syscalls-full` view.
func writeSyscallsUnique(b *strings.Builder, sites []SyscallSite) {
	type agg struct {
		num     int64
		hasNum  bool
		vdso    bool
		name    string // resolved syscall name, when known
		text    string // representative instruction / vDSO name
		count   int
		example string // first enclosing symbol seen
	}
	order := []string{}
	byKey := map[string]*agg{}
	keyOf := func(s SyscallSite) string {
		switch {
		case s.HasNum:
			return fmt.Sprintf("n%d", s.Num)
		case s.VDSO:
			return "v" + s.Text
		default:
			return "u" + s.Text
		}
	}
	for _, s := range sites {
		k := keyOf(s)
		a := byKey[k]
		if a == nil {
			a = &agg{num: s.Num, hasNum: s.HasNum, vdso: s.VDSO, name: s.Name, text: s.Text, example: s.Sym}
			byKey[k] = a
			order = append(order, k)
		}
		a.count++
		if a.example == "" {
			a.example = s.Sym
		}
	}
	aggs := make([]*agg, 0, len(order))
	for _, k := range order {
		aggs = append(aggs, byKey[k])
	}
	sort.Slice(aggs, func(i, j int) bool {
		// Numbered first (ascending), then vDSO, then unresolved.
		ai, aj := aggs[i], aggs[j]
		if ai.hasNum != aj.hasNum {
			return ai.hasNum
		}
		if ai.hasNum {
			return ai.num < aj.num
		}
		if ai.vdso != aj.vdso {
			return ai.vdso
		}
		return ai.text < aj.text
	})

	fmt.Fprintf(b, "%d distinct system calls\n", len(aggs))
	for _, a := range aggs {
		ex := a.example
		if ex == "" {
			ex = "—"
		}
		fmt.Fprintf(b, "%-20s %4d×  %-28s %s\n", syscallLabel(a.name, a.num, a.hasNum, a.vdso), a.count, truncASCII(ex, 28), a.text)
	}
}

// syscallLabel formats a summary row's leading label: the resolved name (with its
// number) when known, else "#<num>", else "vdso" / "—".
func syscallLabel(name string, num int64, hasNum, vdso bool) string {
	switch {
	case name != "" && hasNum:
		return fmt.Sprintf("#%d %s", num, name)
	case name != "":
		return name
	case hasNum:
		return fmt.Sprintf("#%d", num)
	case vdso:
		return "vdso"
	}
	return "—"
}

// dumpScanChunk / dumpScanLead bound the parallel scan: each worker decodes a
// chunk of code plus a small lead-in for instruction resync and the syscall-
// number backward scan.
const (
	dumpScanChunk = 1 << 20
	dumpScanLead  = 1 << 10
)

// chunkTask is one unit of parallel work: decode raw[lo:hi] (resync overlap
// included), but only emit sites in [emitVA, emitEndVA) so each site is produced
// exactly once.
type chunkTask struct {
	lo, hi    int    // file-byte range to decode, including resync overlap
	baseVA    uint64 // virtual address of raw[lo]
	emitVA    uint64 // emit sites with Addr >= this (chunk's real start)
	emitEndVA uint64 // emit sites with Addr < this (chunk's real end)
}

// collectSyscalls scans every executable section for syscall sites, decoding
// chunks in parallel (decoding dominates the cost, so this scales with cores).
// The per-call vDSO symbol lookup is skipped entirely when the binary has no
// vDSO symbols — the common case — so a large stripped binary's scan is just a
// cheap mnemonic test per instruction.
func collectSyscalls(f *binfile.File, dis disasm.Disassembler) []SyscallSite {
	return collectSyscallsCancel(f, dis, nil)
}

func collectSyscallsCancel(f *binfile.File, dis disasm.Disassembler, done <-chan struct{}) []SyscallSite {
	var secs []binfile.Section
	for _, s := range f.Sections {
		// Exec section with file bytes. Addr may be 0 in a relocatable object
		// (a .o, e.g. an archive member) — still scannable; its instruction
		// addresses are then section-relative, which is fine for finding sites.
		if s.Exec && s.FileSize > 0 {
			secs = append(secs, s)
		}
	}
	sort.Slice(secs, func(i, j int) bool { return secs[i].Addr < secs[j].Addr })
	raw := f.Raw()
	a := f.Arch()
	symAt := vdsoSymAt(f)

	var tasks []chunkTask
	for _, s := range secs {
		secOff := int(s.Offset)
		secEnd := secOff + int(s.FileSize)
		if secEnd > len(raw) {
			secEnd = len(raw)
		}
		for p := secOff; p < secEnd; p += dumpScanChunk {
			emitEnd := min(p+dumpScanChunk, secEnd)
			hi := min(emitEnd+dumpScanLead, secEnd)
			lo := max(secOff, p-dumpScanLead)
			tasks = append(tasks, chunkTask{
				lo:        lo,
				hi:        hi,
				baseVA:    s.Addr + uint64(lo-secOff),
				emitVA:    s.Addr + uint64(p-secOff),
				emitEndVA: s.Addr + uint64(emitEnd-secOff),
			})
		}
	}

	results := make([][]SyscallSite, len(tasks))
	workers := max(min(runtime.GOMAXPROCS(0), len(tasks)), 1)
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i, tk := range tasks {
		if scanCancelled(done) {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, tk chunkTask) {
			defer wg.Done()
			defer func() { <-sem }()
			if scanCancelled(done) {
				return
			}
			code := raw[tk.lo:tk.hi]
			if symAt == nil {
				// With no vDSO call heuristic to run, locate syscall opcodes by byte
				// signature and decode only a bounded window around each candidate.
				if instLen := syscallInstLen(a); instLen > 0 {
					results[i] = scanChunkLocalized(dis, code, tk.baseVA, tk.emitVA, tk.emitEndVA, a, instLen, f, done)
					return
				}
				if a == disasm.ArchAMD64 || a == disasm.ArchX86 {
					results[i] = scanChunkX86Localized(dis, code, tk.baseVA, tk.emitVA, tk.emitEndVA, a, f, done)
					return
				}
			}
			// Otherwise skip a chunk that can't contain a syscall (the opcode byte
			// patterns are present in every real syscall/trampoline encoding), then
			// fully decode the rest — needed for variable-length x86 and the vDSO
			// call heuristic.
			if !chunkHasSyscallCandidate(code, a, done) {
				return
			}
			results[i] = scanChunk(dis, code, tk.baseVA, tk.emitVA, tk.emitEndVA, a, symAt, f, done)
		}(i, tk)
	}
	wg.Wait()

	var out []SyscallSite
	for _, rs := range results {
		out = append(out, rs...)
	}
	// Resolve each recovered number to a name for this binary's os/arch (user
	// override tables consulted first; see -syscall-tables).
	key := syscalls.Key(string(f.Format), f.Arch())
	for i := range out {
		if out[i].HasNum {
			if name, ok := syscalls.Name(key, out[i].Num); ok {
				out[i].Name = name
			}
		}
	}
	return out
}

// chunkHasSyscallCandidate reports whether code can contain a syscall site, so a
// chunk that provably can't is skipped without decoding (decoding dominates the
// scan, and most code makes no syscalls). x86 keys off the fixed opcode bytes;
// arm64/arm scan for the svc encoding at any offset (an unaligned coincidence just
// decodes the chunk — still correct, never a miss). Other arches have no compact
// signature and are always decoded.
func chunkHasSyscallCandidate(code []byte, a disasm.Arch, done <-chan struct{}) bool {
	if scanCancelled(done) {
		return false
	}
	switch a {
	case disasm.ArchAMD64, disasm.ArchX86:
		// syscall (0f 05), sysenter (0f 34), int 0x80/0x2e, gs-indirect call such
		// as the i386 vsyscall trampoline (65 ff …).
		for _, p := range [][]byte{{0x0f, 0x05}, {0x0f, 0x34}, {0xcd, 0x80}, {0xcd, 0x2e}, {0x65, 0xff}} {
			if bytes.Index(code, p) >= 0 {
				return true
			}
		}
		return false
	case disasm.ArchARM64:
		// svc #imm16 = 0xd4000001 | (imm<<5).
		for i := 0; i+4 <= len(code); i++ {
			if i&0xfff == 0 && scanCancelled(done) {
				return false
			}
			if binary.LittleEndian.Uint32(code[i:])&0xffe0001f == 0xd4000001 {
				return true
			}
		}
		return false
	case disasm.ArchARM:
		// ARM-mode SVC: cond·1111·imm24 → opcode bits 27..24 all set.
		for i := 0; i+4 <= len(code); i++ {
			if i&0xfff == 0 && scanCancelled(done) {
				return false
			}
			if binary.LittleEndian.Uint32(code[i:])&0x0f000000 == 0x0f000000 {
				return true
			}
		}
		return false
	}
	return true
}

// syscallInstLen returns the fixed instruction width for arches whose syscall
// instruction (svc) can be located by a byte test, enabling a localized scan that
// decodes only a window around each site rather than the whole chunk. 0 means the
// arch is variable-length (x86) and must be fully decoded.
func syscallInstLen(a disasm.Arch) int {
	switch a {
	case disasm.ArchARM64, disasm.ArchARM:
		return 4
	}
	return 0
}

// isSvcEncoding reports whether the 4 bytes at b are a kernel-entry svc on a.
func isSvcEncoding(b []byte, a disasm.Arch) bool {
	if len(b) < 4 {
		return false
	}
	w := binary.LittleEndian.Uint32(b)
	switch a {
	case disasm.ArchARM64:
		return w&0xffe0001f == 0xd4000001
	case disasm.ArchARM:
		return w&0x0f000000 == 0x0f000000
	}
	return false
}

// scanChunkLocalized finds syscall sites on a fixed-width arch by scanning for the
// svc byte encoding and decoding only a bounded backward window at each match —
// so the (overwhelming majority of) non-syscall instructions are never decoded or
// text-formatted. Used when there is no vDSO heuristic to run (the common case);
// the full scanChunk is kept for variable-length arches and vDSO-bearing binaries.
func scanChunkLocalized(dis disasm.Disassembler, code []byte, baseVA, emitVA, emitEndVA uint64, a disasm.Arch, instLen int, f *binfile.File, done <-chan struct{}) []SyscallSite {
	var out []SyscallSite
	il := uint64(instLen)
	start := int((il - baseVA%il) % il) // align the scan to instruction boundaries
	for i := start; i+instLen <= len(code); i += instLen {
		if scanCancelled(done) {
			break
		}
		if !isSvcEncoding(code[i:], a) {
			continue
		}
		va := baseVA + uint64(i)
		if va < emitVA {
			continue
		}
		if va >= emitEndVA {
			break
		}
		lo := i - syscallScanBack*instLen
		if lo < start {
			lo = start
		}
		window := disasm.Range(dis, code[lo:i+instLen], baseVA+uint64(lo), 0)
		if len(window) == 0 {
			continue
		}
		site := window[len(window)-1]
		if site.Addr != va || !isSyscallInstr(site.Text) {
			continue // resync drift or a byte coincidence that isn't really svc
		}
		hit := SyscallSite{Addr: va, Text: strings.TrimSpace(site.Text)}
		if sm, ok := f.SymbolAt(va); ok {
			hit.Sym = sm.Display()
		}
		if n, ok := ResolveSyscallNum(window[:len(window)-1], a); ok {
			hit.Num, hit.HasNum = n, true
		}
		out = append(out, hit)
	}
	return out
}

func scanChunkX86Localized(dis disasm.Disassembler, code []byte, baseVA, emitVA, emitEndVA uint64, a disasm.Arch, f *binfile.File, done <-chan struct{}) []SyscallSite {
	var out []SyscallSite
	for _, off := range x86SyscallCandidateOffsets(code, done) {
		if scanCancelled(done) {
			break
		}
		va := baseVA + uint64(off)
		if va < emitVA {
			continue
		}
		if va >= emitEndVA {
			break
		}
		site, vdso, num, hasNum, ok := decodeX86Candidate(dis, code, baseVA, off, a, done)
		if !ok {
			continue // opcode bytes inside another instruction
		}
		hit := SyscallSite{Addr: va, Text: strings.TrimSpace(site.Text), VDSO: vdso}
		if sm, ok := f.SymbolAt(va); ok {
			hit.Sym = sm.Display()
		}
		if hasNum {
			hit.Num, hit.HasNum = num, true
		}
		out = append(out, hit)
	}
	return out
}

func decodeX86Candidate(dis disasm.Disassembler, code []byte, baseVA uint64, off int, a disasm.Arch, done <-chan struct{}) (disasm.Inst, bool, int64, bool, bool) {
	// An x86 instruction is at most 15 bytes. Try every possible previous
	// instruction start in that window; a true linear instruction boundary must
	// have a decode path that reaches the candidate offset exactly. This avoids
	// both arbitrary-window resync misses and obvious false positives in immediates.
	lo := off - 15
	if lo < 0 {
		lo = 0
	}
	hi := min(off+16, len(code))
	if hi <= off {
		return disasm.Inst{}, false, 0, false, false
	}
	va := baseVA + uint64(off)
	for start := lo; start < off || (off == 0 && start == 0); start++ {
		if scanCancelled(done) {
			return disasm.Inst{}, false, 0, false, false
		}
		var prev [syscallScanBack]disasm.Inst
		prevN := 0
		var site disasm.Inst
		var siteVDSO bool
		var num int64
		var hasNum, found bool
		disasm.RangeFunc(dis, code[start:hi], baseVA+uint64(start), func(in disasm.Inst) bool {
			if scanCancelled(done) {
				return false
			}
			if in.Addr > va {
				return false
			}
			if in.Addr == va {
				if ok, vdso := ClassifySyscallSite(in, nil); ok {
					site, siteVDSO, found = in, vdso, true
					if !vdso {
						num, hasNum = ResolveSyscallNum(prev[:prevN], a)
					}
				}
				return false
			}
			if prevN == syscallScanBack {
				copy(prev[:], prev[1:])
				prev[prevN-1] = in
			} else {
				prev[prevN] = in
				prevN++
			}
			return true
		})
		if found {
			return site, siteVDSO, num, hasNum, true
		}
	}
	return disasm.Inst{}, false, 0, false, false
}

func x86SyscallCandidateOffsets(code []byte, done <-chan struct{}) []int {
	var out []int
	for i := 0; i+1 < len(code); i++ {
		if i&0xfff == 0 && scanCancelled(done) {
			return out
		}
		switch {
		case code[i] == 0x0f && (code[i+1] == 0x05 || code[i+1] == 0x34): // syscall/sysenter
		case code[i] == 0xcd && (code[i+1] == 0x80 || code[i+1] == 0x2e): // int 0x80/0x2e
		case code[i] == 0x65 && code[i+1] == 0xff: // i386 %gs vsyscall trampoline call
		default:
			continue
		}
		out = append(out, i)
	}
	return out
}

// scanChunk decodes one chunk and returns its syscall sites within the chunk's
// real range, recovering each number from a bounded ring of preceding instructions.
func scanChunk(dis disasm.Disassembler, code []byte, baseVA, emitVA, emitEndVA uint64, a disasm.Arch,
	symAt func(uint64) (binfile.Symbol, bool), f *binfile.File, done <-chan struct{}) []SyscallSite {
	var out []SyscallSite
	recent := make([]disasm.Inst, 0, syscallScanBack)
	disasm.RangeFunc(dis, code, baseVA, func(in disasm.Inst) bool {
		if scanCancelled(done) {
			return false
		}
		if in.Addr >= emitEndVA {
			return false
		}
		if in.Addr >= emitVA {
			if site, vdso := ClassifySyscallSite(in, symAt); site {
				hit := SyscallSite{Addr: in.Addr, Text: strings.TrimSpace(in.Text), VDSO: vdso}
				if sm, ok := f.SymbolAt(in.Addr); ok {
					hit.Sym = sm.Display()
				}
				if !vdso {
					if n, ok := ResolveSyscallNum(recent, a); ok {
						hit.Num, hit.HasNum = n, true
					}
				}
				out = append(out, hit)
			}
		}
		if len(recent) == syscallScanBack {
			copy(recent, recent[1:])
			recent[len(recent)-1] = in
		} else {
			recent = append(recent, in)
		}
		return true
	})
	return out
}

// VDSOSymAt returns f.SymbolAt only when the binary actually has vDSO/__kernel_
// symbols; otherwise nil, so a scan can skip the per-call-instruction symbol
// lookup the vDSO heuristic would otherwise do on every call in the image.
// Exported so the TUI scan can apply the same optimisation.
func VDSOSymAt(f *binfile.File) func(uint64) (binfile.Symbol, bool) { return vdsoSymAt(f) }

// vdsoSymAt returns f.SymbolAt only when the binary actually has vDSO/__kernel_
// symbols; otherwise nil, so the scan skips the per-call-instruction symbol
// lookup the vDSO heuristic would otherwise do on every call in the image.
func vdsoSymAt(f *binfile.File) func(uint64) (binfile.Symbol, bool) {
	for i := range f.Symbols {
		if IsVDSOName(f.Symbols[i].Name) {
			return f.SymbolAt
		}
	}
	return nil
}

// firstAddrOperand returns the first absolute "0x…" operand in an instruction's
// text (a resolved branch/call target), if any.
func firstAddrOperand(text string) (uint64, bool) {
	i := strings.Index(text, "0x")
	if i < 0 {
		return 0, false
	}
	j := i + 2
	for j < len(text) && isHexDigit(text[j]) {
		j++
	}
	if j == i+2 {
		return 0, false
	}
	v, err := parseHex(text[i+2 : j])
	if err != nil {
		return 0, false
	}
	return v, true
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func parseHex(s string) (uint64, error) {
	if s == "" {
		return 0, fmt.Errorf("empty hex")
	}
	var v uint64
	for i := 0; i < len(s); i++ {
		c := s[i]
		var d uint64
		switch {
		case c >= '0' && c <= '9':
			d = uint64(c - '0')
		case c >= 'a' && c <= 'f':
			d = uint64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = uint64(c-'A') + 10
		default:
			return 0, fmt.Errorf("bad hex")
		}
		v = v<<4 | d
	}
	return v, nil
}

// truncASCII trims s to at most w columns (ASCII names), with an ellipsis.
func truncASCII(s string, w int) string {
	if len(s) <= w {
		return s
	}
	if w <= 1 {
		return s[:w]
	}
	return s[:w-1] + "…"
}
