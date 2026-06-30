// Package disasm wraps golang.org/x/arch to provide a uniform decoder across
// x86, x86-64, ARM64, RISC-V 64, 32-bit ARM, PowerPC (32- and 64-bit, both
// endians), s390x and LoongArch 64.
package disasm

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/rabarbra/exex/internal/arch"

	"golang.org/x/arch/arm/armasm"
	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/loong64/loong64asm"
	"golang.org/x/arch/ppc64/ppc64asm"
	"golang.org/x/arch/riscv64/riscv64asm"
	"golang.org/x/arch/s390x/s390xasm"
	"golang.org/x/arch/x86/x86asm"
)

// Arch aliases the shared architecture selector used by binary loaders.
type Arch = arch.Arch

const (
	ArchUnknown = arch.ArchUnknown
	ArchX86     = arch.ArchX86
	ArchAMD64   = arch.ArchAMD64
	ArchARM64   = arch.ArchARM64
	ArchRISCV64 = arch.ArchRISCV64
	ArchARM     = arch.ArchARM
	ArchPPC64   = arch.ArchPPC64
	ArchPPC64LE = arch.ArchPPC64LE
	ArchS390X   = arch.ArchS390X
	ArchLoong64 = arch.ArchLoong64
	ArchPPC     = arch.ArchPPC
	ArchPPCLE   = arch.ArchPPCLE
)

// InstClass classifies an instruction's high-level role so the UI can colour
// it appropriately. Classification is done from the rendered mnemonic, which
// keeps the logic uniform across architectures (and means GAS pseudos like
// `ret` and `j` on RISC-V get picked up correctly).
type InstClass uint8

const (
	ClassOther InstClass = iota
	ClassCall
	ClassRet
	ClassJumpCond
	ClassJumpUnc
	ClassSyscall
	ClassNop
	ClassMove
	ClassArithmetic
)

var movePrefixes = []string{
	"mov", "cmov", "vmov", "ldr", "ldp", "ldur", "ldar", "str", "stp", "stur", "stlr", "swp", "push", "pop",
}

var moveMnemonics = map[string]bool{
	"lea": true, "leaq": true, "leal": true, "leaw": true,
	"adr": true, "adrp": true, "mv": true, "li": true, "la": true, "lui": true, "auipc": true,
	"lb": true, "lh": true, "lw": true, "ld": true, "lbu": true, "lhu": true, "lwu": true,
	"sb": true, "sh": true, "sw": true, "sd": true, "flw": true, "fld": true, "fsw": true, "fsd": true,
	"xchg": true, "xadd": true,
}

var arithmeticPrefixes = []string{
	"add", "sub", "mul", "imul", "div", "idiv", "cmp", "test", "and", "orr", "eor", "xor",
	"shl", "shr", "sal", "sar", "rol", "ror", "sll", "srl", "sra", "slt", "rem", "fadd", "fsub", "fmul", "fdiv",
}

var arithmeticMnemonics = map[string]bool{
	"inc": true, "dec": true, "neg": true, "not": true, "adc": true, "sbb": true,
	"cmn": true, "tst": true, "madd": true, "msub": true, "udiv": true, "sdiv": true,
	"andi": true, "ori": true, "xori": true,
}

// Inst is one decoded instruction.
type Inst struct {
	Addr  uint64
	Bytes []byte
	Text  string
	Class InstClass
}

// Classify maps a rendered instruction's mnemonic to an InstClass. Exported so
// callers that already hold an Inst.Text (e.g. after Range) can re-classify.
func Classify(text string) InstClass {
	text = strings.TrimSpace(text)
	sp := strings.IndexAny(text, " \t")
	op := text
	if sp >= 0 {
		op = text[:sp]
	}
	op = lowerASCII(op)

	// "blr" is ambiguous: ARM64 "blr <reg>" is an indirect call, but PowerPC "blr"
	// (no operand) is branch-to-link-register, i.e. a return. Disambiguate by
	// whether an operand follows.
	if op == "blr" {
		if sp < 0 {
			return ClassRet
		}
		return ClassCall
	}
	switch op {
	case "call", "callq", "calll", "callw":
		return ClassCall
	case "bl", "blraa", "blrab", "blraaz", "blrabz", "blx", "blrl", "bctrl":
		return ClassCall
	case "jal", "jalr":
		return ClassCall
	case "ret", "retq", "retl", "retw", "iret", "iretq", "iretd", "iretw",
		"retaa", "retab":
		return ClassRet
	case "syscall", "sysenter", "svc", "ecall", "ebreak",
		"int", "into", "int3", "hvc", "smc", "brk":
		return ClassSyscall
	case "nop", "fnop":
		return ClassNop
	case "jmp", "jmpq", "jmpl", "jmpw", "jmpf",
		"b", "br", "j", "bctr", "ba":
		return ClassJumpUnc
	}
	if strings.HasPrefix(op, "j") {
		return ClassJumpCond
	}
	if strings.HasPrefix(op, "b.") {
		return ClassJumpCond
	}
	switch op {
	case "beq", "bne", "blt", "bge", "bltu", "bgeu",
		"beqz", "bnez", "bltz", "bgez", "bgtz", "blez":
		return ClassJumpCond
	// ARM64 compare/test-and-branch.
	case "cbz", "cbnz", "tbz", "tbnz":
		return ClassJumpCond
	}
	if len(op) == 3 && op[0] == 'b' {
		switch op[1:] {
		case "eq", "ne", "lt", "le", "gt", "ge",
			"hi", "ls", "cs", "cc", "mi", "pl", "vs", "vc", "al":
			return ClassJumpCond
		}
	}
	if moveMnemonics[op] || hasMnemonicPrefix(op, movePrefixes) {
		return ClassMove
	}
	if arithmeticMnemonics[op] || hasMnemonicPrefix(op, arithmeticPrefixes) {
		return ClassArithmetic
	}
	return ClassOther
}

func hasMnemonicPrefix(op string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(op, prefix) {
			return true
		}
	}
	return false
}

func lowerASCII(s string) string {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			b := []byte(s)
			b[i] = c + ('a' - 'A')
			for j := i + 1; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
		if c >= 0x80 {
			return strings.ToLower(s)
		}
	}
	return s
}

// Disassembler decodes a single instruction at code[0] for VM address addr.
// On failure the caller should advance by Step() bytes and try again.
type Disassembler interface {
	Decode(code []byte, addr uint64) (Inst, error)
	// Step is the minimum sane re-sync stride when decode fails.
	Step() int
	// Name is a short identifier ("x86-64", "arm64", ...).
	Name() string
}

// MaxInstLen returns the longest instruction encoding (in bytes) for an
// architecture, used to size the byte column in disassembly views. Fixed-length
// RISC ISAs need only their word size, so their column is much narrower than the
// variable-length x86 cap; an unknown arch falls back to the x86 cap.
func MaxInstLen(a Arch) int {
	switch a {
	case ArchARM64, ArchARM, ArchPPC64, ArchPPC64LE, ArchPPC, ArchPPCLE, ArchLoong64, ArchRISCV64:
		return 4 // fixed 4 bytes (RISC-V's compressed forms are 2, still ≤ 4)
	case ArchS390X:
		return 6 // 2, 4 or 6
	}
	return 8 // x86/x86-64 are variable-length; cap the column as before
}

// For returns a single-instruction decoder for a supported architecture.
func For(a Arch) (Disassembler, error) {
	switch a {
	case ArchAMD64:
		return amd64{}, nil
	case ArchX86:
		return x86{}, nil
	case ArchARM64:
		return arm64d{}, nil
	case ArchRISCV64:
		return riscv64d{}, nil
	case ArchARM:
		return armd{}, nil
	case ArchPPC64:
		return ppc64d{ord: binary.BigEndian, name: "ppc64"}, nil
	case ArchPPC64LE:
		return ppc64d{ord: binary.LittleEndian, name: "ppc64le"}, nil
	case ArchPPC:
		// 32-bit PowerPC shares the ppc64 instruction encodings (the base ISA).
		return ppc64d{ord: binary.BigEndian, name: "ppc"}, nil
	case ArchPPCLE:
		return ppc64d{ord: binary.LittleEndian, name: "ppcle"}, nil
	case ArchS390X:
		return s390xd{}, nil
	case ArchLoong64:
		return loong64d{}, nil
	}
	return nil, fmt.Errorf("unsupported architecture")
}

// amd64 adapts x/arch's 64-bit x86 decoder.
type amd64 struct{}

// Name returns the decoder's short display name.
func (amd64) Name() string { return "x86-64" }

// Step returns the resynchronization stride after decode errors.
func (amd64) Step() int { return 1 }

// Decode decodes one x86-64 instruction at addr.
func (amd64) Decode(code []byte, addr uint64) (Inst, error) {
	inst, err := decodeX86(code, 64)
	if err != nil {
		return Inst{}, err
	}
	text := x86asm.GNUSyntax(inst, addr, nil)
	return Inst{Addr: addr, Bytes: code[:inst.Len], Text: text, Class: Classify(text)}, nil
}

// x86 adapts x/arch's 32-bit x86 decoder.
type x86 struct{}

// Name returns the decoder's short display name.
func (x86) Name() string { return "x86" }

// Step returns the resynchronization stride after decode errors.
func (x86) Step() int { return 1 }

// Decode decodes one x86 instruction at addr.
func (x86) Decode(code []byte, addr uint64) (Inst, error) {
	inst, err := decodeX86(code, 32)
	if err != nil {
		return Inst{}, err
	}
	text := mask32Targets(x86asm.GNUSyntax(inst, addr, nil))
	return Inst{Addr: addr, Bytes: code[:inst.Len], Text: text, Class: Classify(text)}, nil
}

// mask32Targets narrows any hex literal wider than 32 bits to its low word.
// x86asm computes PC-relative targets in 64-bit arithmetic, so a backward branch
// in 32-bit code — e.g. a jump into a higher-half kernel's .text at 0xc0101000 —
// overflows to a sign-extended 0xffffffffc0101000. The real target is the low 32
// bits; masking it keeps the address matching the binary's 32-bit section/symbol
// addresses, so it resolves to a name and can be followed. (32-bit code never
// has a legitimately wider literal, so this only ever fixes overflowed targets.)
func mask32Targets(text string) string {
	if !strings.Contains(text, "0x") && !strings.Contains(text, "0X") {
		return text
	}
	var b strings.Builder
	for i := 0; i < len(text); {
		if text[i] == '0' && i+1 < len(text) && (text[i+1] == 'x' || text[i+1] == 'X') {
			start := i + 2
			j := start
			for j < len(text) && isHexDigit(text[j]) {
				j++
			}
			if v, err := strconv.ParseUint(text[start:j], 16, 64); j > start && err == nil && v > 0xffffffff {
				appendHexTo(&b, v&0xffffffff)
				i = j
				continue
			}
			b.WriteString(text[i:j])
			i = j
			continue
		}
		b.WriteByte(text[i])
		i++
	}
	return b.String()
}

// decodeX86 wraps x86asm.Decode and turns decoder panics into errors.
func decodeX86(code []byte, mode int) (inst x86asm.Inst, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("x86 decode panic: %v", r)
		}
	}()
	return x86asm.Decode(code, mode)
}

// arm64d adapts x/arch's ARM64 decoder.
type arm64d struct{}

// Name returns the decoder's short display name.
func (arm64d) Name() string { return "arm64" }

// Step returns the resynchronization stride after decode errors.
func (arm64d) Step() int { return 4 }

// Decode decodes one ARM64 instruction at addr.
func (arm64d) Decode(code []byte, addr uint64) (Inst, error) {
	if len(code) < 4 {
		return Inst{}, fmt.Errorf("short read")
	}
	inst, err := arm64asm.Decode(code)
	if err != nil {
		return Inst{}, err
	}
	text := hexImmediates(resolveRelTargets(arm64asm.GNUSyntax(inst), addr))
	return Inst{Addr: addr, Bytes: code[:4], Text: text, Class: Classify(text)}, nil
}

// riscv64d adapts x/arch's RISC-V 64 decoder.
type riscv64d struct{}

// Name returns the decoder's short display name.
func (riscv64d) Name() string { return "riscv64" }

// Step returns the resynchronization stride after decode errors.
func (riscv64d) Step() int { return 2 }

// Decode decodes one RISC-V 64 instruction at addr.
func (riscv64d) Decode(code []byte, addr uint64) (Inst, error) {
	if len(code) < 2 {
		return Inst{}, fmt.Errorf("short read")
	}
	// Decode wants 4 bytes; pad if we only have 2 (compressed at end of buf).
	src := code
	if len(src) < 4 {
		buf := make([]byte, 4)
		copy(buf, src)
		src = buf
	}
	inst, err := riscv64asm.Decode(src)
	if err != nil {
		return Inst{}, err
	}
	n := inst.Len
	if n == 0 || n > len(code) {
		n = 2
	}
	text := resolveRiscvBranch(resolveRelTargets(riscv64asm.GNUSyntax(inst), addr), addr)
	return Inst{Addr: addr, Bytes: code[:n], Text: text, Class: Classify(text)}, nil
}

// resolveRiscvBranch rewrites the PC-relative target of a RISC-V branch/jump from
// the bare signed decimal offset that riscv64asm prints (e.g. "j 50", "bnez
// x10,12", "j -40") into an absolute address ("j 0x10fed98"). riscv64asm.GNUSyntax
// takes no PC, so without this branch targets stay relative — unreadable and
// invisible to the UI's symbol annotation, which keys off absolute 0x… operands.
// Only true PC-relative branches are touched (the offset is the last operand and a
// pure signed decimal); register offsets like "jalr x1,528(x1)" and immediates
// like "addi x2,x2,-48" are left alone via the mnemonic gate.
func resolveRiscvBranch(text string, addr uint64) string {
	sp := strings.IndexAny(text, " \t")
	if sp < 0 {
		return text
	}
	op := lowerASCII(text[:sp])
	branch := op == "jal" || op == "j"
	if !branch {
		switch Classify(text) {
		case ClassJumpCond, ClassJumpUnc:
			branch = true
		}
	}
	if !branch {
		return text
	}
	args := text[sp+1:]
	head := len(text[:sp]) + 1 // index in text where args begin
	lastComma := strings.LastIndex(args, ",")
	last := strings.TrimSpace(args[lastComma+1:])
	off, err := strconv.ParseInt(last, 10, 64)
	if err != nil {
		return text // not a bare PC-relative offset (e.g. "528(x1)")
	}
	target := addr + uint64(off) // uint64 wraparound handles negative offsets
	return text[:head+lastComma+1] + fmt.Sprintf("0x%x", target)
}

// armd adapts x/arch's 32-bit ARM decoder. Only the A32 (ARM) instruction set is
// decoded — x/arch's armasm does not implement Thumb — which matches the A32 code
// Go and Zig emit for the ELF arm target.
type armd struct{}

// Name returns the decoder's short display name.
func (armd) Name() string { return "arm" }

// Step returns the resynchronization stride after decode errors.
func (armd) Step() int { return 4 }

// Decode decodes one 32-bit ARM (A32) instruction at addr.
func (armd) Decode(code []byte, addr uint64) (out Inst, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = Inst{}, fmt.Errorf("arm decode panic: %v", r)
		}
	}()
	if len(code) < 4 {
		return Inst{}, fmt.Errorf("short read")
	}
	inst, derr := armasm.Decode(code, armasm.ModeARM)
	if derr != nil {
		return Inst{}, derr
	}
	n := inst.Len
	if n == 0 || n > len(code) {
		n = 4
	}
	text := hexImmediates(resolveRelTargets(armasm.GNUSyntax(inst), addr))
	return Inst{Addr: addr, Bytes: code[:n], Text: text, Class: Classify(text)}, nil
}

// ppc64d adapts x/arch's PowerPC 64 decoder. The byte order is fixed per slice
// (big-endian for ppc64, little for ppc64le), so it is baked in at construction.
type ppc64d struct {
	ord  binary.ByteOrder
	name string
}

// Name returns the decoder's short display name.
func (d ppc64d) Name() string { return d.name }

// Step returns the resynchronization stride after decode errors.
func (ppc64d) Step() int { return 4 }

// Decode decodes one PowerPC 64 instruction at addr.
func (d ppc64d) Decode(code []byte, addr uint64) (out Inst, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = Inst{}, fmt.Errorf("ppc64 decode panic: %v", r)
		}
	}()
	if len(code) < 4 {
		return Inst{}, fmt.Errorf("short read")
	}
	inst, derr := ppc64asm.Decode(code, d.ord)
	if derr != nil {
		return Inst{}, derr
	}
	n := inst.Len
	if n == 0 || n > len(code) {
		n = 4
	}
	text := ppc64asm.GNUSyntax(inst, addr)
	return Inst{Addr: addr, Bytes: code[:n], Text: text, Class: Classify(text)}, nil
}

// s390xd adapts x/arch's s390x (IBM Z) decoder. Instructions are 2, 4 or 6 bytes
// and the architecture is always big-endian.
type s390xd struct{}

// Name returns the decoder's short display name.
func (s390xd) Name() string { return "s390x" }

// Step returns the resynchronization stride after decode errors.
func (s390xd) Step() int { return 2 }

// Decode decodes one s390x instruction at addr.
func (s390xd) Decode(code []byte, addr uint64) (out Inst, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = Inst{}, fmt.Errorf("s390x decode panic: %v", r)
		}
	}()
	if len(code) < 2 {
		return Inst{}, fmt.Errorf("short read")
	}
	inst, derr := s390xasm.Decode(code)
	if derr != nil {
		return Inst{}, derr
	}
	n := inst.Len
	if n == 0 || n > len(code) {
		n = 2
	}
	text := s390xasm.GNUSyntax(inst, addr)
	return Inst{Addr: addr, Bytes: code[:n], Text: text, Class: Classify(text)}, nil
}

// loong64d adapts x/arch's LoongArch 64 decoder. Instructions are a fixed 4 bytes,
// little-endian.
type loong64d struct{}

// Name returns the decoder's short display name.
func (loong64d) Name() string { return "loong64" }

// Step returns the resynchronization stride after decode errors.
func (loong64d) Step() int { return 4 }

// Decode decodes one LoongArch 64 instruction at addr.
func (loong64d) Decode(code []byte, addr uint64) (out Inst, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = Inst{}, fmt.Errorf("loong64 decode panic: %v", r)
		}
	}()
	if len(code) < 4 {
		return Inst{}, fmt.Errorf("short read")
	}
	inst, derr := loong64asm.Decode(code)
	if derr != nil {
		return Inst{}, derr
	}
	text := resolveRelTargets(loong64asm.GNUSyntax(inst), addr)
	return Inst{Addr: addr, Bytes: code[:4], Text: text, Class: Classify(text)}, nil // fixed 4-byte
}

// resolveRelTargets rewrites PC-relative branch operands that the ARM64/RISC-V
// syntaxers print as ".+0x…" / ".-0x…" into the absolute target address, so the
// UI's address-following and symbol annotation work on them. The offset is the
// signed displacement (e.g. ".+0xfffffffffffffc58" is a negative jump); uint64
// wraparound makes "addr + value" land on the right byte either way.
func resolveRelTargets(text string, addr uint64) string {
	// Fast path: only branch/PC-relative operands carry the ".+0x"/".-0x" form, so
	// the vast majority of instructions need no rewrite — skip the allocation.
	if !strings.Contains(text, ".+0x") && !strings.Contains(text, ".-0x") &&
		!strings.Contains(text, ".+0X") && !strings.Contains(text, ".-0X") {
		return text
	}
	var b strings.Builder
	for i := 0; i < len(text); {
		if text[i] == '.' && i+3 < len(text) &&
			(text[i+1] == '+' || text[i+1] == '-') &&
			text[i+2] == '0' && (text[i+3] == 'x' || text[i+3] == 'X') {
			start := i + 4
			j := start
			for j < len(text) && isHexDigit(text[j]) {
				j++
			}
			if j > start {
				if v, err := strconv.ParseUint(text[start:j], 16, 64); err == nil {
					target := addr + v
					if text[i+1] == '-' {
						target = addr - v
					}
					appendHexTo(&b, target)
					i = j
					continue
				}
			}
		}
		b.WriteByte(text[i])
		i++
	}
	return b.String()
}

// hexImmediates rewrites the decimal immediates the ARM/ARM64 GNU syntaxers print
// (e.g. memory offsets "[sp,#8]", "[sp,#-16]") into hex, so they read like objdump
// ("[sp,#0x8]", "[sp,#-0x10]"). Immediates already in hex ("#0x40"), floats
// ("#1.0") and any non-"#" use are left untouched; x86 immediates use "$" and are
// already hex, so only the ARM-family decoders call this. The fast path returns
// the input unchanged (no allocation) when there is no "#" to rewrite.
func hexImmediates(s string) string {
	if strings.IndexByte(s, '#') < 0 {
		return s
	}
	var b strings.Builder
	changed := false
	for i := 0; i < len(s); {
		if s[i] != '#' {
			if changed {
				b.WriteByte(s[i])
			}
			i++
			continue
		}
		j := i + 1
		neg := false
		if j < len(s) && (s[j] == '-' || s[j] == '+') {
			neg = s[j] == '-'
			j++
		}
		start := j
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
		}
		// Leave it alone unless this is a plain decimal: no digits, an "0x" hex
		// prefix, or a "." float suffix all mean "not a decimal immediate".
		if start == j || (j < len(s) && (s[j] == 'x' || s[j] == 'X' || s[j] == '.')) {
			if changed {
				b.WriteByte('#')
			}
			i++
			continue
		}
		v, err := strconv.ParseUint(s[start:j], 10, 64)
		if err != nil {
			if changed {
				b.WriteByte('#')
			}
			i++
			continue
		}
		if !changed {
			b.Grow(len(s) + 8)
			b.WriteString(s[:i])
			changed = true
		}
		b.WriteByte('#')
		if neg {
			b.WriteByte('-')
		}
		appendHexTo(&b, v)
		i = j
	}
	if !changed {
		return s
	}
	return b.String()
}

// appendHexTo writes "0x" + v in lowercase hex to b without fmt's interface
// boxing — these decoders run on every instruction, so the dump/TUI decode paths
// are allocation-sensitive. The scratch array stays on the stack.
func appendHexTo(b *strings.Builder, v uint64) {
	b.WriteString("0x")
	var tmp [16]byte
	b.Write(strconv.AppendUint(tmp[:0], v, 16))
}

// isHexDigit reports whether c is an ASCII hex digit.
func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// RangeFunc walks the buffer and decodes instructions, calling fn for each (a
// "(bad)" placeholder of Step() bytes on a decode error). It stops early when fn
// returns false, so callers can stream output without buffering every decoded
// instruction (used by the whole-binary disassembly dump).
func RangeFunc(d Disassembler, code []byte, addr uint64, fn func(Inst) bool) {
	p := 0
	for p < len(code) {
		inst, err := d.Decode(code[p:], addr+uint64(p))
		if err != nil || len(inst.Bytes) == 0 {
			step := d.Step()
			if p+step > len(code) {
				return
			}
			if !fn(Inst{Addr: addr + uint64(p), Bytes: code[p : p+step], Text: "(bad)"}) {
				return
			}
			p += step
			continue
		}
		if !fn(inst) {
			return
		}
		p += len(inst.Bytes)
	}
}

// Range walks the buffer and decodes instructions until it's exhausted (or
// maxInst is reached, when > 0). On a decode error, it emits a "(bad)"
// placeholder of Step() bytes and continues.
func Range(d Disassembler, code []byte, addr uint64, maxInst int) []Inst {
	out := make([]Inst, 0, 256)
	RangeFunc(d, code, addr, func(in Inst) bool {
		out = append(out, in)
		return maxInst <= 0 || len(out) < maxInst
	})
	return out
}
