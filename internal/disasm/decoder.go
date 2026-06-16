// Package disasm wraps golang.org/x/arch to provide a uniform decoder across
// x86, x86-64, ARM64 and RISC-V 64.
package disasm

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/rabarbra/exex/internal/arch"

	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/riscv64/riscv64asm"
	"golang.org/x/arch/x86/x86asm"
)

type Arch = arch.Arch

const (
	ArchUnknown = arch.ArchUnknown
	ArchX86     = arch.ArchX86
	ArchAMD64   = arch.ArchAMD64
	ArchARM64   = arch.ArchARM64
	ArchRISCV64 = arch.ArchRISCV64
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
)

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
	op = strings.ToLower(op)

	switch op {
	case "call", "callq", "calll", "callw":
		return ClassCall
	case "bl", "blr", "blraa", "blrab", "blraaz", "blrabz", "blx":
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
		"b", "br", "j":
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
	return ClassOther
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
	}
	return nil, fmt.Errorf("unsupported architecture")
}

type amd64 struct{}

func (amd64) Name() string { return "x86-64" }
func (amd64) Step() int    { return 1 }
func (amd64) Decode(code []byte, addr uint64) (Inst, error) {
	inst, err := decodeX86(code, 64)
	if err != nil {
		return Inst{}, err
	}
	text := x86asm.GNUSyntax(inst, addr, nil)
	return Inst{Addr: addr, Bytes: code[:inst.Len], Text: text, Class: Classify(text)}, nil
}

type x86 struct{}

func (x86) Name() string { return "x86" }
func (x86) Step() int    { return 1 }
func (x86) Decode(code []byte, addr uint64) (Inst, error) {
	inst, err := decodeX86(code, 32)
	if err != nil {
		return Inst{}, err
	}
	text := x86asm.GNUSyntax(inst, addr, nil)
	return Inst{Addr: addr, Bytes: code[:inst.Len], Text: text, Class: Classify(text)}, nil
}

func decodeX86(code []byte, mode int) (inst x86asm.Inst, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("x86 decode panic: %v", r)
		}
	}()
	return x86asm.Decode(code, mode)
}

type arm64d struct{}

func (arm64d) Name() string { return "arm64" }
func (arm64d) Step() int    { return 4 }
func (arm64d) Decode(code []byte, addr uint64) (Inst, error) {
	if len(code) < 4 {
		return Inst{}, fmt.Errorf("short read")
	}
	inst, err := arm64asm.Decode(code)
	if err != nil {
		return Inst{}, err
	}
	text := resolveRelTargets(arm64asm.GNUSyntax(inst), addr)
	return Inst{Addr: addr, Bytes: code[:4], Text: text, Class: Classify(text)}, nil
}

type riscv64d struct{}

func (riscv64d) Name() string { return "riscv64" }
func (riscv64d) Step() int    { return 2 }
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
	text := resolveRelTargets(riscv64asm.GNUSyntax(inst), addr)
	return Inst{Addr: addr, Bytes: code[:n], Text: text, Class: Classify(text)}, nil
}

// resolveRelTargets rewrites PC-relative branch operands that the ARM64/RISC-V
// syntaxers print as ".+0x…" / ".-0x…" into the absolute target address, so the
// UI's address-following and symbol annotation work on them. The offset is the
// signed displacement (e.g. ".+0xfffffffffffffc58" is a negative jump); uint64
// wraparound makes "addr + value" land on the right byte either way.
func resolveRelTargets(text string, addr uint64) string {
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
					fmt.Fprintf(&b, "0x%x", target)
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

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// Range walks the buffer and decodes instructions until it's exhausted. On a
// decode error, it emits a "(bad)" placeholder of Step() bytes and continues.
func Range(d Disassembler, code []byte, addr uint64, maxInst int) []Inst {
	out := make([]Inst, 0, 256)
	p := 0
	for p < len(code) && (maxInst <= 0 || len(out) < maxInst) {
		inst, err := d.Decode(code[p:], addr+uint64(p))
		if err != nil || len(inst.Bytes) == 0 {
			step := d.Step()
			if p+step > len(code) {
				break
			}
			out = append(out, Inst{
				Addr:  addr + uint64(p),
				Bytes: code[p : p+step],
				Text:  "(bad)",
			})
			p += step
			continue
		}
		out = append(out, inst)
		p += len(inst.Bytes)
	}
	return out
}
