// Package disasm wraps golang.org/x/arch to provide a uniform decoder across
// x86, x86-64, ARM64 and RISC-V 64.
package disasm

import (
	"debug/elf"
	"fmt"

	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/riscv64/riscv64asm"
	"golang.org/x/arch/x86/x86asm"
)

// Inst is one decoded instruction.
type Inst struct {
	Addr  uint64
	Bytes []byte
	Text  string
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

func For(m elf.Machine) (Disassembler, error) {
	switch m {
	case elf.EM_X86_64:
		return amd64{}, nil
	case elf.EM_386:
		return x86{}, nil
	case elf.EM_AARCH64:
		return arm64d{}, nil
	case elf.EM_RISCV:
		return riscv64d{}, nil
	}
	return nil, fmt.Errorf("unsupported machine: %s", m)
}

type amd64 struct{}

func (amd64) Name() string { return "x86-64" }
func (amd64) Step() int    { return 1 }
func (amd64) Decode(code []byte, addr uint64) (Inst, error) {
	inst, err := x86asm.Decode(code, 64)
	if err != nil {
		return Inst{}, err
	}
	return Inst{Addr: addr, Bytes: code[:inst.Len], Text: x86asm.GNUSyntax(inst, addr, nil)}, nil
}

type x86 struct{}

func (x86) Name() string { return "x86" }
func (x86) Step() int    { return 1 }
func (x86) Decode(code []byte, addr uint64) (Inst, error) {
	inst, err := x86asm.Decode(code, 32)
	if err != nil {
		return Inst{}, err
	}
	return Inst{Addr: addr, Bytes: code[:inst.Len], Text: x86asm.GNUSyntax(inst, addr, nil)}, nil
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
	return Inst{Addr: addr, Bytes: code[:4], Text: arm64asm.GNUSyntax(inst)}, nil
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
	return Inst{Addr: addr, Bytes: code[:n], Text: riscv64asm.GNUSyntax(inst)}, nil
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
