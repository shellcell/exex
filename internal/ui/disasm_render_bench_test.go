package ui

import (
	"testing"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/disasm"
)

func BenchmarkDisasmInstRows(b *testing.B) {
	m := benchmarkDisasmModel()
	insts := benchmarkDisasmInsts()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		inst := insts[i%len(insts)]
		_ = m.disasmInstRows(inst, 120, i%17 == 0, nil)
	}
}

func BenchmarkDisasmScroll(b *testing.B) {
	m := benchmarkDisasmModel()
	seed := benchmarkDisasmInsts()
	m.disasmInst = make([]disasm.Inst, 0, 1024)
	for i := 0; i < 1024; i++ {
		inst := seed[i%len(seed)]
		inst.Addr = 0x1000 + uint64(i*4)
		m.disasmInst = append(m.disasmInst, inst)
	}
	m.disasmCur = 128
	m.mode = modeDisasm
	m.width = 120
	m.height = 40
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.disasmTop = i % 128
		_ = m.renderDisasmScroll(120, 32)
	}
}

func benchmarkDisasmModel() *Model {
	return &Model{
		theme: DefaultTheme(),
		file: &binfile.File{
			Sections: []binfile.Section{
				{Name: ".text", Addr: 0x1000, Size: 0x2000, Alloc: true, Exec: true},
				{Name: ".data", Addr: 0x3000, Size: 0x1000, Alloc: true, Write: true},
			},
		},
	}
}

func benchmarkDisasmInsts() []disasm.Inst {
	return []disasm.Inst{
		{Addr: 0x1000, Bytes: []byte{0x55}, Text: "push %rbp", Class: disasm.ClassOther},
		{Addr: 0x1001, Bytes: []byte{0x48, 0x89, 0xe5}, Text: "mov %rsp,%rbp", Class: disasm.ClassOther},
		{Addr: 0x1004, Bytes: []byte{0xe8, 0xf7, 0x00, 0x00, 0x00}, Text: "call 0x1100", Class: disasm.ClassCall},
		{Addr: 0x1009, Bytes: []byte{0x75, 0x45}, Text: "jne 0x1050", Class: disasm.ClassJumpCond},
		{Addr: 0x100b, Bytes: []byte{0x48, 0x8d, 0x05, 0xee, 0x1f, 0x00, 0x00}, Text: "lea 0x3000(%rip),%rax", Class: disasm.ClassOther},
		{Addr: 0x1012, Bytes: []byte{0x48, 0x8b, 0x05, 0xe7, 0x1f, 0x00, 0x00}, Text: "mov 0x3008(%rip),%rax", Class: disasm.ClassOther},
		{Addr: 0x1019, Bytes: []byte{0x90}, Text: "nop", Class: disasm.ClassNop},
		{Addr: 0x101a, Bytes: []byte{0xc3}, Text: "ret", Class: disasm.ClassRet},
	}
}
