// Package testbin hand-builds tiny, byte-for-byte deterministic binaries for
// tests.
//
// It exists because the alternatives aren't reproducible. Compiling a fixture
// (internal/binfile's buildSample) depends on the host toolchain, and opening a
// system binary (/bin/ls) depends on the host OS and libc. Neither can back a
// golden-frame test, whose whole premise is that the same input renders the same
// bytes on every machine.
//
// Nothing outside tests imports this package, so it does not link into exex.
package testbin

import "encoding/binary"

// ELF64 constants, spelled out so the layout below reads as the spec does.
const (
	etExec       = 2  // e_type: executable
	emX86_64     = 62 // e_machine
	ptLoad       = 1  // p_type
	shtProgbits  = 1  // sh_type
	shtSymtab    = 2
	shtStrtab    = 3
	shfWrite     = 0x1 // sh_flags
	shfAlloc     = 0x2
	shfExecinstr = 0x4

	stbGlobal = 1 // symbol binding
	sttFunc   = 2 // symbol type
	sttObject = 1

	ehSize   = 64 // e_ehsize
	phEntSz  = 56 // e_phentsize
	shEntSz  = 64 // e_shentsize
	symEntSz = 24

	baseAddr  = 0x400000
	textOff   = 0x1000
	rodataOff = 0x2000
	dataOff   = 0x3000
	tabsOff   = 0x4000
)

// textCode is a hand-assembled x86-64 `_start` and `helper`, chosen so the
// disassembly view has one of everything it colours differently: immediate
// moves, a call, a syscall, a ret, and a padded function boundary.
//
//	_start:                          ; 0x401000
//	  48 c7 c0 01 00 00 00   mov rax, 1
//	  48 c7 c7 01 00 00 00   mov rdi, 1
//	  e8 0d 00 00 00         call helper
//	  0f 05                  syscall
//	  c3                     ret
//	  90 90 ... (pad to 0x20)
//	helper:                          ; 0x401020
//	  55                     push rbp
//	  48 89 e5               mov rbp, rsp
//	  b8 2a 00 00 00         mov eax, 42
//	  5d                     pop rbp
//	  c3                     ret
var textCode = func() []byte {
	code := []byte{
		0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,
		0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00,
		0xe8, 0x0d, 0x00, 0x00, 0x00, // rel32 = helperStart(32) - nextInsn(19)
		0x0f, 0x05,
		0xc3,
	}
	for len(code) < 32 { // pad _start out to helper's 16-byte-aligned start
		code = append(code, 0x90)
	}
	return append(code,
		0x55,
		0x48, 0x89, 0xe5,
		0xb8, 0x2a, 0x00, 0x00, 0x00,
		0x5d,
		0xc3,
	)
}()

const helperOff = 32 // offset of `helper` within textCode

// rodata holds NUL-terminated strings long enough to survive the Strings view's
// minimum-length filter, including a path so the path-colouring branch runs.
var rodata = []byte("hello world\x00exex golden fixture\x00/tmp/sample.c\x00")

// data holds a little-endian pointer to rodata's first string, so the hex view's
// "follow pointer at cursor" path has something real to resolve.
var data = func() []byte {
	b := make([]byte, 16)
	binary.LittleEndian.PutUint64(b, baseAddr+rodataOff)
	copy(b[8:], []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33})
	return b
}()

type section struct {
	name            string
	typ             uint32
	flags           uint64
	addr, off, size uint64
	link, info      uint32
	align, entsize  uint64
}

type symbol struct {
	name        string
	info        uint8
	shndx       uint16
	value, size uint64
}

// TinyELF64 returns a complete, deterministic ET_EXEC ELF64 image for x86-64.
// The same bytes every call, on every platform.
func TinyELF64() []byte {
	syms := []symbol{
		{}, // index 0 is the reserved null symbol
		{name: "_start", info: stbGlobal<<4 | sttFunc, shndx: 1, value: baseAddr + textOff, size: helperOff},
		{name: "helper", info: stbGlobal<<4 | sttFunc, shndx: 1, value: baseAddr + textOff + helperOff, size: uint64(len(textCode) - helperOff)},
		{name: "msg", info: stbGlobal<<4 | sttObject, shndx: 2, value: baseAddr + rodataOff, size: 12},
	}
	strtab, symNameOff := buildStrtab(syms)
	symtab := buildSymtab(syms, symNameOff)

	symtabOff := uint64(tabsOff)
	strtabOff := symtabOff + uint64(len(symtab))
	shstrOff := strtabOff + uint64(len(strtab))

	names := []string{"", ".text", ".rodata", ".data", ".symtab", ".strtab", ".shstrtab"}
	shstrtab, shNameOff := buildShstrtab(names)

	secs := []section{
		{name: ""},
		{name: ".text", typ: shtProgbits, flags: shfAlloc | shfExecinstr, addr: baseAddr + textOff, off: textOff, size: uint64(len(textCode)), align: 16},
		{name: ".rodata", typ: shtProgbits, flags: shfAlloc, addr: baseAddr + rodataOff, off: rodataOff, size: uint64(len(rodata)), align: 1},
		{name: ".data", typ: shtProgbits, flags: shfAlloc | shfWrite, addr: baseAddr + dataOff, off: dataOff, size: uint64(len(data)), align: 8},
		// sh_link is the string table; sh_info is the index of the first global
		// symbol, which is 1 here because there are no locals after the null entry.
		{name: ".symtab", typ: shtSymtab, off: symtabOff, size: uint64(len(symtab)), link: 5, info: 1, align: 8, entsize: symEntSz},
		{name: ".strtab", typ: shtStrtab, off: strtabOff, size: uint64(len(strtab)), align: 1},
		{name: ".shstrtab", typ: shtStrtab, off: shstrOff, size: uint64(len(shstrtab)), align: 1},
	}

	shoff := align8(shstrOff + uint64(len(shstrtab)))
	total := shoff + uint64(len(secs)*shEntSz)

	buf := make([]byte, total)
	writeELFHeader(buf, shoff, len(secs))
	writeProgHeader(buf, total)
	copy(buf[textOff:], textCode)
	copy(buf[rodataOff:], rodata)
	copy(buf[dataOff:], data)
	copy(buf[symtabOff:], symtab)
	copy(buf[strtabOff:], strtab)
	copy(buf[shstrOff:], shstrtab)
	for i, s := range secs {
		writeSectionHeader(buf[shoff+uint64(i*shEntSz):], s, shNameOff[s.name])
	}
	return buf
}

func writeELFHeader(b []byte, shoff uint64, shnum int) {
	copy(b, []byte{0x7f, 'E', 'L', 'F'})
	b[4] = 2 // ELFCLASS64
	b[5] = 1 // ELFDATA2LSB
	b[6] = 1 // EV_CURRENT
	le := binary.LittleEndian
	le.PutUint16(b[16:], etExec)
	le.PutUint16(b[18:], emX86_64)
	le.PutUint32(b[20:], 1) // e_version
	le.PutUint64(b[24:], baseAddr+textOff)
	le.PutUint64(b[32:], ehSize) // e_phoff
	le.PutUint64(b[40:], shoff)
	le.PutUint32(b[48:], 0) // e_flags
	le.PutUint16(b[52:], ehSize)
	le.PutUint16(b[54:], phEntSz)
	le.PutUint16(b[56:], 1) // e_phnum
	le.PutUint16(b[58:], shEntSz)
	le.PutUint16(b[60:], uint16(shnum))
	le.PutUint16(b[62:], uint16(shnum-1)) // e_shstrndx: .shstrtab is last
}

// writeProgHeader emits one PT_LOAD covering the whole file, which is all the
// loader-shaped metadata exex's ELF reader looks at here.
func writeProgHeader(b []byte, total uint64) {
	p := b[ehSize:]
	le := binary.LittleEndian
	le.PutUint32(p[0:], ptLoad)
	le.PutUint32(p[4:], 5) // PF_R|PF_X
	le.PutUint64(p[8:], 0) // p_offset
	le.PutUint64(p[16:], baseAddr)
	le.PutUint64(p[24:], baseAddr) // p_paddr
	le.PutUint64(p[32:], total)    // p_filesz
	le.PutUint64(p[40:], total)    // p_memsz
	le.PutUint64(p[48:], 0x1000)   // p_align
}

func writeSectionHeader(b []byte, s section, nameOff uint32) {
	le := binary.LittleEndian
	le.PutUint32(b[0:], nameOff)
	le.PutUint32(b[4:], s.typ)
	le.PutUint64(b[8:], s.flags)
	le.PutUint64(b[16:], s.addr)
	le.PutUint64(b[24:], s.off)
	le.PutUint64(b[32:], s.size)
	le.PutUint32(b[40:], s.link)
	le.PutUint32(b[44:], s.info)
	le.PutUint64(b[48:], s.align)
	le.PutUint64(b[56:], s.entsize)
}

func buildSymtab(syms []symbol, nameOff map[string]uint32) []byte {
	b := make([]byte, len(syms)*symEntSz)
	le := binary.LittleEndian
	for i, s := range syms {
		e := b[i*symEntSz:]
		le.PutUint32(e[0:], nameOff[s.name])
		e[4] = s.info
		e[5] = 0 // st_other
		le.PutUint16(e[6:], s.shndx)
		le.PutUint64(e[8:], s.value)
		le.PutUint64(e[16:], s.size)
	}
	return b
}

// buildStrtab lays out the symbol name table, which must begin with a NUL so
// offset 0 names the empty string.
func buildStrtab(syms []symbol) ([]byte, map[string]uint32) {
	off := map[string]uint32{"": 0}
	b := []byte{0}
	for _, s := range syms {
		if s.name == "" {
			continue
		}
		off[s.name] = uint32(len(b))
		b = append(b, s.name...)
		b = append(b, 0)
	}
	return b, off
}

func buildShstrtab(names []string) ([]byte, map[string]uint32) {
	off := map[string]uint32{"": 0}
	b := []byte{0}
	for _, n := range names {
		if n == "" {
			continue
		}
		off[n] = uint32(len(b))
		b = append(b, n...)
		b = append(b, 0)
	}
	return b, off
}

func align8(n uint64) uint64 { return (n + 7) &^ 7 }
