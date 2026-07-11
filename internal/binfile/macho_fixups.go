package binfile

// Dynamic relocations of a *linked* Mach-O image. The standard library only
// exposes the per-section relocations of object files (machoRelocs); a finished
// executable or dylib instead carries its fixups as dyld metadata, in one of two
// shapes the loader applies at launch:
//
//   - LC_DYLD_INFO(_ONLY): compact opcode streams (rebase + bind/weak/lazy bind)
//     — the classic format, still emitted by many toolchains (incl. the Go
//     linker), and
//   - LC_DYLD_CHAINED_FIXUPS: a walk of in-place pointer chains, each pointer's
//     spare bits pointing at the next — the modern format used by the system
//     toolchain (e.g. /bin/ls) and the dyld shared cache dylibs.
//
// Neither is decoded by debug/macho, so without this the Relocations view is
// empty for essentially every real macOS binary ("this Mach-O uses dyld chained
// fixups, which aren't decoded yet"). We decode both into the neutral Reloc
// model: binds become named entries pointing at the imported symbol (the useful
// part — the import table of the image), rebases record the slid pointer slots.

import (
	"debug/macho"
	"encoding/binary"
	"sort"
)

// Load commands that carry dynamic fixups (debug/macho leaves them as raw
// LoadBytes).
const (
	lcDyldInfo          = 0x22
	lcDyldInfoOnly      = 0x80000022
	lcDyldChainedFixups = 0x80000034
)

// maxDynamicFixups bounds the neutral list built from a linked image. Rebases in
// particular can number in the hundreds of thousands (every absolute pointer in
// a large Go binary is one); past this we stop, since the view/dump is already
// well beyond useful and each entry costs memory.
const maxDynamicFixups = 200000

// machoHasDynamicFixups reports, cheaply, whether the image carries dyld
// bind/rebase or chained-fixup load commands — used so HasRelocs/relocAvail is
// true for a linked Mach-O without forcing the (potentially large) decode.
func machoHasDynamicFixups(mf *macho.File) bool {
	for _, l := range mf.Loads {
		lb, ok := l.(macho.LoadBytes)
		if !ok {
			continue
		}
		raw := lb.Raw()
		if len(raw) < 8 {
			continue
		}
		switch mf.ByteOrder.Uint32(raw) {
		case lcDyldInfo, lcDyldInfoOnly, lcDyldChainedFixups:
			return true
		}
	}
	return false
}

// machoDynamicFixups decodes the image's dyld fixups into neutral Reloc entries.
// raw is the whole file image; base is the chosen slice's file offset (fixup
// tables reference file offsets relative to that slice). Addresses in the result
// are virtual addresses, matching the disasm/symbol/hex views.
func machoDynamicFixups(mf *macho.File, raw []byte, base uint64) []Reloc {
	segs := machoSegmentsInOrder(mf)
	dylibs := machoDylibOrdinals(mf)
	secAt := machoSectionLocator(mf)
	is64 := mf.Magic == macho.Magic64
	bo := mf.ByteOrder

	var out []Reloc
	for _, l := range mf.Loads {
		if len(out) >= maxDynamicFixups {
			break
		}
		lb, ok := l.(macho.LoadBytes)
		if !ok {
			continue
		}
		cmd := lb.Raw()
		if len(cmd) < 8 {
			continue
		}
		switch bo.Uint32(cmd) {
		case lcDyldInfo, lcDyldInfoOnly:
			out = machoDyldInfoFixups(out, cmd, raw, base, bo, is64, segs, dylibs, secAt)
		case lcDyldChainedFixups:
			out = machoChainedFixups(out, cmd, raw, base, bo, segs, dylibs, secAt)
		}
	}
	return out
}

// machoSegmentsInOrder returns the image's segments in load-command order, which
// is the order both the dyld bind opcodes (SET_SEGMENT_AND_OFFSET) and the
// chained-fixups per-segment table index by.
func machoSegmentsInOrder(mf *macho.File) []*macho.Segment {
	var segs []*macho.Segment
	for _, l := range mf.Loads {
		if seg, ok := l.(*macho.Segment); ok {
			segs = append(segs, seg)
		}
	}
	return segs
}

// machoDylibOrdinals returns dylib names indexed for ordinal lookup: entry i is
// the (i+1)-th dylib load command (LC_LOAD_DYLIB and its weak/reexport/upward
// variants), matching the 1-based ordinal stored in bind entries. Unlike
// machoAllDylibs this keeps every command in order without de-duplicating, so the
// ordinal→name mapping stays exact.
func machoDylibOrdinals(mf *macho.File) []string {
	var libs []string
	for _, l := range mf.Loads {
		switch v := l.(type) {
		case *macho.Dylib:
			libs = append(libs, v.Name)
		case macho.LoadBytes:
			raw := v.Raw()
			if len(raw) < 16 {
				continue
			}
			switch mf.ByteOrder.Uint32(raw) {
			case lcLoadWeakDylib, lcReexportDylib, lcLoadUpwardDylib:
				nameOff := mf.ByteOrder.Uint32(raw[8:])
				if int(nameOff) < len(raw) {
					libs = append(libs, cStr(raw[nameOff:]))
				}
			}
		}
	}
	return libs
}

// dylibName maps a 1-based bind ordinal to its library name. Non-positive
// "special" ordinals (self / main-executable / flat-lookup) name no concrete
// library and yield "".
func dylibName(ordinal int, dylibs []string) string {
	if ordinal >= 1 && ordinal <= len(dylibs) {
		return dylibs[ordinal-1]
	}
	return ""
}

// machoSectionLocator returns a function mapping a virtual address to the
// "SEG,sect" label of the section containing it (matching machoRelocs' Section
// field), or "" when no section covers it. Backed by an address-sorted index so
// the per-fixup lookup stays cheap across a large chain.
func machoSectionLocator(mf *macho.File) func(uint64) string {
	type secSpan struct {
		lo, hi uint64
		label  string
	}
	spans := make([]secSpan, 0, len(mf.Sections))
	for _, s := range mf.Sections {
		if s.Size == 0 {
			continue
		}
		spans = append(spans, secSpan{lo: s.Addr, hi: s.Addr + s.Size, label: s.Seg + "," + s.Name})
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].lo < spans[j].lo })
	return func(addr uint64) string {
		i := sort.Search(len(spans), func(i int) bool { return spans[i].hi > addr })
		if i < len(spans) && addr >= spans[i].lo {
			return spans[i].label
		}
		return ""
	}
}

// slab returns raw[off : off+size] with bounds checking, or nil.
func slab(raw []byte, off, size uint64) []byte {
	if off > uint64(len(raw)) || off+size > uint64(len(raw)) || off+size < off {
		return nil
	}
	return raw[off : off+size]
}

// --- LC_DYLD_INFO opcode streams --------------------------------------------

// dyld bind opcodes (mach-o/loader.h). opcode = byte & 0xf0, immediate = & 0x0f.
const (
	bindDone            = 0x00
	bindSetDylibOrdImm  = 0x10
	bindSetDylibOrdUleb = 0x20
	bindSetDylibSpecial = 0x30
	bindSetSymbol       = 0x40
	bindSetType         = 0x50
	bindSetAddend       = 0x60
	bindSetSegOff       = 0x70
	bindAddAddrUleb     = 0x80
	bindDoBind          = 0x90
	bindDoBindAddUleb   = 0xa0
	bindDoBindImmScaled = 0xb0
	bindDoBindUlebSkip  = 0xc0
	bindThreaded        = 0xd0
)

// dyld rebase opcodes.
const (
	rebaseDone         = 0x00
	rebaseSetType      = 0x10
	rebaseSetSegOff    = 0x20
	rebaseAddAddrUleb  = 0x30
	rebaseAddAddrImm   = 0x40
	rebaseImmTimes     = 0x50
	rebaseUlebTimes    = 0x60
	rebaseAddAddrUleb1 = 0x70
	rebaseUlebSkip     = 0x80
)

// machoDyldInfoFixups decodes an LC_DYLD_INFO(_ONLY) command's rebase and bind
// (regular / weak / lazy) opcode streams, appending to out.
func machoDyldInfoFixups(out []Reloc, cmd, raw []byte, base uint64, bo binary.ByteOrder, is64 bool, segs []*macho.Segment, dylibs []string, secAt func(uint64) string) []Reloc {
	if len(cmd) < 48 {
		return out
	}
	ptr := uint64(4)
	if is64 {
		ptr = 8
	}
	table := func(offField, sizeField int) []byte {
		off := uint64(bo.Uint32(cmd[offField:]))
		size := uint64(bo.Uint32(cmd[sizeField:]))
		return slab(raw, base+off, size)
	}
	out = machoRebaseOps(out, table(8, 12), ptr, segs, secAt)
	out = machoBindOps(out, table(16, 20), "BIND", ptr, segs, dylibs, secAt)
	out = machoBindOps(out, table(24, 28), "WEAK_BIND", ptr, segs, dylibs, secAt)
	out = machoBindOps(out, table(32, 36), "LAZY_BIND", ptr, segs, dylibs, secAt)
	return out
}

// segAddr resolves a (segment index, in-segment offset) pair to a virtual
// address, guarding against a malformed segment index.
func segAddr(segs []*macho.Segment, idx int, off uint64) (uint64, bool) {
	if idx < 0 || idx >= len(segs) {
		return 0, false
	}
	return segs[idx].Addr + off, true
}

// machoBindOps interprets one dyld bind opcode stream. Each DO_BIND* emits a
// Reloc for the current symbol at the current address, then advances.
func machoBindOps(out []Reloc, data []byte, typ string, ptr uint64, segs []*macho.Segment, dylibs []string, secAt func(uint64) string) []Reloc {
	var (
		segIdx  = -1
		segOff  uint64
		sym     string
		lib     string
		ordinal int
	)
	emit := func() {
		if len(out) >= maxDynamicFixups {
			return
		}
		if addr, ok := segAddr(segs, segIdx, segOff); ok {
			out = append(out, Reloc{Offset: addr, Type: typ, Sym: sym, Lib: lib, Section: secAt(addr)})
		}
	}
	p := 0
	for p < len(data) && len(out) < maxDynamicFixups {
		op := data[p] & 0xf0
		imm := int(data[p] & 0x0f)
		p++
		switch op {
		case bindDone:
			// A zero byte terminates the lazy stream between per-symbol runs; keep
			// going so every lazy bind is seen, and stop only at end of data.
			if typ != "LAZY_BIND" {
				return out
			}
		case bindSetDylibOrdImm:
			ordinal = imm
			lib = dylibName(ordinal, dylibs)
		case bindSetDylibOrdUleb:
			var v uint64
			v, p = uleb(data, p)
			ordinal = int(v)
			lib = dylibName(ordinal, dylibs)
		case bindSetDylibSpecial:
			// Sign-extended small negative ordinal (self / main / flat lookup) — no
			// concrete library.
			if imm == 0 {
				ordinal = 0
			} else {
				ordinal = imm | ^0x0f
			}
			lib = ""
		case bindSetSymbol:
			sym, p = cstrAt(data, p)
		case bindSetType:
			// pointer / text-abs32 / text-pcrel32 — not needed for naming.
		case bindSetAddend:
			_, p = sleb(data, p)
		case bindSetSegOff:
			segIdx = imm
			segOff, p = uleb(data, p)
		case bindAddAddrUleb:
			var v uint64
			v, p = uleb(data, p)
			segOff += v
		case bindDoBind:
			emit()
			segOff += ptr
		case bindDoBindAddUleb:
			emit()
			var v uint64
			v, p = uleb(data, p)
			segOff += ptr + v
		case bindDoBindImmScaled:
			emit()
			segOff += ptr + uint64(imm)*ptr
		case bindDoBindUlebSkip:
			var count, skip uint64
			count, p = uleb(data, p)
			skip, p = uleb(data, p)
			for i := uint64(0); i < count && len(out) < maxDynamicFixups; i++ {
				emit()
				segOff += ptr + skip
			}
		case bindThreaded:
			// LC_DYLD_INFO threaded-rebase/bind (a pre-chained variant) needs its own
			// state machine; stop rather than misdecode the rest of the stream.
			return out
		default:
			return out
		}
	}
	return out
}

// machoRebaseOps interprets one dyld rebase opcode stream, emitting a REBASE
// entry per slid pointer slot.
func machoRebaseOps(out []Reloc, data []byte, ptr uint64, segs []*macho.Segment, secAt func(uint64) string) []Reloc {
	var (
		segIdx = -1
		segOff uint64
	)
	emit := func() {
		if len(out) >= maxDynamicFixups {
			return
		}
		if addr, ok := segAddr(segs, segIdx, segOff); ok {
			out = append(out, Reloc{Offset: addr, Type: "REBASE", Section: secAt(addr)})
		}
	}
	p := 0
	for p < len(data) && len(out) < maxDynamicFixups {
		op := data[p] & 0xf0
		imm := int(data[p] & 0x0f)
		p++
		switch op {
		case rebaseDone:
			return out
		case rebaseSetType:
			// pointer / text-abs32 / text-pcrel32 — not needed.
		case rebaseSetSegOff:
			segIdx = imm
			segOff, p = uleb(data, p)
		case rebaseAddAddrUleb:
			var v uint64
			v, p = uleb(data, p)
			segOff += v
		case rebaseAddAddrImm:
			segOff += uint64(imm) * ptr
		case rebaseImmTimes:
			for i := 0; i < imm && len(out) < maxDynamicFixups; i++ {
				emit()
				segOff += ptr
			}
		case rebaseUlebTimes:
			var count uint64
			count, p = uleb(data, p)
			for i := uint64(0); i < count && len(out) < maxDynamicFixups; i++ {
				emit()
				segOff += ptr
			}
		case rebaseAddAddrUleb1:
			emit()
			var v uint64
			v, p = uleb(data, p)
			segOff += ptr + v
		case rebaseUlebSkip:
			var count, skip uint64
			count, p = uleb(data, p)
			skip, p = uleb(data, p)
			for i := uint64(0); i < count && len(out) < maxDynamicFixups; i++ {
				emit()
				segOff += ptr + skip
			}
		default:
			return out
		}
	}
	return out
}

// --- LC_DYLD_CHAINED_FIXUPS --------------------------------------------------

// chained pointer formats (mach-o/fixup-chains.h) we decode. 32-bit and cache
// formats are intentionally omitted (not produced for macOS x86_64/arm64 apps).
const (
	chainPtrArm64e           = 1
	chainPtr64               = 2
	chainPtr64Offset         = 6
	chainPtrArm64eKernel     = 7
	chainPtrArm64eUserland   = 9
	chainPtrArm64eFirmware   = 10
	chainPtrArm64eUserland24 = 12

	chainStartNone  = 0xffff // DYLD_CHAINED_PTR_START_NONE
	chainStartMulti = 0x8000 // DYLD_CHAINED_PTR_START_MULTI
	chainStartLast  = 0x8000 // DYLD_CHAINED_PTR_START_LAST (in the overflow list)
)

// chainedImport is one resolved entry of the chained-fixups imports table.
type chainedImport struct {
	name string
	lib  string
}

// machoChainedFixups decodes an LC_DYLD_CHAINED_FIXUPS command: it reads the
// imports table (ordinal → symbol/library) and walks every segment's pointer
// chains, emitting a bind (named) or rebase entry per link.
func machoChainedFixups(out []Reloc, cmd, raw []byte, base uint64, bo binary.ByteOrder, segs []*macho.Segment, dylibs []string, secAt func(uint64) string) []Reloc {
	if len(cmd) < 16 {
		return out
	}
	dataOff := uint64(bo.Uint32(cmd[8:]))
	dataSize := uint64(bo.Uint32(cmd[12:]))
	hdr := slab(raw, base+dataOff, dataSize)
	if len(hdr) < 28 {
		return out
	}
	startsOff := bo.Uint32(hdr[4:])
	importsOff := bo.Uint32(hdr[8:])
	symbolsOff := bo.Uint32(hdr[12:])
	importsCount := bo.Uint32(hdr[16:])
	importsFormat := bo.Uint32(hdr[20:])

	imports := machoChainedImports(hdr, importsOff, symbolsOff, importsCount, importsFormat, bo, dylibs)

	if int(startsOff)+4 > len(hdr) {
		return out
	}
	segCount := bo.Uint32(hdr[startsOff:])
	for i := uint32(0); i < segCount && len(out) < maxDynamicFixups; i++ {
		e := uint64(startsOff) + 4 + uint64(i)*4
		if e+4 > uint64(len(hdr)) {
			break
		}
		segInfo := bo.Uint32(hdr[e:])
		if segInfo == 0 || int(i) >= len(segs) {
			continue // no chains in this segment (or a segment we can't map)
		}
		out = machoChainSegment(out, hdr, uint64(startsOff)+uint64(segInfo), raw, base, bo, segs[i], imports, secAt)
	}
	return out
}

// machoChainedImports resolves the imports array into names + libraries. The
// three formats differ only in field widths and whether an addend trails.
func machoChainedImports(hdr []byte, importsOff, symbolsOff, count, format uint32, bo binary.ByteOrder, dylibs []string) []chainedImport {
	pool := hdr
	if int(symbolsOff) <= len(hdr) {
		pool = hdr[symbolsOff:]
	}
	name := func(off uint32) string {
		s, _ := cstrAt(pool, int(off))
		return s
	}
	var stride uint32
	switch format {
	case 2: // DYLD_CHAINED_IMPORT_ADDEND
		stride = 8
	case 3: // DYLD_CHAINED_IMPORT_ADDEND64
		stride = 16
	default: // DYLD_CHAINED_IMPORT
		stride = 4
	}
	out := make([]chainedImport, 0, count)
	for i := uint32(0); i < count; i++ {
		off := uint64(importsOff) + uint64(i)*uint64(stride)
		if off+uint64(stride) > uint64(len(hdr)) {
			break
		}
		var ordinal int
		var nameOff uint32
		if format == 3 {
			v := bo.Uint64(hdr[off:])
			ordinal = int(v & 0xffff)
			nameOff = uint32(v >> 32)
		} else {
			v := bo.Uint32(hdr[off:])
			ordinal = int(v & 0xff)
			nameOff = v >> 9
		}
		out = append(out, chainedImport{name: name(nameOff), lib: dylibName(ordinal, dylibs)})
	}
	return out
}

// machoChainSegment walks the pointer chains of one segment. startOff is the
// offset within hdr of this segment's dyld_chained_starts_in_segment.
func machoChainSegment(out []Reloc, hdr []byte, startOff uint64, raw []byte, base uint64, bo binary.ByteOrder, seg *macho.Segment, imports []chainedImport, secAt func(uint64) string) []Reloc {
	if startOff+22 > uint64(len(hdr)) {
		return out
	}
	s := hdr[startOff:]
	pageSize := uint64(bo.Uint16(s[4:]))
	pointerFormat := bo.Uint16(s[6:])
	segmentOffset := bo.Uint64(s[8:])
	pageCount := int(bo.Uint16(s[20:]))
	if pageSize == 0 {
		return out
	}
	// segmentOffset is the segment's offset from the mach header (its file offset
	// for a normal image); vmBase converts an in-segment file delta to a vaddr.
	vmBase := seg.Addr - segmentOffset

	for pi := 0; pi < pageCount && len(out) < maxDynamicFixups; pi++ {
		po := 22 + pi*2
		if po+2 > len(s) {
			break
		}
		start := bo.Uint16(s[po:])
		if start == chainStartNone {
			continue
		}
		for _, chainOff := range machoChainStartsOnPage(s, pageCount, start, bo) {
			pageBase := segmentOffset + uint64(pi)*pageSize
			out = machoWalkChain(out, raw, base, bo, pageBase+uint64(chainOff), vmBase, pointerFormat, imports, secAt)
		}
	}
	return out
}

// machoChainStartsOnPage returns the in-page byte offsets at which chains begin
// on a page. The common case is a single start; a START_MULTI page indexes an
// overflow list of offsets (terminated by START_LAST) appended after page_start.
func machoChainStartsOnPage(s []byte, pageCount int, start uint16, bo binary.ByteOrder) []uint16 {
	if start&chainStartMulti == 0 {
		return []uint16{start}
	}
	var starts []uint16
	idx := pageCount + int(start&^chainStartMulti)
	for {
		po := 22 + idx*2
		if po+2 > len(s) || len(starts) > 0x10000 {
			break
		}
		v := bo.Uint16(s[po:])
		starts = append(starts, v&^chainStartLast)
		if v&chainStartLast != 0 {
			break
		}
		idx++
	}
	return starts
}

// machoWalkChain follows one pointer chain from fileOff (relative to base),
// emitting a bind or rebase per link until a next-delta of 0 ends it. vmBase maps
// the link's file offset back to its virtual address.
func machoWalkChain(out []Reloc, raw []byte, base uint64, bo binary.ByteOrder, fileOff, vmBase uint64, format uint16, imports []chainedImport, secAt func(uint64) string) []Reloc {
	off := fileOff
	for guard := 0; guard < maxDynamicFixups && len(out) < maxDynamicFixups; guard++ {
		abs := base + off
		if abs+8 > uint64(len(raw)) {
			break
		}
		v := bo.Uint64(raw[abs:])
		isBind, auth, ordinal, next, stride, ok := decodeChainedPtr(v, format)
		if !ok {
			break
		}
		addr := vmBase + off
		if isBind {
			typ := "BIND"
			var sym, lib string
			if ordinal >= 0 && ordinal < len(imports) {
				sym = imports[ordinal].name
				lib = imports[ordinal].lib
			}
			if auth {
				typ = "AUTH_BIND"
			}
			out = append(out, Reloc{Offset: addr, Type: typ, Sym: sym, Lib: lib, Section: secAt(addr)})
		} else {
			typ := "REBASE"
			if auth {
				typ = "AUTH_REBASE"
			}
			out = append(out, Reloc{Offset: addr, Type: typ, Section: secAt(addr)})
		}
		if next == 0 {
			break
		}
		off += uint64(next) * stride
	}
	return out
}

// decodeChainedPtr splits a raw chained pointer per its format into the fields
// this decoder needs: whether it's a bind (vs rebase), whether it's authenticated
// (arm64e), the import ordinal (binds), the next-link delta and its stride. ok is
// false for formats we don't decode (32-bit / cache), stopping the chain.
func decodeChainedPtr(v uint64, format uint16) (isBind, auth bool, ordinal int, next uint32, stride uint64, ok bool) {
	switch format {
	case chainPtr64, chainPtr64Offset:
		// next:12 at bits 51..62, bind:1 at bit 63; bind ordinal is 24 bits.
		isBind = v>>63&1 != 0
		next = uint32(v >> 51 & 0xfff)
		if isBind {
			ordinal = int(v & 0xffffff)
		}
		return isBind, false, ordinal, next, 4, true
	case chainPtrArm64e, chainPtrArm64eUserland, chainPtrArm64eUserland24,
		chainPtrArm64eKernel, chainPtrArm64eFirmware:
		// next:11 at bits 51..61, bind:1 at bit 62, auth:1 at bit 63.
		auth = v>>63&1 != 0
		isBind = v>>62&1 != 0
		next = uint32(v >> 51 & 0x7ff)
		if isBind {
			if format == chainPtrArm64eUserland24 {
				ordinal = int(v & 0xffffff)
			} else {
				ordinal = int(v & 0xffff)
			}
		}
		stride = 8
		if format == chainPtrArm64eKernel || format == chainPtrArm64eFirmware {
			stride = 4
		}
		return isBind, auth, ordinal, next, stride, true
	}
	return false, false, 0, 0, 0, false
}

// --- LEB128 + string helpers -------------------------------------------------

// uleb reads an unsigned LEB128 at data[p], returning the value and the next
// position. A truncated encoding stops at end of data.
func uleb(data []byte, p int) (uint64, int) {
	var result uint64
	var shift uint
	for p < len(data) {
		b := data[p]
		p++
		if shift < 64 {
			result |= uint64(b&0x7f) << shift
		}
		if b&0x80 == 0 {
			break
		}
		shift += 7
	}
	return result, p
}

// sleb reads a signed LEB128 at data[p].
func sleb(data []byte, p int) (int64, int) {
	var result int64
	var shift uint
	var b byte
	for p < len(data) {
		b = data[p]
		p++
		result |= int64(b&0x7f) << shift
		shift += 7
		if b&0x80 == 0 {
			break
		}
	}
	if shift < 64 && b&0x40 != 0 {
		result |= -1 << shift
	}
	return result, p
}

// cstrAt reads a NUL-terminated string at data[p], returning it and the position
// just past the terminator.
func cstrAt(data []byte, p int) (string, int) {
	if p < 0 || p >= len(data) {
		return "", p
	}
	for i := p; i < len(data); i++ {
		if data[i] == 0 {
			return string(data[p:i]), i + 1
		}
	}
	return string(data[p:]), len(data)
}
