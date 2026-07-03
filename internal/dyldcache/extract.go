package dyldcache

// Extracting ("un-sharing") one dylib out of the cache. A cache-resident dylib
// cannot be parsed as a standalone Mach-O directly: its segments are scattered
// across the cache's address space (and across subcache files), and every file
// offset in its load commands refers to the cache layout, not to any single
// file. ExtractImage stitches the segments back into one contiguous buffer and
// rewrites the offsets so ordinary Mach-O parsers (binfile.OpenBytes) accept
// it: each segment is copied via the address-translation table and laid out
// page-aligned in load-command order, segment/section file offsets are rebased
// to the new layout, and every __LINKEDIT-relative table offset (symbols,
// strings, indirect symbols, exports, function starts, …) is shifted by
// __LINKEDIT's move.
//
// The result is a *browsable* dylib — sections, symbols, strings, disassembly
// and syscall scanning all work. It is not a runnable one: pointers in data
// segments keep their in-cache values (the cache builder discarded the rebase
// info that dyld would need to slide them), and stubs stay cache-optimised.
//
// __LINKEDIT is a special case: in the cache it is one giant region shared by
// every image — the symbol table, and especially the string pool, are unified
// across all dylibs, so this image's LC_SYMTAB points into a hundreds-of-MB
// shared blob even though the dylib itself has only a few hundred symbols.
// Copying it verbatim (or even trimming by offset range) would make every
// extracted dylib enormous. Instead the extractor rebuilds a compact,
// self-contained __LINKEDIT holding just this image's nlist symbols, a fresh
// string table containing only the strings those symbols name, its indirect
// symbol table and function-starts; the shared-only tables (bind/rebase/export
// info, split-seg info, code signature) are dropped, since browsing doesn't
// need them.

import (
	"errors"
	"fmt"
	"strings"
)

// Mach-O constants used by the rewrite (from mach-o/loader.h).
const (
	magic64 = 0xfeedfacf

	lcSegment64     = 0x19
	lcSymtab        = 0x2
	lcDysymtab      = 0xb
	lcDyldInfo      = 0x22
	lcReqDyld       = 0x80000000 // LC_REQ_DYLD bit: lcDyldInfo|lcReqDyld = LC_DYLD_INFO_ONLY
	lcCodeSig       = 0x1d
	lcSplitInfo     = 0x1e
	lcFuncStarts    = 0x26
	lcDataInCode    = 0x29
	lcCodeSignDR    = 0x2b
	lcLinkerOpt     = 0x2e
	lcExportsTrie   = 0x80000033
	lcChainedFixups = 0x80000034

	mhDylibInCache = 0x80000000 // header flag set on cache-resident dylibs

	headerSize64  = 32
	segCmdSize64  = 72
	sectionSize64 = 80
)

// extractMaxBytes caps an extracted dylib's stitched size, guarding against a
// corrupt image table pointing at garbage segment sizes.
const extractMaxBytes = 2 << 30

// FindImage returns the cache image whose install path is installPath, falling
// back to a unique basename match (so "libSystem.B.dylib" finds
// "/usr/lib/libSystem.B.dylib").
func (c *Cache) FindImage(installPath string) (Image, bool) {
	for _, im := range c.Images {
		if im.Path == installPath {
			return im, true
		}
	}
	base := "/" + baseName(installPath)
	var hit Image
	n := 0
	for _, im := range c.Images {
		if strings.HasSuffix(im.Path, base) {
			hit = im
			n++
		}
	}
	return hit, n == 1
}

func baseName(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// extractSeg is one LC_SEGMENT_64 of the image being extracted.
type extractSeg struct {
	cmdOff  int // offset of the load command within the load-command area
	name    string
	vmaddr  uint64
	filesz  uint64
	fileoff uint64 // in-cache file offset (the rebase base for its sections)
	newoff  uint64 // file offset in the stitched output
}

// ExtractImage stitches the cache-resident dylib im into a standalone Mach-O
// image parseable by binfile.OpenBytes.
func (c *Cache) ExtractImage(im Image) ([]byte, error) {
	hdr, ok := c.BytesAt(im.Address, headerSize64)
	if !ok || len(hdr) < headerSize64 {
		return nil, errors.New("dyld cache: image header not mapped")
	}
	if order.Uint32(hdr) != magic64 {
		return nil, fmt.Errorf("dyld cache: image at %#x is not a 64-bit Mach-O", im.Address)
	}
	sizeofcmds := int(order.Uint32(hdr[20:]))
	cmds, ok := c.BytesAt(im.Address+headerSize64, sizeofcmds)
	if !ok || len(cmds) < sizeofcmds {
		return nil, errors.New("dyld cache: load commands not mapped")
	}
	ncmds := int(order.Uint32(hdr[16:]))

	// Pass 1: collect the segments and assign their stitched offsets.
	var segs []extractSeg
	var linkedit *extractSeg
	total := uint64(0)
	for off, i := 0, 0; i < ncmds && off+8 <= len(cmds); i++ {
		cmd := order.Uint32(cmds[off:])
		cmdsize := int(order.Uint32(cmds[off+4:]))
		if cmdsize < 8 || off+cmdsize > len(cmds) {
			return nil, errors.New("dyld cache: corrupt load command")
		}
		if cmd == lcSegment64 && cmdsize >= segCmdSize64 {
			segs = append(segs, extractSeg{
				cmdOff:  off,
				name:    cString(cmds[off+8 : off+24]),
				vmaddr:  order.Uint64(cmds[off+24:]),
				filesz:  order.Uint64(cmds[off+48:]),
				fileoff: order.Uint64(cmds[off+40:]),
			})
		}
		off += cmdsize
	}
	if len(segs) == 0 || segs[0].vmaddr != im.Address {
		return nil, errors.New("dyld cache: image's first segment does not start at its header")
	}

	// Build the compact self-contained __LINKEDIT for this image, and drop the
	// original shared one from the layout (its filesz spans the whole cache).
	le, err := c.buildLinkedit(cmds, ncmds)
	if err != nil {
		return nil, err
	}
	for i := range segs {
		if segs[i].name == "__LINKEDIT" {
			linkedit = &segs[i]
			segs[i].filesz = uint64(len(le.data))
		}
	}

	for i := range segs {
		segs[i].newoff = total
		total += (segs[i].filesz + 0xfff) &^ 0xfff // page-align each segment
		if total > extractMaxBytes {
			return nil, fmt.Errorf("dyld cache: image %s unreasonably large (%d MB)", im.Path, total>>20)
		}
	}

	// Pass 2: copy the segment contents via address translation; __LINKEDIT is
	// the freshly built compact buffer.
	out := make([]byte, total)
	for _, s := range segs {
		if s.filesz == 0 {
			continue
		}
		if s.name == "__LINKEDIT" {
			copy(out[s.newoff:], le.data)
			continue
		}
		src, ok := c.BytesAt(s.vmaddr, int(s.filesz))
		if !ok || uint64(len(src)) < s.filesz {
			return nil, fmt.Errorf("dyld cache: segment %s of %s not fully mapped", s.name, im.Path)
		}
		copy(out[s.newoff:], src[:s.filesz])
	}

	// Pass 3: rewrite the copied load commands for the stitched layout. The
	// header and load commands sit at the start of the first segment (offset 0).
	oc := out[headerSize64 : headerSize64+sizeofcmds]
	for _, s := range segs {
		order.PutUint64(oc[s.cmdOff+40:], s.newoff) // fileoff
		if s.name == "__LINKEDIT" {
			// The command still carries the cache's huge vm/file sizes; shrink them
			// to the compact copy so the segment's file range stays inside the buffer.
			order.PutUint64(oc[s.cmdOff+32:], (s.filesz+0xfff)&^0xfff) // vmsize
			order.PutUint64(oc[s.cmdOff+48:], s.filesz)                // filesz
		}
		delta := int64(s.newoff) - int64(s.fileoff)
		nsects := int(order.Uint32(oc[s.cmdOff+64:]))
		for j := range nsects {
			so := s.cmdOff + segCmdSize64 + j*sectionSize64
			if so+sectionSize64 > len(oc) {
				return nil, errors.New("dyld cache: section table past load commands")
			}
			shiftU32(oc[so+48:], delta) // section offset (0 for zero-fill stays 0)
		}
	}
	if linkedit != nil {
		le.rewriteCommands(oc, ncmds, linkedit.newoff)
	}
	// Clear the in-cache flag so downstream tooling treats it as standalone.
	flags := order.Uint32(out[24:])
	order.PutUint32(out[24:], flags&^mhDylibInCache)
	return out, nil
}

// compactLinkedit is a freshly built, self-contained __LINKEDIT for one image:
// its symbol table (with a private string pool), indirect symbol table and
// function-starts, laid out contiguously. Offsets are relative to the segment
// start; rewriteCommands turns them into file offsets once its final position
// is known.
type compactLinkedit struct {
	data []byte

	nsyms          uint32
	symRel         int
	strRel, strLen int
	indRel         int
	nindirect      uint32
	funcRel        int
	funcLen        int
}

// buildLinkedit reads this image's symbol/indirect/function-starts tables out of
// the shared cache linkedit and packs them, with a private string table, into a
// compact standalone linkedit. The shared-only tables (bind/rebase/export info,
// split-seg, code signature) are omitted — browsing needs none of them.
func (c *Cache) buildLinkedit(cmds []byte, ncmds int) (*compactLinkedit, error) {
	u32 := func(b []byte, o int) uint32 {
		if o+4 > len(b) {
			return 0
		}
		return order.Uint32(b[o:])
	}
	// leByteAt reads n bytes at a linkedit *file offset* by translating it to a
	// virtual address through the cache mapping table.
	var leVmaddr, leFileoff, leFilesz uint64
	haveLE := false
	for off, i := 0, 0; i < ncmds && off+8 <= len(cmds); i++ {
		cmd := order.Uint32(cmds[off:])
		cmdsize := int(order.Uint32(cmds[off+4:]))
		if cmd == lcSegment64 && cString(cmds[off+8:off+24]) == "__LINKEDIT" {
			leVmaddr = order.Uint64(cmds[off+24:])
			leFileoff = order.Uint64(cmds[off+40:])
			leFilesz = order.Uint64(cmds[off+48:])
			haveLE = true
		}
		off += cmdsize
	}
	if !haveLE {
		return &compactLinkedit{data: []byte{0}}, nil // no linkedit at all
	}
	leByteAt := func(fileOff uint64, n int) ([]byte, bool) {
		if fileOff < leFileoff || fileOff+uint64(n) > leFileoff+leFilesz {
			return nil, false
		}
		return c.BytesAt(leVmaddr+(fileOff-leFileoff), n)
	}

	// Locate LC_SYMTAB, LC_DYSYMTAB (indirect syms), LC_FUNCTION_STARTS.
	var symOff, nsyms, strOff, strSize uint32
	var indOff, nindirect uint32
	var funcOff, funcSize uint32
	for off, i := 0, 0; i < ncmds && off+8 <= len(cmds); i++ {
		cmd := order.Uint32(cmds[off:])
		cmdsize := int(order.Uint32(cmds[off+4:]))
		switch cmd {
		case lcSymtab:
			symOff, nsyms = u32(cmds, off+8), u32(cmds, off+12)
			strOff, strSize = u32(cmds, off+16), u32(cmds, off+20)
		case lcDysymtab:
			indOff, nindirect = u32(cmds, off+56), u32(cmds, off+60)
		case lcFuncStarts:
			funcOff, funcSize = u32(cmds, off+8), u32(cmds, off+12)
		}
		off += cmdsize
	}

	lc := &compactLinkedit{nsyms: nsyms, nindirect: nindirect}
	var buf []byte
	buf = append(buf, 0) // reserve index 0 as the empty string
	strIndex := map[string]uint32{"": 0}
	intern := func(s string) uint32 {
		if idx, ok := strIndex[s]; ok {
			return idx
		}
		idx := uint32(len(buf))
		strIndex[s] = idx
		buf = append(buf, s...)
		buf = append(buf, 0)
		return idx
	}

	// Symbol table: copy each nlist_64, re-pointing n_strx into the private pool.
	sym := make([]byte, int(nsyms)*16)
	if nsyms > 0 {
		src, ok := leByteAt(uint64(symOff), int(nsyms)*16)
		if !ok {
			return nil, errors.New("dyld cache: symbol table not mapped")
		}
		copy(sym, src)
		for k := range int(nsyms) {
			nStrx := order.Uint32(sym[k*16:])
			name := c.cStringInLinkedit(leVmaddr, leFileoff, leFilesz, uint64(strOff)+uint64(nStrx))
			order.PutUint32(sym[k*16:], intern(name))
		}
	}
	_ = strSize

	// Assemble: [strtab | symtab | indirect | funcstarts], 8-byte aligned tables.
	pad := func() {
		for len(buf)%8 != 0 {
			buf = append(buf, 0)
		}
	}
	lc.strRel, lc.strLen = 0, len(buf)
	pad()
	lc.symRel = len(buf)
	buf = append(buf, sym...)
	if nindirect > 0 {
		if src, ok := leByteAt(uint64(indOff), int(nindirect)*4); ok {
			lc.indRel = len(buf)
			buf = append(buf, src...)
		} else {
			lc.nindirect = 0
		}
	}
	if funcSize > 0 {
		if src, ok := leByteAt(uint64(funcOff), int(funcSize)); ok {
			pad()
			lc.funcRel, lc.funcLen = len(buf), int(funcSize)
			buf = append(buf, src...)
		}
	}
	pad()
	lc.data = buf
	return lc, nil
}

// rewriteCommands points this image's LC_SYMTAB / LC_DYSYMTAB (indirect) /
// LC_FUNCTION_STARTS at the compact linkedit now placed at file offset base,
// and zeroes the load commands whose shared-only tables were dropped so no
// parser chases them into the (absent) cache linkedit.
func (lc *compactLinkedit) rewriteCommands(oc []byte, ncmds int, base uint64) {
	for off, i := 0, 0; i < ncmds && off+8 <= len(oc); i++ {
		cmd := order.Uint32(oc[off:])
		cmdsize := int(order.Uint32(oc[off+4:]))
		if cmdsize < 8 || off+cmdsize > len(oc) {
			return
		}
		switch cmd {
		case lcSymtab:
			order.PutUint32(oc[off+8:], uint32(base)+uint32(lc.symRel))
			order.PutUint32(oc[off+12:], lc.nsyms)
			order.PutUint32(oc[off+16:], uint32(base)+uint32(lc.strRel))
			order.PutUint32(oc[off+20:], uint32(lc.strLen))
		case lcDysymtab:
			// Keep only the indirect symbol table; drop the toc/module/reference
			// and relocation tables (shared, unused for browsing).
			for _, fo := range []int{32, 36, 40, 44, 48, 52, 64, 68, 72, 76} {
				order.PutUint32(oc[off+fo:], 0)
			}
			if lc.nindirect > 0 {
				order.PutUint32(oc[off+56:], uint32(base)+uint32(lc.indRel))
				order.PutUint32(oc[off+60:], lc.nindirect)
			} else {
				order.PutUint32(oc[off+56:], 0)
				order.PutUint32(oc[off+60:], 0)
			}
		case lcFuncStarts:
			if lc.funcLen > 0 {
				order.PutUint32(oc[off+8:], uint32(base)+uint32(lc.funcRel))
				order.PutUint32(oc[off+12:], uint32(lc.funcLen))
			} else {
				order.PutUint32(oc[off+8:], 0)
				order.PutUint32(oc[off+12:], 0)
			}
		case lcDyldInfo, lcDyldInfo | lcReqDyld:
			for _, fo := range []int{8, 12, 16, 20, 24, 28, 32, 36, 40, 44} {
				order.PutUint32(oc[off+fo:], 0)
			}
		case lcCodeSig, lcSplitInfo, lcDataInCode, lcCodeSignDR, lcLinkerOpt,
			lcExportsTrie, lcChainedFixups:
			order.PutUint32(oc[off+8:], 0)
			order.PutUint32(oc[off+12:], 0)
		}
		off += cmdsize
	}
}

// cStringInLinkedit reads a NUL-terminated string at a linkedit file offset,
// translating through the cache mapping in bounded chunks.
func (c *Cache) cStringInLinkedit(leVmaddr, leFileoff, leFilesz, fileOff uint64) string {
	if fileOff < leFileoff || fileOff >= leFileoff+leFilesz {
		return ""
	}
	addr := leVmaddr + (fileOff - leFileoff)
	b, ok := c.BytesAt(addr, 4096)
	if !ok {
		if b, ok = c.BytesAt(addr, 256); !ok {
			return ""
		}
	}
	if i := indexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

// shiftU32 adds delta to the uint32 at b when it is nonzero (zero means "no
// such table" in every command it is used for, and must stay zero).
func shiftU32(b []byte, delta int64) {
	v := order.Uint32(b)
	if v == 0 {
		return
	}
	order.PutUint32(b, uint32(int64(v)+delta))
}

// hostCacheDirs lists where the running system's dyld shared cache lives,
// newest layout first.
var hostCacheDirs = []string{
	"/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld",
	"/System/Library/dyld",
}

// cacheArchNames maps a binary's architecture to the cache-file arch suffixes
// that can serve it, in preference order (arm64 binaries are served by the
// arm64e cache on Apple Silicon; x86_64h serves x86_64 on Haswell+ Macs).
func cacheArchNames(a string) []string {
	switch a {
	case "arm64", "arm64e":
		return []string{"arm64e", "arm64"}
	case "amd64", "x86_64", "x86_64h":
		return []string{"x86_64h", "x86_64"}
	}
	return []string{"arm64e", "arm64", "x86_64h", "x86_64"}
}

// HostCachePath locates the running system's dyld shared cache serving
// architecture a (a binfile/arch name like "arm64" or "amd64"; "" tries all).
func HostCachePath(a string, exists func(string) bool) (string, bool) {
	for _, dir := range hostCacheDirs {
		for _, an := range cacheArchNames(a) {
			p := dir + "/dyld_shared_cache_" + an
			if exists(p) {
				return p, true
			}
		}
	}
	return "", false
}
