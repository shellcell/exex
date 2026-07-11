// Package dyldcache reads Apple's dyld shared cache: the single large mapped
// image (split across a main file plus ".NN" subcache files) that macOS/iOS ship
// their system dylibs in instead of as standalone files on disk.
//
// The reader is deliberately read-only and header-driven. It parses the cache
// header, the memory mappings, the subcache file list and the image (dylib)
// table, and exposes a virtual-address → bytes translation across every subcache
// file. That is enough to list the dylibs a cache contains and to locate an
// image's Mach-O header for further parsing, without reconstructing ("un-sharing")
// a standalone dylib — the expensive part exex does not need for browsing.
//
// Field offsets follow include/mach-o/dyld_cache_format.h. The header has grown
// over many OS releases, so every field past the original core is read only when
// it lies within mappingOffset (the header's own length): older caches simply do
// not have the newer fields, and reading past mappingOffset would be garbage.
package dyldcache

import (
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// Magic prefixes every dyld shared cache. The full 16-byte magic continues with
// the architecture, e.g. "dyld_v1  arm64e".
const magicPrefix = "dyld_v1"

// Header field offsets within dyld_cache_header (bytes). Only the fields the
// reader uses are named; see dyld_cache_format.h for the full layout.
const (
	offMagic               = 0   // char magic[16]
	offMappingOffset       = 16  // uint32 — also the header's length
	offMappingCount        = 20  // uint32
	offImagesOffsetOld     = 24  // uint32 (pre-images-relocation caches)
	offImagesCountOld      = 28  // uint32
	offSubCacheArrayOffset = 392 // uint32
	offSubCacheArrayCount  = 396 // uint32
	offImagesOffset        = 448 // uint32 (current image-table location)
	offImagesCount         = 452 // uint32
	offCacheSubType        = 456 // uint32 — its presence marks v2 subcache entries

	mappingInfoSize = 32 // dyld_cache_mapping_info
	imageInfoSize   = 32 // dyld_cache_image_info
	subEntryV1Size  = 24 // uuid[16] + cacheVMOffset
	subEntryV2Size  = 56 // v1 + fileSuffix[32]
	suffixLen       = 32
)

// Mapping is one contiguous region of the shared cache: a run of virtual
// addresses backed by a byte range in file File.
type Mapping struct {
	Address    uint64 // virtual address of the region's first byte
	Size       uint64 // region length in bytes
	FileOffset uint64 // byte offset of the region within File
	MaxProt    uint32
	InitProt   uint32
	File       int // index into Cache.files (0 = main cache file)
}

// contains reports whether addr falls within the mapping.
func (m Mapping) contains(addr uint64) bool {
	return addr >= m.Address && addr-m.Address < m.Size
}

// Image is one dylib stored in the cache, named by its install path and located
// by the virtual address of its Mach-O header.
type Image struct {
	Address uint64
	Path    string
}

// subFile is one cache file (the main file or a subcache) held for translation.
type subFile struct {
	name string
	data []byte
}

// Cache is a parsed, read-only view of a dyld shared cache and its subcaches.
type Cache struct {
	Arch     string // architecture from the magic, e.g. "arm64e"
	Mappings []Mapping
	Images   []Image

	files   []subFile // index 0 is the main cache file
	closers []func() error
}

// order is the byte order of every dyld cache exex targets: little-endian.
var order = binary.LittleEndian

// IsCache reports whether raw begins with the dyld shared cache magic.
func IsCache(raw []byte) bool {
	return len(raw) >= 16 && strings.HasPrefix(string(raw[:16]), magicPrefix)
}

// Open maps the shared cache at path and every subcache alongside it, then parses
// the header, mappings and image table. Close releases all mappings.
func Open(path string) (*Cache, error) {
	main, closeMain, err := mapFile(path)
	if err != nil {
		return nil, err
	}
	c := &Cache{
		files:   []subFile{{name: filepath.Base(path), data: main}},
		closers: []func() error{closeMain},
	}
	if err := c.parseMain(path); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// hdrU32 reads a uint32 header field, but only when it lies within the header's
// own declared length (mappingOffset). Fields past that don't exist on the
// (older) cache and read as 0.
func hdrU32(raw []byte, off int) uint32 {
	mappingOffset := order.Uint32(raw[offMappingOffset:])
	if off+4 > int(mappingOffset) || off+4 > len(raw) {
		return 0
	}
	return order.Uint32(raw[off:])
}

func (c *Cache) parseMain(path string) error {
	raw := c.files[0].data
	if !IsCache(raw) {
		return errors.New("not a dyld shared cache")
	}
	if len(raw) < offMappingCount+4 {
		return errors.New("dyld cache: truncated header")
	}
	c.Arch = parseArch(raw[:16])

	mappingOffset := order.Uint32(raw[offMappingOffset:])
	mappingCount := order.Uint32(raw[offMappingCount:])
	if int(mappingOffset) > len(raw) {
		return fmt.Errorf("dyld cache: mappingOffset %d past end", mappingOffset)
	}

	// Open subcaches first so their mappings join the address-translation table.
	if err := c.openSubCaches(path, raw); err != nil {
		return err
	}

	if err := c.readMappings(0, raw, mappingOffset, mappingCount); err != nil {
		return err
	}
	// Re-read every subcache's mappings into the shared table now that files exist.
	for i := 1; i < len(c.files); i++ {
		sub := c.files[i].data
		if len(sub) < offMappingCount+4 || !IsCache(sub) {
			continue
		}
		mo := order.Uint32(sub[offMappingOffset:])
		mc := order.Uint32(sub[offMappingCount:])
		if err := c.readMappings(i, sub, mo, mc); err != nil {
			return err
		}
	}
	sort.Slice(c.Mappings, func(i, j int) bool { return c.Mappings[i].Address < c.Mappings[j].Address })

	return c.readImages(raw)
}

// readMappings appends the mappingCount mappings of file fileIdx to the table.
func (c *Cache) readMappings(fileIdx int, raw []byte, mappingOffset, mappingCount uint32) error {
	end := int(mappingOffset) + int(mappingCount)*mappingInfoSize
	if end > len(raw) {
		return fmt.Errorf("dyld cache: mapping table past end (file %d)", fileIdx)
	}
	for i := uint32(0); i < mappingCount; i++ {
		off := int(mappingOffset) + int(i)*mappingInfoSize
		c.Mappings = append(c.Mappings, Mapping{
			Address:    order.Uint64(raw[off:]),
			Size:       order.Uint64(raw[off+8:]),
			FileOffset: order.Uint64(raw[off+16:]),
			MaxProt:    order.Uint32(raw[off+24:]),
			InitProt:   order.Uint32(raw[off+28:]),
			File:       fileIdx,
		})
	}
	return nil
}

// readImages reads the dylib image table (path + header address). Newer caches
// moved it from imagesOffsetOld to imagesOffset; use whichever the header sets.
func (c *Cache) readImages(raw []byte) error {
	imagesOffset := hdrU32(raw, offImagesOffset)
	imagesCount := hdrU32(raw, offImagesCount)
	if imagesOffset == 0 {
		imagesOffset = order.Uint32(raw[offImagesOffsetOld:])
		imagesCount = order.Uint32(raw[offImagesCountOld:])
	}
	if imagesOffset == 0 || imagesCount == 0 {
		return nil // a cache with no image table is unusual but not fatal
	}
	end := int(imagesOffset) + int(imagesCount)*imageInfoSize
	if end > len(raw) {
		return fmt.Errorf("dyld cache: image table past end")
	}
	c.Images = make([]Image, 0, imagesCount)
	for i := uint32(0); i < imagesCount; i++ {
		off := int(imagesOffset) + int(i)*imageInfoSize
		addr := order.Uint64(raw[off:])
		pathOff := order.Uint32(raw[off+24:])
		c.Images = append(c.Images, Image{Address: addr, Path: cStringAt(raw, int(pathOff))})
	}
	return nil
}

// openSubCaches maps the subcache files named by the header's subcache array. It
// is best-effort: a missing subcache degrades address translation for that file's
// ranges but does not fail the whole cache (browsing the image list still works).
func (c *Cache) openSubCaches(path string, raw []byte) error {
	arrOff := hdrU32(raw, offSubCacheArrayOffset)
	arrCount := hdrU32(raw, offSubCacheArrayCount)
	if arrOff == 0 || arrCount == 0 {
		return nil
	}
	stride := subEntryV1Size
	hasSuffix := int(order.Uint32(raw[offMappingOffset:])) > offCacheSubType
	if hasSuffix {
		stride = subEntryV2Size
	}
	end := int(arrOff) + int(arrCount)*stride
	if end > len(raw) {
		return fmt.Errorf("dyld cache: subcache array past end")
	}
	for i := uint32(0); i < arrCount; i++ {
		off := int(arrOff) + int(i)*stride
		suffix := fmt.Sprintf(".%02d", i+1) // v1 caches imply sequential suffixes
		if hasSuffix {
			suffix = cString(raw[off+subEntryV1Size : off+subEntryV1Size+suffixLen])
		}
		subPath := path + suffix
		data, closer, err := mapFile(subPath)
		if err != nil {
			// Record an empty file so File indices stay aligned with the array.
			c.files = append(c.files, subFile{name: filepath.Base(subPath)})
			continue
		}
		c.files = append(c.files, subFile{name: filepath.Base(subPath), data: data})
		c.closers = append(c.closers, closer)
	}
	return nil
}

// BytesAt returns up to n bytes starting at virtual address addr, resolving which
// subcache file backs it. ok is false when no mapping covers addr.
func (c *Cache) BytesAt(addr uint64, n int) (data []byte, ok bool) {
	m := c.mappingFor(addr)
	if m == nil {
		return nil, false
	}
	avail := m.Size - (addr - m.Address)
	if uint64(n) > avail {
		n = int(avail)
	}
	fileOff := m.FileOffset + (addr - m.Address)
	buf := c.files[m.File].data
	if buf == nil || fileOff+uint64(n) > uint64(len(buf)) {
		return nil, false
	}
	return buf[fileOff : fileOff+uint64(n)], true
}

// mappingFor returns the mapping covering addr via binary search, or nil.
func (c *Cache) mappingFor(addr uint64) *Mapping {
	i := sort.Search(len(c.Mappings), func(i int) bool { return c.Mappings[i].Address > addr })
	if i == 0 {
		return nil
	}
	if m := &c.Mappings[i-1]; m.contains(addr) {
		return m
	}
	return nil
}

// SubCacheNames returns the file names of the main cache and every subcache, in
// File-index order.
func (c *Cache) SubCacheNames() []string {
	out := make([]string, len(c.files))
	for i, f := range c.files {
		out[i] = f.name
	}
	return out
}

// Close releases every mapped cache file.
func (c *Cache) Close() error {
	var err error
	for _, closer := range c.closers {
		if closer != nil {
			if e := closer(); e != nil && err == nil {
				err = e
			}
		}
	}
	c.closers = nil
	c.files = nil
	c.Mappings = nil
	return err
}

// parseArch extracts the architecture token from the 16-byte magic
// ("dyld_v1  arm64e" → "arm64e").
func parseArch(magic []byte) string {
	s := cString(magic)
	return strings.TrimSpace(strings.TrimPrefix(s, "dyld_v1"))
}

// cString reads a NUL-terminated string from a fixed byte slice.
func cString(b []byte) string {
	if i := indexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

// cStringAt reads a NUL-terminated string from raw starting at off (bounded).
func cStringAt(raw []byte, off int) string {
	if off < 0 || off >= len(raw) {
		return ""
	}
	if i := indexByte(raw[off:], 0); i >= 0 {
		return string(raw[off : off+i])
	}
	return string(raw[off:])
}

func indexByte(b []byte, c byte) int {
	for i := 0; i < len(b); i++ {
		if b[i] == c {
			return i
		}
	}
	return -1
}
