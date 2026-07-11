package dyldcache

import (
	"os"
	"testing"
)

// openRealCache opens the host's dyld shared cache, skipping when absent.
func openRealCache(t *testing.T) *Cache {
	t.Helper()
	var path string
	for _, p := range realCachePaths {
		if _, err := os.Stat(p); err == nil {
			path = p
			break
		}
	}
	if path == "" {
		t.Skip("no system dyld shared cache on this host")
	}
	c, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// TestExtractRealDylib un-shares a real system dylib and checks the stitched
// image is a self-consistent standalone Mach-O: header magic, every segment's
// rewritten file range inside the buffer, and the symbol/string tables inside
// the relocated __LINKEDIT.
func TestExtractRealDylib(t *testing.T) {
	c := openRealCache(t)

	im, ok := c.FindImage("/usr/lib/libSystem.B.dylib")
	if !ok {
		t.Fatal("libSystem.B.dylib not in cache image table")
	}
	out, err := c.ExtractImage(im)
	if err != nil {
		t.Fatal(err)
	}
	if order.Uint32(out) != magic64 {
		t.Fatalf("stitched image magic = %#x", order.Uint32(out))
	}
	if order.Uint32(out[24:])&mhDylibInCache != 0 {
		t.Fatal("MH_DYLIB_IN_CACHE flag not cleared")
	}

	// Walk the rewritten load commands: segments and linkedit tables must lie
	// within the stitched buffer.
	ncmds := int(order.Uint32(out[16:]))
	sizeofcmds := int(order.Uint32(out[20:]))
	oc := out[headerSize64 : headerSize64+sizeofcmds]
	var symoff, stroff, strsize uint32
	segs := 0
	for off, i := 0, 0; i < ncmds; i++ {
		cmd := order.Uint32(oc[off:])
		cmdsize := int(order.Uint32(oc[off+4:]))
		switch cmd {
		case lcSegment64:
			segs++
			fileoff := order.Uint64(oc[off+40:])
			filesz := order.Uint64(oc[off+48:])
			if fileoff+filesz > uint64(len(out)) {
				t.Fatalf("segment %s [%#x,+%#x) outside stitched buffer (%#x)",
					cString(oc[off+8:off+24]), fileoff, filesz, len(out))
			}
		case lcSymtab:
			symoff = order.Uint32(oc[off+8:])
			stroff = order.Uint32(oc[off+16:])
			strsize = order.Uint32(oc[off+20:])
		}
		off += cmdsize
	}
	if segs < 2 {
		t.Fatalf("only %d segments", segs)
	}
	if symoff == 0 || int(symoff) > len(out) {
		t.Fatalf("rewritten symoff %#x outside buffer (%#x)", symoff, len(out))
	}
	if int(stroff)+int(strsize) > len(out) {
		t.Fatalf("rewritten string table [%#x,+%#x) outside buffer (%#x)", stroff, strsize, len(out))
	}
}

// TestFindImageByBasename checks the unique-basename fallback.
func TestFindImageByBasename(t *testing.T) {
	c := openRealCache(t)
	im, ok := c.FindImage("libSystem.B.dylib")
	if !ok {
		t.Fatal("basename lookup failed")
	}
	if im.Path != "/usr/lib/libSystem.B.dylib" {
		t.Fatalf("basename lookup found %q", im.Path)
	}
}
