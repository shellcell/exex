package dyldcache

import (
	"os"
	"path/filepath"
	"testing"
)

// buildSyntheticCache writes a minimal but structurally valid v2 dyld cache with
// one subcache, one mapping in each, and two images, returning the main path.
func buildSyntheticCache(t *testing.T, dir string) string {
	t.Helper()

	const (
		mappingOffset = 552
		imagesOffset  = 664
		subArrOffset  = 900
		strOffset     = 1200 // where image path strings live in the main file
	)
	// Region A (main file) covers VA 0x1000.., Region B (subcache) VA 0x8000..
	main := make([]byte, 4096)
	copy(main, "dyld_v1  arm64e\x00")
	order.PutUint32(main[offMappingOffset:], mappingOffset)
	order.PutUint32(main[offMappingCount:], 1)
	order.PutUint32(main[offImagesOffset:], imagesOffset)
	order.PutUint32(main[offImagesCount:], 2)
	order.PutUint32(main[offSubCacheArrayOffset:], subArrOffset)
	order.PutUint32(main[offSubCacheArrayCount:], 1)

	// main mapping: VA 0x1000, size 0x1000, fileOffset 0
	order.PutUint64(main[mappingOffset:], 0x1000)
	order.PutUint64(main[mappingOffset+8:], 0x1000)
	order.PutUint64(main[mappingOffset+16:], 0)

	// images: one in the main mapping, one in the subcache mapping
	pathA := "/usr/lib/libA.dylib"
	pathB := "/usr/lib/libB.dylib"
	copy(main[strOffset:], pathA+"\x00")
	copy(main[strOffset+64:], pathB+"\x00")
	order.PutUint64(main[imagesOffset:], 0x1100) // libA header VA (in main mapping)
	order.PutUint32(main[imagesOffset+24:], strOffset)
	order.PutUint64(main[imagesOffset+imageInfoSize:], 0x8100) // libB header VA (subcache)
	order.PutUint32(main[imagesOffset+imageInfoSize+24:], strOffset+64)

	// v2 subcache entry: uuid, cacheVMOffset, fileSuffix ".01"
	order.PutUint64(main[subArrOffset+16:], 0x7000)
	copy(main[subArrOffset+subEntryV1Size:], ".01\x00")

	// Subcache file: header + one mapping covering VA 0x8000.
	sub := make([]byte, 4096)
	copy(sub, "dyld_v1  arm64e\x00")
	order.PutUint32(sub[offMappingOffset:], mappingOffset)
	order.PutUint32(sub[offMappingCount:], 1)
	order.PutUint64(sub[mappingOffset:], 0x8000)   // VA
	order.PutUint64(sub[mappingOffset+8:], 0x1000) // size
	order.PutUint64(sub[mappingOffset+16:], 0)     // fileOffset
	sub[0x100] = 0xAB                              // marker byte at VA 0x8100

	main[0x100] = 0xCD // marker byte at VA 0x1100

	mainPath := filepath.Join(dir, "dyld_shared_cache_arm64e")
	if err := os.WriteFile(mainPath, main, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mainPath+".01", sub, 0o644); err != nil {
		t.Fatal(err)
	}
	return mainPath
}

func TestOpenSyntheticCache(t *testing.T) {
	dir := t.TempDir()
	path := buildSyntheticCache(t, dir)

	c, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if c.Arch != "arm64e" {
		t.Errorf("Arch = %q, want arm64e", c.Arch)
	}
	if len(c.Images) != 2 {
		t.Fatalf("images = %d, want 2", len(c.Images))
	}
	if c.Images[0].Path != "/usr/lib/libA.dylib" || c.Images[1].Path != "/usr/lib/libB.dylib" {
		t.Errorf("image paths = %q, %q", c.Images[0].Path, c.Images[1].Path)
	}
	if len(c.Mappings) != 2 {
		t.Fatalf("mappings = %d, want 2 (main + subcache)", len(c.Mappings))
	}
	if names := c.SubCacheNames(); len(names) != 2 || names[1] != "dyld_shared_cache_arm64e.01" {
		t.Errorf("subcache names = %v", names)
	}
}

func TestBytesAtCrossesSubcaches(t *testing.T) {
	dir := t.TempDir()
	c, err := Open(buildSyntheticCache(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// VA 0x1100 lives in the main file (marker 0xCD).
	if b, ok := c.BytesAt(0x1100, 1); !ok || b[0] != 0xCD {
		t.Errorf("BytesAt(0x1100) = %v ok=%v, want [0xCD]", b, ok)
	}
	// VA 0x8100 lives in the subcache file (marker 0xAB) — translation must find it.
	if b, ok := c.BytesAt(0x8100, 1); !ok || b[0] != 0xAB {
		t.Errorf("BytesAt(0x8100) = %v ok=%v, want [0xAB]", b, ok)
	}
	// An address in no mapping fails cleanly.
	if _, ok := c.BytesAt(0x50000, 4); ok {
		t.Errorf("BytesAt(unmapped) ok=true, want false")
	}
	// A short-read at the end of a mapping is clamped, not out of bounds.
	if b, ok := c.BytesAt(0x1FFF, 16); !ok || len(b) != 1 {
		t.Errorf("BytesAt near end = len %d ok=%v, want 1", len(b), ok)
	}
}

func TestIsCache(t *testing.T) {
	if !IsCache([]byte("dyld_v1  arm64e\x00")) {
		t.Error("valid magic rejected")
	}
	if IsCache([]byte("\x7fELF")) {
		t.Error("ELF accepted as cache")
	}
	if IsCache([]byte("short")) {
		t.Error("short buffer accepted")
	}
}

func TestOldImagesFallback(t *testing.T) {
	// A cache that only sets imagesOffsetOld must still resolve its images.
	dir := t.TempDir()
	path := buildSyntheticCache(t, dir)
	raw, _ := os.ReadFile(path)
	// Move the two-image table's location into the *Old fields and zero the new.
	order.PutUint32(raw[offImagesOffset:], 0)
	order.PutUint32(raw[offImagesCount:], 0)
	order.PutUint32(raw[offImagesOffsetOld:], 664)
	order.PutUint32(raw[offImagesCountOld:], 2)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if len(c.Images) != 2 {
		t.Fatalf("images via Old fields = %d, want 2", len(c.Images))
	}
}
