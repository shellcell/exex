package dyldcache

import (
	"os"
	"testing"
)

// realCachePaths lists where a system dyld shared cache lives across macOS
// versions. The test is skipped when none is present (e.g. CI, Linux).
var realCachePaths = []string{
	"/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e",
	"/System/Library/dyld/dyld_shared_cache_arm64e",
	"/System/Library/dyld/dyld_shared_cache_x86_64",
}

// TestReadRealCache exercises the reader end-to-end against the host's own dyld
// cache when one is available: every image header must translate to valid bytes.
func TestReadRealCache(t *testing.T) {
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
	defer c.Close()

	if len(c.Images) == 0 {
		t.Fatal("real cache reported no images")
	}
	t.Logf("arch=%s images=%d mappings=%d subcaches=%d",
		c.Arch, len(c.Images), len(c.Mappings), len(c.SubCacheNames()))

	fails := 0
	for _, im := range c.Images {
		if b, ok := c.BytesAt(im.Address, 4); !ok || len(b) < 4 {
			fails++
		}
	}
	if fails > 0 {
		t.Errorf("%d of %d image headers failed address translation", fails, len(c.Images))
	}
}
