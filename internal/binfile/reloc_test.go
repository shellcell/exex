package binfile

import (
	"encoding/binary"
	"testing"
)

func TestDecodeReloc(t *testing.T) {
	bo := binary.LittleEndian

	// RELA64: r_offset(8) | r_info(8) where info = sym<<32 | type.
	rela := make([]byte, 24)
	bo.PutUint64(rela[0:], 0x1000)
	bo.PutUint64(rela[8:], (uint64(5)<<32)|7)
	if off, sym, typ := decodeReloc(rela, 0, true, bo); off != 0x1000 || sym != 5 || typ != 7 {
		t.Errorf("RELA64 = (0x%x,%d,%d), want (0x1000,5,7)", off, sym, typ)
	}

	// REL32: r_offset(4) | r_info(4) where info = sym<<8 | type.
	rel := make([]byte, 8)
	bo.PutUint32(rel[0:], 0x2000)
	bo.PutUint32(rel[4:], (uint32(3)<<8)|6)
	if off, sym, typ := decodeReloc(rel, 0, false, bo); off != 0x2000 || sym != 3 || typ != 6 {
		t.Errorf("REL32 = (0x%x,%d,%d), want (0x2000,3,6)", off, sym, typ)
	}
}

func TestIsELFMappingSymbol(t *testing.T) {
	for _, n := range []string{"$x", "$d", "$a", "$t", "$x.0", "$d.123"} {
		if !isELFMappingSymbol(n) {
			t.Errorf("%q should be a mapping symbol", n)
		}
	}
	for _, n := range []string{"main", "g", "$", "$z", "_$s123", "x$d"} {
		if isELFMappingSymbol(n) {
			t.Errorf("%q should NOT be a mapping symbol", n)
		}
	}
}
