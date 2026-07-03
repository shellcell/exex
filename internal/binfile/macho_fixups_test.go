package binfile

import (
	"debug/macho"
	"runtime"
	"strings"
	"testing"
)

// fakeSegs builds segments at known addresses for the opcode-stream tests.
func fakeSegs(addrs ...uint64) []*macho.Segment {
	segs := make([]*macho.Segment, len(addrs))
	for i, a := range addrs {
		segs[i] = &macho.Segment{SegmentHeader: macho.SegmentHeader{Addr: a}}
	}
	return segs
}

func noSection(uint64) string { return "" }

func TestUlebSleb(t *testing.T) {
	// 0x9c 0x01 -> 156; 0x00 -> 0; 0xe5 0x8e 0x26 -> 624485.
	if v, p := uleb([]byte{0x9c, 0x01}, 0); v != 156 || p != 2 {
		t.Errorf("uleb 156: got %d, p=%d", v, p)
	}
	if v, p := uleb([]byte{0xe5, 0x8e, 0x26}, 0); v != 624485 || p != 3 {
		t.Errorf("uleb 624485: got %d, p=%d", v, p)
	}
	// sleb 0x7f -> -1; 0x80 0x7f -> -128.
	if v, _ := sleb([]byte{0x7f}, 0); v != -1 {
		t.Errorf("sleb -1: got %d", v)
	}
	if v, _ := sleb([]byte{0x80, 0x7f}, 0); v != -128 {
		t.Errorf("sleb -128: got %d", v)
	}
}

func TestBindOpsStream(t *testing.T) {
	segs := fakeSegs(0x1000, 0x2000)
	dylibs := []string{"/usr/lib/libSystem.B.dylib"}
	// ordinal 1; symbol "_foo"; type pointer; seg 0 off 0x10; DO_BIND;
	// DO_BIND_ADD_ADDR_IMM_SCALED with imm 1; DONE.
	stream := []byte{}
	stream = append(stream, bindSetDylibOrdImm|0x01)
	stream = append(stream, bindSetSymbol|0x00)
	stream = append(stream, []byte("_foo")...)
	stream = append(stream, 0x00)
	stream = append(stream, bindSetType|0x01)
	stream = append(stream, bindSetSegOff|0x00, 0x10)
	stream = append(stream, bindDoBind)
	stream = append(stream, bindDoBindImmScaled|0x01)
	stream = append(stream, bindDone)

	got := machoBindOps(nil, stream, "BIND", 8, segs, dylibs, noSection)
	if len(got) != 2 {
		t.Fatalf("expected 2 binds, got %d: %+v", len(got), got)
	}
	if got[0].Offset != 0x1010 || got[1].Offset != 0x1018 {
		t.Errorf("bind addresses: got 0x%x, 0x%x; want 0x1010, 0x1018", got[0].Offset, got[1].Offset)
	}
	for _, r := range got {
		if r.Sym != "_foo" || r.Lib != dylibs[0] || r.Type != "BIND" {
			t.Errorf("bind fields: %+v", r)
		}
	}
}

func TestBindOpsUlebTimesSkipping(t *testing.T) {
	segs := fakeSegs(0x4000)
	// seg 0 off 0; DO_BIND_ULEB_TIMES_SKIPPING_ULEB count=3 skip=8; DONE.
	// each iteration advances ptr(8)+skip(8)=16.
	stream := []byte{
		bindSetSymbol, '_', 'b', 0x00,
		bindSetSegOff, 0x00,
		bindDoBindUlebSkip, 0x03, 0x08,
		bindDone,
	}
	got := machoBindOps(nil, stream, "LAZY_BIND", 8, segs, nil, noSection)
	want := []uint64{0x4000, 0x4010, 0x4020}
	if len(got) != len(want) {
		t.Fatalf("expected %d binds, got %d", len(want), len(got))
	}
	for i, w := range want {
		if got[i].Offset != w {
			t.Errorf("bind %d: got 0x%x, want 0x%x", i, got[i].Offset, w)
		}
	}
}

func TestRebaseOpsStream(t *testing.T) {
	segs := fakeSegs(0x8000)
	// seg 0 off 0; DO_REBASE_IMM_TIMES 3; ADD_ADDR_IMM_SCALED 1; DO_REBASE_ULEB_TIMES 2; DONE.
	stream := []byte{
		rebaseSetType | 0x01,
		rebaseSetSegOff, 0x00,
		rebaseImmTimes | 0x03,
		rebaseAddAddrImm | 0x01,
		rebaseUlebTimes, 0x02,
		rebaseDone,
	}
	got := machoRebaseOps(nil, stream, 8, segs, noSection)
	// imm-times: 0x8000, 0x8008, 0x8010 (segOff now 0x18); add imm*ptr=8 -> 0x20;
	// uleb-times 2: 0x8020, 0x8028.
	want := []uint64{0x8000, 0x8008, 0x8010, 0x8020, 0x8028}
	if len(got) != len(want) {
		t.Fatalf("expected %d rebases, got %d: %+v", len(want), len(got), got)
	}
	for i, w := range want {
		if got[i].Offset != w || got[i].Type != "REBASE" {
			t.Errorf("rebase %d: got 0x%x/%s, want 0x%x/REBASE", i, got[i].Offset, got[i].Type, w)
		}
	}
}

func TestDecodeChainedPtr(t *testing.T) {
	// DYLD_CHAINED_PTR_64 bind: bind@63, next@51..62 (12b), ordinal low 24.
	v := uint64(1)<<63 | uint64(2)<<51 | 5
	isBind, auth, ord, next, stride, ok := decodeChainedPtr(v, chainPtr64)
	if !ok || !isBind || auth || ord != 5 || next != 2 || stride != 4 {
		t.Errorf("ptr64 bind: bind=%v auth=%v ord=%d next=%d stride=%d ok=%v", isBind, auth, ord, next, stride, ok)
	}
	// DYLD_CHAINED_PTR_64 rebase: bind bit clear.
	v = uint64(3) << 51
	isBind, _, _, next, stride, ok = decodeChainedPtr(v, chainPtr64)
	if !ok || isBind || next != 3 || stride != 4 {
		t.Errorf("ptr64 rebase: bind=%v next=%d stride=%d ok=%v", isBind, next, stride, ok)
	}
	// arm64e userland auth-bind: auth@63, bind@62, next@51..61 (11b), ordinal low 16.
	v = uint64(1)<<63 | uint64(1)<<62 | uint64(1)<<51 | 7
	isBind, auth, ord, next, stride, ok = decodeChainedPtr(v, chainPtrArm64eUserland)
	if !ok || !isBind || !auth || ord != 7 || next != 1 || stride != 8 {
		t.Errorf("arm64e auth-bind: bind=%v auth=%v ord=%d next=%d stride=%d ok=%v", isBind, auth, ord, next, stride, ok)
	}
	// arm64e userland24 bind: 24-bit ordinal.
	v = uint64(1)<<62 | 0x123456
	_, _, ord, _, _, _ = decodeChainedPtr(v, chainPtrArm64eUserland24)
	if ord != 0x123456 {
		t.Errorf("userland24 ordinal: got 0x%x, want 0x123456", ord)
	}
	// 32-bit / cache formats we don't decode -> ok=false stops the chain.
	if _, _, _, _, _, ok := decodeChainedPtr(0, 3); ok {
		t.Errorf("32-bit format should not decode")
	}
}

func TestUlebTruncatedTerminates(t *testing.T) {
	// A continuation-bit-only tail must not loop past the buffer.
	if v, p := uleb([]byte{0x80, 0x80}, 0); p != 2 || v != 0 {
		t.Errorf("truncated uleb: v=%d p=%d", v, p)
	}
}

// TestMachoDynamicFixupsRealBinary is the end-to-end check against a real linked
// image: /bin/ls (chained fixups on macOS) must yield named binds resolved to
// libSystem and a populated relocs list — the whole point of the decoder.
func TestMachoDynamicFixupsRealBinary(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("needs a system Mach-O")
	}
	f, err := Open("/bin/ls")
	if err != nil {
		t.Skipf("open /bin/ls: %v", err)
	}
	defer f.Close()
	if !f.HasRelocs() {
		t.Fatal("HasRelocs is false for a linked Mach-O with chained fixups")
	}
	rs := f.Relocations()
	binds, rebases, named := 0, 0, 0
	sawLibSystem := false
	for _, r := range rs {
		switch {
		case strings.Contains(r.Type, "BIND"):
			binds++
		case strings.Contains(r.Type, "REBASE"):
			rebases++
		}
		if r.Sym != "" {
			named++
			if r.Offset == 0 {
				t.Errorf("named reloc %q has zero address", r.Sym)
			}
		}
		if strings.Contains(r.Lib, "libSystem") {
			sawLibSystem = true
		}
	}
	t.Logf("/bin/ls: %d relocs, %d binds, %d rebases, %d named", len(rs), binds, rebases, named)
	if binds == 0 || named == 0 {
		t.Fatal("no named binds decoded from /bin/ls")
	}
	if !sawLibSystem {
		t.Error("expected at least one import resolved to libSystem")
	}
}
