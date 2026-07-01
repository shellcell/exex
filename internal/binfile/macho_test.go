package binfile

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestOpenSystemMachO exercises the Mach-O path against a real (usually fat)
// system binary. /bin/ls is Mach-O only on macOS (it's ELF on Linux CI), so the
// test is darwin-only; skipped elsewhere or when the file isn't present.
func TestOpenSystemMachO(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("system Mach-O binary only available on macOS")
	}
	const path = "/bin/ls"
	if _, err := os.Stat(path); err != nil {
		t.Skipf("%s not present", path)
	}
	f, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if f.Format != FormatMachO {
		t.Fatalf("format = %q, want Mach-O", f.Format)
	}
	if f.Entry() == 0 {
		t.Fatal("entry is zero")
	}
	if len(f.Sections) == 0 {
		t.Fatal("no sections")
	}
	if len(f.Symbols) == 0 {
		t.Fatal("no symbols")
	}

	// The entry point must live inside the executable image we'll disassemble.
	if _, ok := f.ExecImage().PosForAddr(f.Entry()); !ok {
		t.Fatalf("entry 0x%x not in executable image", f.Entry())
	}
	// Every byte of the file must be addressable in the raw view.
	if got := len(f.Raw()); got == 0 {
		t.Fatal("raw file is empty")
	}
	if f.VAImage().Len() == 0 {
		t.Fatal("virtual-address image is empty")
	}

	t.Logf("format=%s arch=%d entry=0x%x sections=%d symbols=%d raw=%d va-image=%d exec-image=%d",
		f.Format, f.Arch(), f.Entry(), len(f.Sections), len(f.Symbols),
		len(f.Raw()), f.VAImage().Len(), f.ExecImage().Len())
}

func TestMachOLayoutOnlyMatchesFullLayout(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("system Mach-O binary only available on macOS")
	}
	const path = "/bin/ls"
	if _, err := os.Stat(path); err != nil {
		t.Skipf("%s not present", path)
	}
	full, err := Open(path)
	if err != nil {
		t.Fatalf("Open full: %v", err)
	}
	defer full.Close()
	lite, err := Open(path, WithLayoutOnly())
	if err != nil {
		t.Fatalf("Open layout-only: %v", err)
	}
	defer lite.Close()
	if lite.Format != full.Format || lite.Arch() != full.Arch() || lite.Entry() != full.Entry() {
		t.Fatalf("identity mismatch: lite %s/%d/0x%x full %s/%d/0x%x",
			lite.Format, lite.Arch(), lite.Entry(), full.Format, full.Arch(), full.Entry())
	}
	if len(lite.Symbols) != 0 {
		t.Fatalf("layout-only loaded %d symbols, want 0", len(lite.Symbols))
	}
	if len(lite.Sections) != len(full.Sections) || len(lite.Segments) != len(full.Segments) {
		t.Fatalf("layout size mismatch: sections %d/%d segments %d/%d",
			len(lite.Sections), len(full.Sections), len(lite.Segments), len(full.Segments))
	}
	for i := range full.Sections {
		got, want := lite.Sections[i], full.Sections[i]
		if got != want {
			t.Fatalf("section %d mismatch:\n got  %#v\n want %#v", i, got, want)
		}
	}
	for i := range full.Segments {
		got, want := lite.Segments[i], full.Segments[i]
		if got != want {
			t.Fatalf("segment %d mismatch:\n got  %#v\n want %#v", i, got, want)
		}
	}
}

// TestMachODylibInfo guards that a Mach-O dylib reports no entry point and no
// interpreter (only executables have those), and is treated as position-
// independent. Regression for an earlier bug that invented an __text "entry" and
// a hardcoded "/usr/lib/dyld" interpreter for dylibs.
func TestMachODylibInfo(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("on-disk system dylib only available on macOS")
	}
	matches, _ := filepath.Glob("/usr/lib/*.dylib")
	var path string
	for _, m := range matches {
		fi, err := os.Lstat(m)
		if err == nil && fi.Mode().IsRegular() { // skip symlinks into the shared cache
			path = m
			break
		}
	}
	if path == "" {
		t.Skip("no on-disk dylib found under /usr/lib")
	}
	f, err := Open(path)
	if err != nil {
		t.Fatalf("Open(%s): %v", path, err)
	}
	defer f.Close()
	if f.Format != FormatMachO {
		t.Skipf("%s is not Mach-O", path)
	}
	if f.Entry() != 0 {
		t.Errorf("dylib entry = 0x%x, want 0 (no entry point)", f.Entry())
	}
	if f.Info != nil {
		if f.Info.Interp != "" {
			t.Errorf("dylib interpreter = %q, want empty", f.Info.Interp)
		}
		if f.Info.PIE != TriYes {
			t.Errorf("dylib PIE = %v, want yes (position-independent)", f.Info.PIE)
		}
	}
}

func TestMachORelocatableObjectUsesSyntheticSectionAddresses(t *testing.T) {
	f, err := OpenBytes("tiny.o", tinyMachOObject64())
	if err != nil {
		t.Fatalf("OpenBytes Mach-O object: %v", err)
	}
	if !f.IsRelocatable() {
		t.Fatal("Mach-O object was not marked relocatable")
	}
	if !f.SyntheticAddrs() {
		t.Fatal("Mach-O object did not get synthetic addresses")
	}
	if len(f.Sections) != 2 {
		t.Fatalf("sections = %d, want 2", len(f.Sections))
	}
	text, data := f.Sections[0], f.Sections[1]
	if !text.SynthAddr || !data.SynthAddr || !text.Alloc || !data.Alloc {
		t.Fatalf("synthetic/alloc flags not set: text=%#v data=%#v", text, data)
	}
	if text.Addr == data.Addr {
		t.Fatalf("section addresses still collide at 0x%x", text.Addr)
	}
	if len(f.Symbols) != 2 {
		t.Fatalf("symbols = %d, want 2", len(f.Symbols))
	}
	var textSym, dataSym Symbol
	for _, sym := range f.Symbols {
		switch sym.Name {
		case "_textSym":
			textSym = sym
		case "_dataSym":
			dataSym = sym
		}
	}
	if textSym.Section != "__text" || dataSym.Section != "__data" {
		t.Fatalf("symbol sections: text=%#v data=%#v", textSym, dataSym)
	}
	if textSym.Addr != text.Addr || dataSym.Addr != data.Addr {
		t.Fatalf("symbol addrs = 0x%x/0x%x, want section addrs 0x%x/0x%x", textSym.Addr, dataSym.Addr, text.Addr, data.Addr)
	}
	if sym, ok := f.SymbolAt(textSym.Addr); !ok || sym.Name != "_textSym" {
		t.Fatalf("SymbolAt(text) = %#v, %v; want _textSym", sym, ok)
	}
	if sym, ok := f.SymbolAt(dataSym.Addr); !ok || sym.Name != "_dataSym" {
		t.Fatalf("SymbolAt(data) = %#v, %v; want _dataSym", sym, ok)
	}
	if _, ok := f.ExecImage().PosForAddr(text.Addr); !ok {
		t.Fatalf("exec image cannot locate synthetic text address 0x%x", text.Addr)
	}
}

func tinyMachOObject64() []byte {
	const (
		headerSize = 32
		segSize    = 72 + 2*80
		symCmdSize = 24
		cmdSize    = segSize + symCmdSize
		dataOff    = headerSize + cmdSize
		symOff     = dataOff + 8
		strOff     = symOff + 2*16
		lcSymtab   = 0x2
		cpuAMD64   = 0x01000007
	)
	strs := []byte{0}
	textName := uint32(len(strs))
	strs = append(strs, []byte("_textSym\x00")...)
	dataName := uint32(len(strs))
	strs = append(strs, []byte("_dataSym\x00")...)
	raw := make([]byte, strOff+len(strs))
	bo := binary.LittleEndian

	bo.PutUint32(raw[0:], machoMagic64)
	bo.PutUint32(raw[4:], cpuAMD64)
	bo.PutUint32(raw[8:], 3)  // CPU_SUBTYPE_X86_64_ALL
	bo.PutUint32(raw[12:], 1) // MH_OBJECT
	bo.PutUint32(raw[16:], 2) // ncmds
	bo.PutUint32(raw[20:], cmdSize)

	off := headerSize
	bo.PutUint32(raw[off:], lcSegment64)
	bo.PutUint32(raw[off+4:], segSize)
	bo.PutUint64(raw[off+32:], 8) // vmsize
	bo.PutUint64(raw[off+40:], dataOff)
	bo.PutUint64(raw[off+48:], 8) // filesize
	bo.PutUint32(raw[off+56:], vmProtRead|vmProtExecute)
	bo.PutUint32(raw[off+60:], vmProtRead|vmProtExecute)
	bo.PutUint32(raw[off+64:], 2) // nsects

	sec := off + 72
	copy(raw[sec:], "__text")
	copy(raw[sec+16:], "__TEXT")
	bo.PutUint64(raw[sec+40:], 4)
	bo.PutUint32(raw[sec+48:], dataOff)
	bo.PutUint32(raw[sec+52:], 2)
	bo.PutUint32(raw[sec+64:], machoAttrPureInstr|machoAttrSomeInstr)

	sec += 80
	copy(raw[sec:], "__data")
	copy(raw[sec+16:], "__DATA")
	bo.PutUint64(raw[sec+40:], 4)
	bo.PutUint32(raw[sec+48:], dataOff+4)
	bo.PutUint32(raw[sec+52:], 2)

	off += segSize
	bo.PutUint32(raw[off:], lcSymtab)
	bo.PutUint32(raw[off+4:], symCmdSize)
	bo.PutUint32(raw[off+8:], symOff)
	bo.PutUint32(raw[off+12:], 2)
	bo.PutUint32(raw[off+16:], strOff)
	bo.PutUint32(raw[off+20:], uint32(len(strs)))

	copy(raw[dataOff:], []byte{0x90, 0x90, 0x90, 0xc3, 1, 2, 3, 4})
	bo.PutUint32(raw[symOff:], textName)
	raw[symOff+4] = nSect | nExt
	raw[symOff+5] = 1
	bo.PutUint32(raw[symOff+16:], dataName)
	raw[symOff+20] = nSect | nExt
	raw[symOff+21] = 2
	copy(raw[strOff:], strs)
	return raw
}

// TestFatMagicVsJavaClass guards the 0xCAFEBABE ambiguity: a fat Mach-O has a
// small architecture count, while a Java .class has minor/major version (major
// >= 45) where the count would be, so it must not be detected as Mach-O.
func TestFatMagicVsJavaClass(t *testing.T) {
	fat := []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2}      // 2 architectures
	class := []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0x34} // Java 8 (major 52)
	if !isFatMachO(fat) || !isMachO(fat) {
		t.Fatal("a sane fat header must be detected as fat Mach-O")
	}
	if isFatMachO(class) || isMachO(class) {
		t.Fatal("a Java .class must not be detected as (fat) Mach-O")
	}
}

func TestMachOLayoutRejectsWrappingFatOffset(t *testing.T) {
	raw := make([]byte, 8+32)
	binary.BigEndian.PutUint32(raw[0:], machoFatMagic64)
	binary.BigEndian.PutUint32(raw[4:], 1)
	binary.BigEndian.PutUint64(raw[16:], ^uint64(0)-4)
	binary.BigEndian.PutUint64(raw[24:], 16)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("parseMachOLayoutHeader panicked on wrapping fat offset: %v", r)
		}
	}()
	if _, _, _, err := parseMachOLayoutHeader(raw, ""); err == nil {
		t.Fatal("parseMachOLayoutHeader succeeded for out-of-range fat slice")
	}
}

func TestMachOLayoutBoundsLoadCommandsToSelectedFatSlice(t *testing.T) {
	const off = 64
	const size = 32
	raw := make([]byte, off+size+8)
	binary.BigEndian.PutUint32(raw[0:], machoFatMagic)
	binary.BigEndian.PutUint32(raw[4:], 1)
	binary.BigEndian.PutUint32(raw[16:], off)
	binary.BigEndian.PutUint32(raw[20:], size)

	binary.BigEndian.PutUint32(raw[off:], machoMagic64)
	binary.BigEndian.PutUint32(raw[off+12:], uint32(2)) // executable
	binary.BigEndian.PutUint32(raw[off+16:], 1)         // ncmds
	binary.BigEndian.PutUint32(raw[off+20:], 8)         // sizeofcmds extends past the slice
	binary.BigEndian.PutUint32(raw[off+size:], lcMain)
	binary.BigEndian.PutUint32(raw[off+size+4:], 8)

	f := &File{raw: raw}
	if err := f.loadMachOLayout(); err == nil {
		t.Fatal("loadMachOLayout succeeded after reading load commands outside the selected fat slice")
	}
}
