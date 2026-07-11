package explorer

import (
	"os"
	"testing"

	"github.com/rabarbra/exex/internal/binfile"
	"github.com/rabarbra/exex/internal/disasm"
)

// TestDecodeRangeMatchesWindow guards the xref speed-up: DecodeRange (small
// resync lead, uncached) must decode the same instructions over a window as
// DecodeWindow (large interactive overlap). Uses the test binary itself so it
// needs no fixture.
func TestDecodeRangeMatchesWindow(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	f, err := binfile.Open(exe)
	if err != nil {
		t.Skip(err)
	}
	defer f.Close()
	dis, err := disasm.For(f.Arch())
	if err != nil || dis == nil {
		t.Skip("no disassembler for host arch")
	}
	img := f.ExecImage()
	size := 8192
	if img.Len() < 4*size {
		t.Skip("exec image too small")
	}
	start := (img.Len() / 2) &^ 0xfff // a 4 KiB-aligned window well inside .text

	s := NewDisasmService(f, dis, 2<<20, 0)
	want := s.DecodeWindow(img.Window(start, size))
	got := s.DecodeRange(start, size, 1<<10)

	if len(want) == 0 || len(want) != len(got) {
		t.Fatalf("instruction count: DecodeWindow=%d DecodeRange=%d", len(want), len(got))
	}
	for i := range want {
		if want[i].Addr != got[i].Addr || want[i].Text != got[i].Text {
			t.Fatalf("inst %d differs:\n window: 0x%x %q\n  range: 0x%x %q",
				i, want[i].Addr, want[i].Text, got[i].Addr, got[i].Text)
		}
	}
}

// TestDecodeRangeFuncMatchesSlice guards the scan allocation win: the streamed
// DecodeRangeFunc must visit exactly the instructions DecodeRange returns, in
// order — so xref/find/scan results are identical to the slice path.
func TestDecodeRangeFuncMatchesSlice(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	f, err := binfile.Open(exe)
	if err != nil {
		t.Skip(err)
	}
	defer f.Close()
	dis, err := disasm.For(f.Arch())
	if err != nil || dis == nil {
		t.Skip("no disassembler for host arch")
	}
	img := f.ExecImage()
	size := 8192
	if img.Len() < 4*size {
		t.Skip("exec image too small")
	}
	start := (img.Len() / 2) &^ 0xfff
	s := NewDisasmService(f, dis, 2<<20, 0)

	want := s.DecodeRange(start, size, 1<<10)
	var got []disasm.Inst
	s.DecodeRangeFunc(start, size, 1<<10, func(in disasm.Inst) bool {
		got = append(got, in)
		return true
	})
	if len(want) == 0 || len(want) != len(got) {
		t.Fatalf("instruction count: DecodeRange=%d DecodeRangeFunc=%d", len(want), len(got))
	}
	for i := range want {
		if want[i].Addr != got[i].Addr || want[i].Text != got[i].Text {
			t.Fatalf("inst %d differs: 0x%x %q vs 0x%x %q", i, want[i].Addr, want[i].Text, got[i].Addr, got[i].Text)
		}
	}

	// Early stop: returning false halts iteration.
	n := 0
	s.DecodeRangeFunc(start, size, 1<<10, func(disasm.Inst) bool { n++; return n < 3 })
	if n != 3 {
		t.Fatalf("early stop visited %d instructions, want 3", n)
	}
}

func TestDisasmSearchWorkerPolicy(t *testing.T) {
	s := NewDisasmService(nil, nil, 256<<10, 3)
	if got := s.SearchWorkersFor(10); got != 3 {
		t.Fatalf("workers = %d, want configured 3", got)
	}
	if got := s.SearchWorkersFor(2); got != 2 {
		t.Fatalf("workers capped by chunks = %d, want 2", got)
	}
	if got := s.SearchBatchChunks(); got < 2 {
		t.Fatalf("batch chunks = %d, want at least 2", got)
	}
	s.SetOptions(64<<10, 3)
	if got := s.SearchBatchChunks(); got < 4 {
		t.Fatalf("small-window batch chunks = %d, want at least 4", got)
	}
	s.SetOptions(256<<10, 0)
	if got := s.SearchWorkersFor(100); got < 1 || got > 6 {
		t.Fatalf("default workers = %d, want between 1 and 6", got)
	}
}

func TestDisasmLeadAndOverlapStayWithinBudget(t *testing.T) {
	s := NewDisasmService(nil, nil, 16<<10, 0)
	if got := s.OverlapBytes(); got <= 0 || got >= 16<<10 {
		t.Fatalf("overlap = %d, want positive and below budget", got)
	}
	if got := s.LeadBytes(); got < s.OverlapBytes() || got >= 16<<10 {
		t.Fatalf("lead = %d, overlap = %d", got, s.OverlapBytes())
	}
}

func TestDisasmCacheEvictsByRetainedBytes(t *testing.T) {
	s := NewDisasmService(nil, nil, 1, 0)
	light := []disasm.Inst{{Text: "x"}}
	heavy := []disasm.Inst{{Text: "xx"}}
	s.cacheBudget = disasmCacheWeight(light) * 2

	a := disasmCacheKey{start: 1}
	b := disasmCacheKey{start: 2}
	c := disasmCacheKey{start: 3}
	s.cachePut(a, light)
	s.cachePut(b, light)
	s.cachePut(c, heavy)

	if _, ok := s.cacheGet(a); ok {
		t.Fatal("oldest entry remained cached after byte eviction")
	}
	if _, ok := s.cacheGet(b); ok {
		t.Fatal("second entry remained cached despite unequal entry weights")
	}
	if _, ok := s.cacheGet(c); !ok {
		t.Fatal("new entry was not cached")
	}
	if s.cacheBytes != disasmCacheWeight(heavy) || len(s.cache) != 1 {
		t.Fatalf("cache retained %d bytes in %d entries, budget %d", s.cacheBytes, len(s.cache), s.cacheBudget)
	}
}

func TestDisasmCacheRejectsOversizedEntry(t *testing.T) {
	s := NewDisasmService(nil, nil, 1, 0)
	s.cacheBudget = disasmCacheWeight([]disasm.Inst{{}})
	key := disasmCacheKey{start: 1}
	s.cachePut(key, []disasm.Inst{{Text: "too large"}})

	if _, ok := s.cacheGet(key); ok {
		t.Fatal("oversized entry entered cache")
	}
	if s.cacheBytes != 0 || len(s.cache) != 0 {
		t.Fatalf("cache retained oversized entry: %d bytes in %d entries", s.cacheBytes, len(s.cache))
	}
}

func TestDisasmCacheHitUpdatesRecency(t *testing.T) {
	s := NewDisasmService(nil, nil, 1, 0)
	insts := []disasm.Inst{{Text: "x"}}
	weight := disasmCacheWeight(insts)
	s.cacheBudget = weight * 2

	a := disasmCacheKey{start: 1}
	b := disasmCacheKey{start: 2}
	c := disasmCacheKey{start: 3}
	s.cachePut(a, insts)
	s.cachePut(b, insts)
	if _, ok := s.cacheGet(a); !ok {
		t.Fatal("expected first entry in cache")
	}
	s.cachePut(c, insts)

	if _, ok := s.cacheGet(b); ok {
		t.Fatal("least recently used entry remained cached")
	}
	if _, ok := s.cacheGet(a); !ok {
		t.Fatal("recently accessed entry was evicted")
	}
	if _, ok := s.cacheGet(c); !ok {
		t.Fatal("new entry was not cached")
	}
}
