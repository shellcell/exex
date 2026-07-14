package disasm

import (
	"testing"

	dis "github.com/shellcell/exex/internal/disasm"
	"github.com/shellcell/exex/internal/explorer"
)

func pushed(addrs ...uint64) *State {
	st := &State{}
	for _, a := range addrs {
		st.PushHistory(a)
	}
	return st
}

func TestPushHistoryAppendsAndPoints(t *testing.T) {
	st := pushed(0x10, 0x20, 0x30)
	if len(st.History) != 3 || st.HistoryPos != 2 {
		t.Fatalf("History = %#x pos %d, want 3 entries pos 2", st.History, st.HistoryPos)
	}
}

// TestPushHistoryDedupesTheNewestEntry: jumping to where you already are must
// not burn a history slot, but it must still move the pointer to the end.
func TestPushHistoryDedupesTheNewestEntry(t *testing.T) {
	st := pushed(0x10, 0x20)
	st.HistoryPos = 1
	st.PushHistory(0x20)
	if len(st.History) != 2 {
		t.Errorf("duplicate push grew the stack to %#x", st.History)
	}
	if st.HistoryPos != 1 {
		t.Errorf("HistoryPos = %d, want 1", st.HistoryPos)
	}
	// Only the *most recent* entry dedupes; revisiting an older address is a
	// genuine new jump.
	st.PushHistory(0x10)
	if len(st.History) != 3 {
		t.Errorf("revisiting an older address did not push: %#x", st.History)
	}
}

// TestPushHistoryTruncatesTheForwardTail: going back and then jumping somewhere
// new discards the forward entries, like a browser.
func TestPushHistoryTruncatesTheForwardTail(t *testing.T) {
	st := pushed(0x10, 0x20, 0x30)
	st.HistoryPos = 0 // went back twice
	st.PushHistory(0x99)
	want := []uint64{0x10, 0x99}
	if len(st.History) != len(want) || st.History[0] != want[0] || st.History[1] != want[1] {
		t.Errorf("History = %#x, want %#x", st.History, want)
	}
	if st.HistoryPos != 1 {
		t.Errorf("HistoryPos = %d, want 1", st.HistoryPos)
	}
}

func TestPushHistoryCapsTheStack(t *testing.T) {
	st := &State{}
	for i := range HistoryCap + 5 {
		st.PushHistory(uint64(i + 1))
	}
	if len(st.History) != HistoryCap {
		t.Fatalf("stack grew to %d, cap is %d", len(st.History), HistoryCap)
	}
	// The oldest entries fall off; the newest survive.
	if st.History[0] != 6 || st.History[len(st.History)-1] != uint64(HistoryCap+5) {
		t.Errorf("kept [%#x..%#x], want the newest window", st.History[0], st.History[len(st.History)-1])
	}
	if st.HistoryPos != HistoryCap-1 {
		t.Errorf("HistoryPos = %d, want %d", st.HistoryPos, HistoryCap-1)
	}
}

// TestSnapshotCursorRewritesTheCurrentEntry is what makes "back" land on the
// exact instruction the user left, not the address they originally jumped to.
func TestSnapshotCursorRewritesTheCurrentEntry(t *testing.T) {
	st := pushed(0x10, 0x20)
	st.Inst = []dis.Inst{{Addr: 0x24}, {Addr: 0x28}}
	st.Cur = 1
	st.SnapshotCursorToHistory()
	if st.History[1] != 0x28 {
		t.Errorf("History[1] = %#x, want the cursor address 0x28", st.History[1])
	}
	if st.History[0] != 0x10 {
		t.Errorf("History[0] = %#x changed; only the current entry may move", st.History[0])
	}
}

func TestSnapshotCursorNoops(t *testing.T) {
	t.Run("empty history", func(t *testing.T) {
		st := &State{Inst: []dis.Inst{{Addr: 0x24}}}
		st.SnapshotCursorToHistory() // must not panic
		if len(st.History) != 0 {
			t.Error("snapshot invented a history entry")
		}
	})
	t.Run("no window loaded", func(t *testing.T) {
		st := pushed(0x10)
		st.SnapshotCursorToHistory()
		if st.History[0] != 0x10 {
			t.Errorf("History[0] = %#x, want 0x10 untouched", st.History[0])
		}
	})
	t.Run("cursor outside window", func(t *testing.T) {
		st := pushed(0x10)
		st.Inst = []dis.Inst{{Addr: 0x24}}
		st.Cur = 2
		st.SnapshotCursorToHistory()
		if st.History[0] != 0x10 {
			t.Errorf("History[0] = %#x, want 0x10 untouched", st.History[0])
		}
	})
}

func TestSetSpanInstallsAndDropsCaches(t *testing.T) {
	st := &State{Decoding: true, PendingAddr: 0x40}
	st.HeightCache = make(map[HeightKey]int)
	st.HeightCache[HeightKey{I: 0, W: 80}] = 3

	ok := st.SetSpan(explorer.Span{Insts: []dis.Inst{{Addr: 0x10}}, PosLo: 5, PosHi: 9})
	if !ok {
		t.Fatal("installing a non-empty span reported false")
	}
	if len(st.Inst) != 1 || st.PosLo != 5 || st.PosHi != 9 {
		t.Errorf("window = (%d insts, %d, %d), want (1, 5, 9)", len(st.Inst), st.PosLo, st.PosHi)
	}
	if !st.Built || st.Decoding || st.PendingAddr != 0 {
		t.Errorf("flags = built %v decoding %v pending %#x, want true/false/0", st.Built, st.Decoding, st.PendingAddr)
	}
	// The heights belong to the old window's instructions.
	if st.HeightCache != nil {
		t.Error("SetSpan kept the height cache of the previous window")
	}
}

// TestSetSpanNeverClobbersAGoodWindow: a step that runs off the end decodes
// nothing; replacing the window with it would strand the cursor.
func TestSetSpanNeverClobbersAGoodWindow(t *testing.T) {
	st := &State{Inst: []dis.Inst{{Addr: 0x10}}, PosLo: 1, PosHi: 2}
	if st.SetSpan(explorer.Span{}) {
		t.Error("installing an empty span over a good window reported true")
	}
	if len(st.Inst) != 1 || st.PosLo != 1 || st.PosHi != 2 {
		t.Error("the empty span clobbered the window")
	}
	// On a genuinely empty view an empty decode is the truth, and Built must be
	// recorded so the shell stops retrying.
	empty := &State{}
	if empty.SetSpan(explorer.Span{}) {
		t.Error("an empty decode into an empty view reported a usable window")
	}
	if !empty.Built {
		t.Error("the empty decode was not recorded as built")
	}
}

func TestCurAddr(t *testing.T) {
	st := &State{}
	if _, ok := st.CurAddr(); ok {
		t.Error("an empty window has a cursor address")
	}
	st.Inst = []dis.Inst{{Addr: 0x10}, {Addr: 0x14}}
	st.Cur = 1
	if a, ok := st.CurAddr(); !ok || a != 0x14 {
		t.Errorf("CurAddr = (%#x, %v), want (0x14, true)", a, ok)
	}
	st.Cur = len(st.Inst)
	if _, ok := st.CurAddr(); ok {
		t.Error("an out-of-range cursor has an address")
	}
}
