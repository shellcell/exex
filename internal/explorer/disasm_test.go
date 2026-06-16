package explorer

import "testing"

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
