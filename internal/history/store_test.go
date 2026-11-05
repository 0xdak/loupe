package history

import (
	"os"
	"path/filepath"
	"testing"

	"lightproxy/internal/flow"
)

func TestReopenContinuesIDsAndSkipsPartialLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "h.jsonl")
	s, err := Open(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := s.Add(&flow.Flow{ID: s.NextID(), Method: "GET"}); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()

	// Simulate a write cut short by a crash.
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString(`{"id":99,"meth`)
	f.Close()

	s, err = Open(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.NextID(); got != 4 {
		t.Errorf("NextID after reopen = %d, want 4", got)
	}
	if err := s.Add(&flow.Flow{ID: 4}); err != nil {
		t.Fatal(err)
	}
	if n := len(s.Recent(100)); n != 4 {
		t.Errorf("Recent has %d flows, want 4", n)
	}
	s.Close()

	var ids []int64
	skipped, err := Each(path, func(f *flow.Flow) error { ids = append(ids, f.ID); return nil })
	if err != nil || skipped != 1 || len(ids) != 4 || ids[3] != 4 {
		t.Errorf("Each: ids=%v skipped=%d err=%v; want 4 ids ending in 4, 1 skipped", ids, skipped, err)
	}
}

func TestRecentKeepsNewest(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "h.jsonl"), 2)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for range 3 {
		s.Add(&flow.Flow{ID: s.NextID()})
	}
	r := s.Recent(10)
	if len(r) != 2 || r[0].ID != 2 || r[1].ID != 3 {
		t.Errorf("Recent = %v, want IDs 2,3", r)
	}
}
