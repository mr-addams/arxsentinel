package detector

import (
	"os"
	"path/filepath"
	"testing"
)

// ── MemoryStore ───────────────────────────────────────────────────────────────────────

func TestMemoryStore_LoadEmpty(t *testing.T) {
	s := &MemoryStore{}
	ua, ref, err := s.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ua) != 0 || len(ref) != 0 {
		t.Errorf("want empty slices, got ua=%v ref=%v", ua, ref)
	}
}

func TestMemoryStore_SaveLoad(t *testing.T) {
	s := &MemoryStore{}
	wantUA := []string{"ahrefsbot", "semrushbot"}
	wantRef := []string{"semalt", "buttons-for-website"}

	if err := s.Save(wantUA, wantRef); err != nil {
		t.Fatalf("Save: %v", err)
	}

	gotUA, gotRef, err := s.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !strSliceEqual(gotUA, wantUA) {
		t.Errorf("UA: want %v, got %v", wantUA, gotUA)
	}
	if !strSliceEqual(gotRef, wantRef) {
		t.Errorf("Ref: want %v, got %v", wantRef, gotRef)
	}
}

func TestMemoryStore_SaveIsolatesSlice(t *testing.T) {
	// Save must copy, not store the original slice — mutation must not affect the store.
	s := &MemoryStore{}
	ua := []string{"bot1", "bot2"}
	s.Save(ua, nil)
	ua[0] = "mutated"

	got, _, _ := s.Load()
	if got[0] == "mutated" {
		t.Error("MemoryStore.Save must copy the slice, not store the reference")
	}
}

func TestMemoryStore_Close(t *testing.T) {
	s := &MemoryStore{}
	if err := s.Close(); err != nil {
		t.Errorf("Close: unexpected error: %v", err)
	}
}

// ── BboltStore ────────────────────────────────────────────────────────────────────────

func TestBboltStore_SaveLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	store, err := newBboltStore(path)
	if err != nil {
		t.Fatalf("newBboltStore: %v", err)
	}

	wantUA := []string{"ahrefsbot", "semrushbot", "mj12bot"}
	wantRef := []string{"semalt", "buttons-for-website"}

	if err := store.Save(wantUA, wantRef); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reopen and verify persistence.
	store2, err := newBboltStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer store2.Close()

	gotUA, gotRef, err := store2.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !strSliceEqual(gotUA, wantUA) {
		t.Errorf("UA: want %v, got %v", wantUA, gotUA)
	}
	if !strSliceEqual(gotRef, wantRef) {
		t.Errorf("Ref: want %v, got %v", wantRef, gotRef)
	}
}

func TestBboltStore_LoadMissing(t *testing.T) {
	// Fresh DB with no saved patterns → Load must return empty slices, not an error.
	path := filepath.Join(t.TempDir(), "empty.db")
	store, err := newBboltStore(path)
	if err != nil {
		t.Fatalf("newBboltStore: %v", err)
	}
	defer store.Close()

	ua, ref, err := store.Load()
	if err != nil {
		t.Fatalf("Load on fresh DB: %v", err)
	}
	if len(ua) != 0 || len(ref) != 0 {
		t.Errorf("want empty slices, got ua=%v ref=%v", ua, ref)
	}
}

func TestBboltStore_SaveEmptyRef(t *testing.T) {
	// Saving with an empty ref slice must not corrupt UA data.
	path := filepath.Join(t.TempDir(), "no-ref.db")
	store, err := newBboltStore(path)
	if err != nil {
		t.Fatalf("newBboltStore: %v", err)
	}
	defer store.Close()

	wantUA := []string{"ahrefsbot"}
	if err := store.Save(wantUA, nil); err != nil {
		t.Fatalf("Save: %v", err)
	}

	gotUA, gotRef, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !strSliceEqual(gotUA, wantUA) {
		t.Errorf("UA: want %v, got %v", wantUA, gotUA)
	}
	if len(gotRef) != 0 {
		t.Errorf("Ref: want empty, got %v", gotRef)
	}
}

// ── Factory ───────────────────────────────────────────────────────────────────────────

func TestNewPatternStore_Memory(t *testing.T) {
	store, err := newPatternStore("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer store.Close()
	if _, ok := store.(*MemoryStore); !ok {
		t.Errorf("want *MemoryStore, got %T", store)
	}
}

func TestNewPatternStore_Bbolt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "factory.db")
	store, err := newPatternStore(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer store.Close()
	if _, ok := store.(*BboltStore); !ok {
		t.Errorf("want *BboltStore, got %T", store)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("bbolt file not created: %v", err)
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────────────

// splitLines / joinLines round-trip.
func TestSplitJoinLines_RoundTrip(t *testing.T) {
	in := []string{"ahrefsbot", "semrushbot", "mj12bot"}
	got := splitLines(joinLines(in))
	if !strSliceEqual(got, in) {
		t.Errorf("round-trip failed: want %v, got %v", in, got)
	}
}

func TestSplitLines_Nil(t *testing.T) {
	if got := splitLines(nil); len(got) != 0 {
		t.Errorf("want empty, got %v", got)
	}
}

func TestJoinLines_Nil(t *testing.T) {
	if got := joinLines(nil); got != nil {
		t.Errorf("want nil, got %v", got)
	}
}

// strSliceEqual compares two string slices element by element.
func strSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
