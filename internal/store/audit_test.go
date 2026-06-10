package store

import (
	"bytes"
	"testing"
	"time"
)

func TestComputeRecordHashDeterministic(t *testing.T) {
	at := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	d := []byte(`{"a":"1"}`)
	h1 := computeRecordHash(nil, at, "alice", "session.start", "web01", d)
	h2 := computeRecordHash(nil, at, "alice", "session.start", "web01", d)
	if !bytes.Equal(h1, h2) {
		t.Fatal("hash should be deterministic for identical inputs")
	}
	if len(h1) != 32 {
		t.Fatalf("expected 32-byte SHA-256, got %d", len(h1))
	}
}

func TestComputeRecordHashFieldSensitivity(t *testing.T) {
	at := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	base := computeRecordHash(nil, at, "alice", "session.start", "web01", []byte(`{}`))

	variants := map[string][]byte{
		"prev changed":   computeRecordHash([]byte{1}, at, "alice", "session.start", "web01", []byte(`{}`)),
		"time changed":   computeRecordHash(nil, at.Add(time.Second), "alice", "session.start", "web01", []byte(`{}`)),
		"actor changed":  computeRecordHash(nil, at, "bob", "session.start", "web01", []byte(`{}`)),
		"event changed":  computeRecordHash(nil, at, "alice", "session.end", "web01", []byte(`{}`)),
		"target changed": computeRecordHash(nil, at, "alice", "session.start", "web02", []byte(`{}`)),
		"detail changed": computeRecordHash(nil, at, "alice", "session.start", "web01", []byte(`{"x":"1"}`)),
	}
	for name, h := range variants {
		if bytes.Equal(base, h) {
			t.Errorf("hash should change when %s", name)
		}
	}
}

// TestFieldBoundaryUnambiguous guards against delimiter-injection: moving a
// character across a field boundary must change the hash.
func TestFieldBoundaryUnambiguous(t *testing.T) {
	at := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	a := computeRecordHash(nil, at, "ab", "c", "", []byte(`{}`))
	b := computeRecordHash(nil, at, "a", "bc", "", []byte(`{}`))
	if bytes.Equal(a, b) {
		t.Fatal("length-prefixing should make field boundaries unambiguous")
	}
}

func TestCanonicalDetailSortsKeys(t *testing.T) {
	// Same content, different key order in source bytes → same canonical form.
	c1, err := canonicalDetail([]byte(`{"b":"2","a":"1"}`))
	if err != nil {
		t.Fatal(err)
	}
	c2, err := canonicalDetail([]byte(`{"a":"1","b":"2"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c1, c2) {
		t.Fatalf("canonical detail should be key-order independent: %s vs %s", c1, c2)
	}
}
