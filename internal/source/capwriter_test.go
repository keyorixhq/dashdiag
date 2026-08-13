package source

import (
	"bytes"
	"testing"
)

func TestCapWriterCapsAtLimit(t *testing.T) {
	t.Parallel()
	w := NewCapWriter(10)
	n, err := w.Write([]byte("0123456789ABCDEF")) // 16 bytes, limit is 10
	if err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	if n != 16 {
		t.Errorf("Write() n = %d, want 16 (must report the full slice consumed)", n)
	}
	if got := w.Bytes(); !bytes.Equal(got, []byte("0123456789")) {
		t.Errorf("Bytes() = %q, want %q", got, "0123456789")
	}
}

func TestCapWriterMultipleWritesStopAtLimit(t *testing.T) {
	t.Parallel()
	w := NewCapWriter(5)
	for i := 0; i < 5; i++ {
		if _, err := w.Write([]byte("XY")); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}
	if got := len(w.Bytes()); got != 5 {
		t.Errorf("Bytes() length = %d, want 5 (capped)", got)
	}
}

func TestCapWriterUnderLimit(t *testing.T) {
	t.Parallel()
	w := NewCapWriter(100)
	if _, err := w.Write([]byte("hello")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := w.Bytes(); !bytes.Equal(got, []byte("hello")) {
		t.Errorf("Bytes() = %q, want %q", got, "hello")
	}
}
