package cvedata

import (
	"io"
	"strings"
	"testing"
)

// withShrunkFeedCap temporarily lowers maxDecompressedFeedBytes so a test can
// prove the cap is enforced without constructing a real gigabyte-scale
// gzip/bzip2 bomb fixture. Mutates a package global, so callers must not
// t.Parallel() (same constraint as other global-swap test helpers in this
// codebase).
func withShrunkFeedCap(t *testing.T, n int64) {
	t.Helper()
	old := maxDecompressedFeedBytes
	maxDecompressedFeedBytes = n
	t.Cleanup(func() { maxDecompressedFeedBytes = old })
}

// TestBoundedReader_CapsRead exercises the capping logic directly via
// boundedReader's explicit limit parameter — safe to run in parallel since,
// unlike boundDecompressed, it never touches the maxDecompressedFeedBytes
// package var.
func TestBoundedReader_CapsRead(t *testing.T) {
	t.Parallel()
	r := boundedReader(strings.NewReader(strings.Repeat("x", 100)), 10)
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(got) != 10 {
		t.Errorf("boundedReader did not cap the read: got %d bytes, want 10", len(got))
	}
}
