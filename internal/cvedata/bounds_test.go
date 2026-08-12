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

func TestBoundDecompressed_CapsRead(t *testing.T) {
	t.Parallel()
	withoutParallelShrink := func(n int64) io.Reader {
		old := maxDecompressedFeedBytes
		maxDecompressedFeedBytes = n
		defer func() { maxDecompressedFeedBytes = old }()
		return boundDecompressed(strings.NewReader(strings.Repeat("x", 100)))
	}
	r := withoutParallelShrink(10)
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(got) != 10 {
		t.Errorf("boundDecompressed did not cap the read: got %d bytes, want 10", len(got))
	}
}
