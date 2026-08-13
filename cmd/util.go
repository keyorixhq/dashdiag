package cmd

import (
	"fmt"
	"io"
	"os"
	"time"
)

// truncateStr truncates a string to at most n runes with an ellipsis. It slices
// by rune, not byte, so a multibyte character at the boundary is never split
// into invalid UTF-8.
func truncateStr(s string, n int) string {
	if n <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// validateWatchInterval rejects a non-positive --watch-interval duration
// before it reaches time.NewTicker, which panics on d <= 0. Cobra's
// DurationVar accepts a "0s" or negative duration string without complaint,
// so every --watch command must check this explicitly before starting its
// ticker loop.
func validateWatchInterval(d time.Duration) error {
	if d <= 0 {
		return fmt.Errorf("--watch-interval must be positive, got %s", d)
	}
	return nil
}

// readCapped reads r fully, refusing input past max bytes rather than
// buffering an unbounded amount of memory. Used for every stdin/file read of
// externally-supplied content (a pasted blob, a remote snapshot, a piped
// capture) where the source is not trusted just because a human ran the
// command — a huge or maliciously large input must fail fast, not OOM dsd.
func readCapped(r io.Reader, max int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("input exceeds maximum size of %d bytes", max)
	}
	return data, nil
}

// readCappedFile is readCapped for a file path.
func readCappedFile(path string, max int64) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-supplied path
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return readCapped(f, max)
}
