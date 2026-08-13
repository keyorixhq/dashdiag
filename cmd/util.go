package cmd

import (
	"fmt"
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
