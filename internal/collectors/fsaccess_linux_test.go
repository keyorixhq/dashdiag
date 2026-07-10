//go:build linux

package collectors

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestNowViaSource_MalformedCachedTimestamp covers the time.Parse error
// branch: a Cached "__wallclock_now__" value that isn't a valid RFC3339Nano
// timestamp (a corrupted/hand-edited capture bundle) must fall back to the
// live clock rather than propagating a parse error or a zero time.
func TestNowViaSource_MalformedCachedTimestamp(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"__wallclock_now__": []byte("not-a-timestamp"),
	}, nil, func(b *source.Bundle) {})

	got := NowViaSource()
	if got.IsZero() {
		t.Fatal("NowViaSource() returned the zero time, want a live-clock fallback")
	}
}
