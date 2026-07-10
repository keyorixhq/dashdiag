//go:build linux

package collectors

import (
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestMarkCVEStaleMetadata_NilAndEmptyPackageManager guards the two early-exit
// guards markCVEStaleMetadataSetsScanFailed doesn't reach: a nil result must
// pass through as nil (no panic), and an empty PackageManager (a result that
// never resolved to a manager) must be returned unchanged, never touched by
// the age lookup.
func TestMarkCVEStaleMetadata_NilAndEmptyPackageManager(t *testing.T) {
	t.Parallel()
	if got := markCVEStaleMetadata(nil); got != nil {
		t.Errorf("expected nil passthrough for a nil result, got %+v", got)
	}

	r := &models.CVEAllResult{PackageManager: "", Total: 0, StatusReason: "no pending security advisories"}
	got := markCVEStaleMetadata(r)
	if got.ScanFailed {
		t.Errorf("empty PackageManager must not be downgraded, got %+v", got)
	}
}

// TestMarkCVEStaleMetadata_NonCleanReasonPassesThrough guards the branch where
// Total==0 but the StatusReason doesn't match any of the "clean" markers (e.g.
// an already-failed scan with its own distinct reason) — must pass through
// unmodified, not get re-labeled as a stale-metadata downgrade.
func TestMarkCVEStaleMetadata_NonCleanReasonPassesThrough(t *testing.T) {
	t.Parallel()
	r := &models.CVEAllResult{
		PackageManager: "apt",
		Total:          0,
		StatusReason:   "apt-get --simulate upgrade failed: network unreachable",
		ScanFailed:     true,
	}
	got := markCVEStaleMetadata(r)
	if got.StatusReason != r.StatusReason {
		t.Errorf("a non-clean reason must pass through unchanged, got %q", got.StatusReason)
	}
}

// TestMarkCVEStaleMetadata_StaleIndexDowngraded guards the age>threshold
// downgrade: a clean "up to date" apt result backed by a cache file older than
// packageMetadataStaleDays must be downgraded to "NOT verified" with an age in
// the message, and ScanFailed set (the #565 false-OK class).
func TestMarkCVEStaleMetadata_StaleIndexDowngraded(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		old := time.Now().Add(-30 * 24 * time.Hour)
		b.PutGlob("/var/lib/apt/lists/*InRelease", []string{"/var/lib/apt/lists/example_InRelease"})
		b.PutGlob("/var/lib/apt/lists/*Release", nil)
		b.PutGlob("/var/lib/apt/lists/*_Packages*", nil)
		b.PutStat("/var/lib/apt/lists/example_InRelease", source.FileMeta{ModTime: old})
	})
	r := &models.CVEAllResult{
		PackageManager: "apt",
		Total:          0,
		StatusReason:   "no pending security advisories — system is up to date",
	}
	got := markCVEStaleMetadata(r)
	if !got.ScanFailed {
		t.Fatalf("a 30-day-stale index must set ScanFailed, got %+v", got)
	}
	if !strings.Contains(got.StatusReason, "stale") || !strings.Contains(got.StatusReason, "30 days") {
		t.Errorf("StatusReason = %q, want it to mention 'stale' and the 30-day age", got.StatusReason)
	}
}

// TestMarkCVEStaleMetadata_FreshIndexNotDowngraded guards the found-and-fresh
// case: a clean result backed by a cache file well under the stale threshold
// must NOT be downgraded — the confident green result is the correct one.
func TestMarkCVEStaleMetadata_FreshIndexNotDowngraded(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		fresh := time.Now().Add(-1 * time.Hour)
		b.PutGlob("/var/lib/apt/lists/*InRelease", []string{"/var/lib/apt/lists/example_InRelease"})
		b.PutGlob("/var/lib/apt/lists/*Release", nil)
		b.PutGlob("/var/lib/apt/lists/*_Packages*", nil)
		b.PutStat("/var/lib/apt/lists/example_InRelease", source.FileMeta{ModTime: fresh})
	})
	r := &models.CVEAllResult{
		PackageManager: "apt",
		Total:          0,
		StatusReason:   "no pending security advisories — system is up to date",
	}
	got := markCVEStaleMetadata(r)
	if got.ScanFailed {
		t.Errorf("a fresh index must not be downgraded, got %+v", got)
	}
	if got.StatusReason != r.StatusReason {
		t.Errorf("StatusReason should be left untouched, got %q", got.StatusReason)
	}
}
