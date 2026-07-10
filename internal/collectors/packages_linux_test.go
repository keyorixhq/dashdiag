//go:build linux

package collectors

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// markStaleMetadata must only downgrade a genuinely-clean "0 updates" result to
// unverified — never override a real finding or an existing status, and never flag
// a manager whose cache layout we don't read.
func TestMarkStaleMetadata_Guards(t *testing.T) {
	// Updates found → a real result, never a confidence gap.
	i1 := &models.PackagesInfo{Checked: true, SecurityUpdates: 3, PackageManager: "apt"}
	markStaleMetadata(i1)
	if i1.Status == "stale-metadata" {
		t.Error("must not flag stale when security updates were found")
	}

	// Existing status (e.g. no-security-repo) must be preserved.
	i2 := &models.PackagesInfo{Checked: true, SecurityUpdates: 0, Status: "no-security-repo", PackageManager: "apt"}
	markStaleMetadata(i2)
	if i2.Status != "no-security-repo" {
		t.Errorf("must not override existing status, got %q", i2.Status)
	}

	// A manager whose cache layout we don't read must not be flagged.
	i3 := &models.PackagesInfo{Checked: true, SecurityUpdates: 0, PackageManager: "pacman"}
	markStaleMetadata(i3)
	if i3.Status == "stale-metadata" {
		t.Error("must not flag a manager whose cache layout is unknown")
	}

	// Never queried → nothing to confirm or deny.
	i4 := &models.PackagesInfo{Checked: false, PackageManager: "apt"}
	markStaleMetadata(i4)
	if i4.Status == "stale-metadata" {
		t.Error("must not flag when the manager was never queried")
	}
}

func TestSupportedMetadataManager(t *testing.T) {
	for _, pm := range []string{"apt", "dnf", "yum", "zypper"} {
		if !supportedMetadataManager(pm) {
			t.Errorf("%s should be a supported metadata manager", pm)
		}
	}
	for _, pm := range []string{"brew", "pacman", "unknown", ""} {
		if supportedMetadataManager(pm) {
			t.Errorf("%s should NOT be a supported metadata manager", pm)
		}
	}
}

func TestZypperLocked(t *testing.T) {
	// The real zypp-lock messages (exit 7) — must be detected so collectZypper
	// retries instead of false-reporting "could not verify" while patches are pending.
	locked := []string{
		"System management is locked by the application with pid 4070 (/usr/bin/zypper).",
		"System management is locked by the application with pid 4215 (zypper).",
		"error: /run/zypp.pid is held by another process",
	}
	for _, s := range locked {
		if !zypperLocked(s) {
			t.Errorf("expected lock detected for: %q", s)
		}
	}
	notLocked := []string{
		"28 patches needed (28 security patches)",
		"No updates found.",
		"",
	}
	for _, s := range notLocked {
		if zypperLocked(s) {
			t.Errorf("expected NOT locked for: %q", s)
		}
	}
}

// TestMarkStaleMetadata_FreshCache guards the "trustworthy" branch: a
// supported manager with a cache file younger than packageMetadataStaleDays
// must NOT be flagged stale.
func TestMarkStaleMetadata_FreshCache(t *testing.T) {
	b := source.NewBundle()
	b.PutGlob("/var/lib/apt/lists/*InRelease", []string{"/var/lib/apt/lists/deb.debian.org_debian_InRelease"})
	b.PutStat("/var/lib/apt/lists/deb.debian.org_debian_InRelease", source.FileMeta{
		ModTime: time.Now().Add(-1 * time.Hour),
	})
	prev := SetSource(source.NewReplay(b))
	defer SetSource(prev)

	info := &models.PackagesInfo{Checked: true, PackageManager: "apt"}
	markStaleMetadata(info)
	if info.Status == "stale-metadata" {
		t.Errorf("expected fresh cache to NOT be flagged stale, got Status=%q MetadataAgeDays=%d", info.Status, info.MetadataAgeDays)
	}
}

// TestMarkStaleMetadata_StaleCache guards the "too old to trust" branch: a
// cache file older than packageMetadataStaleDays must flag the clean 0-updates
// result as unverified, with MetadataAgeDays and a day-count StatusReason.
func TestMarkStaleMetadata_StaleCache(t *testing.T) {
	b := source.NewBundle()
	b.PutGlob("/var/cache/dnf/*/repodata/repomd.xml", []string{"/var/cache/dnf/updates/repodata/repomd.xml"})
	b.PutStat("/var/cache/dnf/updates/repodata/repomd.xml", source.FileMeta{
		ModTime: time.Now().Add(-10 * 24 * time.Hour),
	})
	prev := SetSource(source.NewReplay(b))
	defer SetSource(prev)

	info := &models.PackagesInfo{Checked: true, PackageManager: "dnf"}
	markStaleMetadata(info)
	if info.Status != "stale-metadata" {
		t.Fatalf("expected stale-metadata status, got %q", info.Status)
	}
	if info.MetadataAgeDays < 10 {
		t.Errorf("MetadataAgeDays = %d, want >= 10", info.MetadataAgeDays)
	}
	if !strings.Contains(info.StatusReason, "days old") || !strings.Contains(info.StatusReason, "cannot confirm") {
		t.Errorf("StatusReason = %q, want an age-based message", info.StatusReason)
	}
}

// TestMarkStaleMetadata_NoCacheFound guards the "found=false" branch: a
// supported manager with NO cache files at all must flag stale with
// MetadataAgeDays=-1 and a "not found" reason (never a fabricated age).
func TestMarkStaleMetadata_NoCacheFound(t *testing.T) {
	prev := SetSource(source.NewReplay(source.NewBundle())) // no globs seeded — every glob misses
	defer SetSource(prev)

	info := &models.PackagesInfo{Checked: true, PackageManager: "zypper"}
	markStaleMetadata(info)
	if info.Status != "stale-metadata" {
		t.Fatalf("expected stale-metadata status, got %q", info.Status)
	}
	if info.MetadataAgeDays != -1 {
		t.Errorf("MetadataAgeDays = %d, want -1 when no cache is found", info.MetadataAgeDays)
	}
	if !strings.Contains(info.StatusReason, "not found") {
		t.Errorf("StatusReason = %q, want a not-found message", info.StatusReason)
	}
}

// ── checkESMUpdates ────────────────────────────────────────────────────────

func TestCheckESMUpdates_NotInstalled(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("pro", []string{"security-status", "--format", "json"})
	})
	info := &models.PackagesInfo{}
	checkESMUpdates(context.Background(), info)
	if info.ESMUpdates != 0 {
		t.Errorf("expected ESMUpdates=0 when pro is not installed, got %d", info.ESMUpdates)
	}
}

// realProSecurityStatusJSON mirrors `pro security-status --format json`'s real
// pretty-printed shape (one field per line) — checkESMUpdates scans line-by-
// line for the two num_esm_*_updates keys, so a single-line/compact JSON
// fixture would make both key-checks match the SAME line and double-count.
const realProSecurityStatusJSON = `{
  "summary": {
    "num_esm_apps_updates": 3,
    "num_esm_infra_updates": 2
  }
}
`

func TestCheckESMUpdates_Populates(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("pro", []string{"security-status", "--format", "json"}, realProSecurityStatusJSON, 0)
	})
	info := &models.PackagesInfo{}
	checkESMUpdates(context.Background(), info)
	if info.ESMUpdates != 5 {
		t.Errorf("ESMUpdates = %d, want 5 (3 apps + 2 infra)", info.ESMUpdates)
	}
}

func TestCheckESMUpdates_ZeroUpdates(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("pro", []string{"security-status", "--format", "json"},
			"{\n  \"summary\": {\n    \"num_esm_apps_updates\": 0,\n    \"num_esm_infra_updates\": 0\n  }\n}\n", 0)
	})
	info := &models.PackagesInfo{}
	checkESMUpdates(context.Background(), info)
	if info.ESMUpdates != 0 {
		t.Errorf("ESMUpdates = %d, want 0", info.ESMUpdates)
	}
}
