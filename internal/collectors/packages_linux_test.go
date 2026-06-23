//go:build linux

package collectors

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
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
