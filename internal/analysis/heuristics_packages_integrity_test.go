package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestPackageIntegrityNotGatedByUpdateStatus guards the false-OK fix: package
// integrity (broken packages / unmet deps) must be evaluated regardless of the
// security-update verdict. It used to be skipped by the early returns for a
// fully-patched host (SecurityUpdates==0), stale metadata, or a failed query —
// so broken deps on a common (patched or stale) host read clean.
func TestPackageIntegrityNotGatedByUpdateStatus(t *testing.T) {
	unmet := &models.PackageIntegrity{UnmetDeps: []string{"foo : Depends: bar but it is not installed"}}
	broken := &models.PackageIntegrity{BrokenPackages: []string{"pkg1 is in a bad state"}}

	cases := []struct {
		name string
		pkg  models.PackagesInfo
		want string // substring that must appear as a CRIT
	}{
		{"fully patched + unmet deps",
			models.PackagesInfo{PackageManager: "apt", SecurityUpdates: 0, Integrity: unmet}, "unmet dependency"},
		{"stale metadata + broken pkgs",
			models.PackagesInfo{PackageManager: "apt", Status: "stale-metadata", Integrity: broken}, "broken/inconsistent"},
		{"query failed + unmet deps",
			models.PackagesInfo{PackageManager: "apt", Status: "query-failed", Integrity: unmet}, "unmet dependency"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !insightWithMsg(checkPackages(c.pkg), "CRIT", c.want) {
				t.Errorf("integrity CRIT %q must fire under %q, got %+v", c.want, c.name, checkPackages(c.pkg))
			}
		})
	}

	// A clean integrity result on a patched host must NOT manufacture a concern.
	clean := checkPackages(models.PackagesInfo{
		PackageManager: "apt", SecurityUpdates: 0,
		Integrity: &models.PackageIntegrity{LdconfigOK: true},
	})
	for _, ins := range clean {
		if ins.Level == "CRIT" || ins.Level == "WARN" {
			t.Errorf("clean integrity must not warn/crit, got %+v", clean)
		}
	}
}
