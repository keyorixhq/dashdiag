package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestSlowBootFix_RemainingCases covers the slowBootFix branches not exercised
// by heuristics_gapfill4_test.go: plymouth, fwupd-refresh, snapd, and apt-daily.
func TestSlowBootFix_RemainingCases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		unit       string
		wantSubstr string
	}{
		{"plymouth-quit-wait.service", "plymouth"},
		{"fwupd-refresh.service", "fwupdmgr"},
		{"snapd.service", "snapd"},
		{"snapd.seeded.service", "snapd"},
		{"apt-daily.service", "apt"},
		{"apt-daily-upgrade.service", "apt"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.unit, func(t *testing.T) {
			t.Parallel()
			got := slowBootFix(tt.unit)
			if len(got) == 0 {
				t.Fatalf("slowBootFix(%q) must return hints, got none", tt.unit)
			}
			found := false
			for _, h := range got {
				if strings.Contains(h, tt.wantSubstr) {
					found = true
				}
			}
			if !found {
				t.Errorf("slowBootFix(%q) hints must mention %q, got %v", tt.unit, tt.wantSubstr, got)
			}
		})
	}
}

// TestExtractAVCProcessNames covers edge cases in extractAVCProcessNames beyond
// the existing TestCheckKernelSecurity_AVCSamples test:
// - a line without comm=" is skipped (the !ok continue at line 409),
// - a line with an empty comm value (end <= 0) is skipped,
// - duplicate comm values are deduplicated.
func TestExtractAVCProcessNames(t *testing.T) {
	t.Parallel()

	// Line with no comm= field → should produce no process name.
	t.Run("no comm field skipped", func(t *testing.T) {
		t.Parallel()
		got := extractAVCProcessNames([]string{`type=AVC msg=audit(1): avc: denied { read }`})
		if len(got) != 0 {
			t.Errorf("line without comm= must yield no process names, got %v", got)
		}
	})

	// Line where the closing quote immediately follows the open quote (empty name).
	t.Run("empty comm value skipped", func(t *testing.T) {
		t.Parallel()
		got := extractAVCProcessNames([]string{`type=AVC msg=audit(1): avc: denied { read } comm="" pid=1`})
		if len(got) != 0 {
			t.Errorf("empty comm value must be skipped, got %v", got)
		}
	})

	// Duplicate comm values must appear only once.
	t.Run("duplicates deduplicated", func(t *testing.T) {
		t.Parallel()
		lines := []string{
			`type=AVC msg=audit(1): avc: denied { read } comm="httpd" pid=1`,
			`type=AVC msg=audit(2): avc: denied { write } comm="httpd" pid=2`,
			`type=AVC msg=audit(3): avc: denied { read } comm="sshd" pid=3`,
		}
		got := extractAVCProcessNames(lines)
		if len(got) != 2 {
			t.Errorf("expected 2 unique process names (httpd, sshd), got %v", got)
		}
	})

	// Mixed: one valid, one missing comm=, one empty comm.
	t.Run("mixed lines", func(t *testing.T) {
		t.Parallel()
		lines := []string{
			`type=AVC msg=audit(1): avc: denied { read } comm="nginx" pid=10`,
			`type=AVC msg=audit(2): avc: denied { write }`,
			`type=AVC msg=audit(3): avc: denied { read } comm="" pid=11`,
		}
		got := extractAVCProcessNames(lines)
		if len(got) != 1 || got[0] != "nginx" {
			t.Errorf("expected [nginx], got %v", got)
		}
	})
}

// TestCheckKernelSecurity_PolicyDirMissing covers the !mac.SELinuxPolicyDirOK
// branch in checkKernelSecurity (line 450-459): a valid SELINUXTYPE whose policy
// directory is absent must CRIT.
func TestCheckKernelSecurity_PolicyDirMissing(t *testing.T) {
	t.Parallel()
	mac := models.KernelSecurityInfo{
		SELinuxPresent:     true,
		SELinuxMode:        "enforcing",
		SELinuxType:        "targeted",
		SELinuxTypeValid:   true,
		SELinuxPolicyDirOK: false, // the missing-dir branch
		SELinuxPolicyPkgOK: true,
	}
	got := checkKernelSecurity(mac, defaultThresh)
	if !hasInsightMsg(got, "CRIT", "policy directory") {
		t.Errorf("missing policy directory must CRIT, got %+v", got)
	}
}

// TestCheckKernelSecurity_PolicyPkgMissing covers the !mac.SELinuxPolicyPkgOK
// branch in checkKernelSecurity (lines 459-466): a valid type whose package is
// absent must CRIT.
func TestCheckKernelSecurity_PolicyPkgMissing(t *testing.T) {
	t.Parallel()
	mac := models.KernelSecurityInfo{
		SELinuxPresent:     true,
		SELinuxMode:        "enforcing",
		SELinuxType:        "targeted",
		SELinuxTypeValid:   true,
		SELinuxPolicyDirOK: true,
		SELinuxPolicyPkgOK: false, // the missing-pkg branch
	}
	got := checkKernelSecurity(mac, defaultThresh)
	if !hasInsightMsg(got, "CRIT", "policy package") {
		t.Errorf("missing policy package must CRIT, got %+v", got)
	}
}
