package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestCheckPackageDBHealth_EmptyReason covers the empty DBBlockReason branch
// in checkPackageDBHealth (line 89-91): when the reason field is blank the
// function substitutes a generic default message.
func TestCheckPackageDBHealth_EmptyReason(t *testing.T) {
	t.Parallel()
	pkg := models.PackagesInfo{
		Checked:          true,
		DBHealthChecked:  true,
		DBUpdatesBlocked: true,
		DBBlockReason:    "", // empty → must use the default
	}
	got := checkPackageDBHealth(pkg)
	if len(got) == 0 {
		t.Fatal("expected a WARN insight, got none")
	}
	const want = "the package database is in a state that blocks updates"
	if !strings.Contains(got[0].Message, want) {
		t.Errorf("empty reason must fall back to %q, got %q", want, got[0].Message)
	}
}

// TestCheckPackageDBHealth_ProbeFailed is the regression test for the
// false-OK fix: a recognized package manager whose DB/lock probe itself
// couldn't run (DBHealthChecked=false — dpkg unusable, no rpm binary, or the
// probe never got a turn) must disclose an INFO, not silently read the same
// as "checked, clean" (both leave DBUpdatesBlocked at its false zero value).
func TestCheckPackageDBHealth_ProbeFailed(t *testing.T) {
	t.Parallel()
	got := checkPackageDBHealth(models.PackagesInfo{PackageManager: "apt", DBHealthChecked: false})
	if len(got) == 0 || got[0].Level != "INFO" || !strings.Contains(got[0].Message, "could not be checked") {
		t.Errorf("unchecked DB health on a recognized package manager must INFO, got %+v", got)
	}
}

// TestCheckPackageDBHealth_NoPackageManager_NoSpuriousDisclosure is the
// control: a host with no recognized package manager at all (Collect()'s
// PackageManager="unknown" early-return, or the zero-value "" in a bare
// struct) never runs the DB-health probe by design — DBHealthChecked=false
// there is legitimate and must NOT trigger the new disclosure.
func TestCheckPackageDBHealth_NoPackageManager_NoSpuriousDisclosure(t *testing.T) {
	t.Parallel()
	for _, pm := range []string{"", "unknown"} {
		got := checkPackageDBHealth(models.PackagesInfo{PackageManager: pm, DBHealthChecked: false})
		if len(got) != 0 {
			t.Errorf("PackageManager=%q must not disclose a DB-health gap, got %+v", pm, got)
		}
	}
}

// TestCheckPackageUpdates_UnrecognizedStatus covers a pkg.Status value outside
// the three known sentinels ("no-security-repo"/"query-failed"/"stale-metadata")
// — e.g. a future collector change or a tampered/corrupted `dsd replay` bundle.
// It must render as an unverified INFO, not fall through to the same silent
// "0 security updates" result a genuinely clean scan produces.
func TestCheckPackageUpdates_UnrecognizedStatus(t *testing.T) {
	t.Parallel()
	pkg := models.PackagesInfo{
		Checked:         true,
		Status:          "garbled-status",
		SecurityUpdates: 0,
	}
	got := checkPackageUpdates(pkg)
	if len(got) == 0 {
		t.Fatal("expected an unverified INFO insight, got none (silent false-OK)")
	}
	if got[0].Level != "INFO" {
		t.Errorf("unrecognized status must be INFO, got %q", got[0].Level)
	}
	if !strings.Contains(got[0].Message, "unrecognized scan status") {
		t.Errorf("message must disclose the unrecognized status, got %q", got[0].Message)
	}
}

// TestSecurityUpdateInsight_ImportantUpdates covers the ImportantUpdates > 0
// branch in securityUpdateInsight (lines 213-217): managers that expose per-
// advisory severity (dnf/zypper) emit a WARN for important (non-critical) advisories.
func TestSecurityUpdateInsight_ImportantUpdates(t *testing.T) {
	t.Parallel()
	pkg := models.PackagesInfo{
		PackageManager:   "dnf",
		SecurityUpdates:  5,
		ImportantUpdates: 3,
		CriticalUpdates:  0,
	}
	got := securityUpdateInsight(pkg)
	if len(got) == 0 {
		t.Fatal("expected an insight for important updates, got none")
	}
	if got[0].Level != "WARN" {
		t.Errorf("important updates must be WARN, got %q", got[0].Level)
	}
	if !strings.Contains(got[0].Message, "important") {
		t.Errorf("message must mention 'important', got %q", got[0].Message)
	}
}

// TestCheckPackageUpdates_ESMWithZeroSecurityUpdates covers the ESM-only branch
// in checkPackageUpdates (line 160-168): when SecurityUpdates == 0 but ESMUpdates > 0
// a standalone WARN for the ESM-gated updates is emitted.
func TestCheckPackageUpdates_ESMWithZeroSecurityUpdates(t *testing.T) {
	t.Parallel()
	pkg := models.PackagesInfo{
		Checked:         true,
		PackageManager:  "apt",
		SecurityUpdates: 0,
		ESMUpdates:      4,
	}
	got := checkPackageUpdates(pkg)
	if len(got) == 0 {
		t.Fatal("expected a WARN for ESM-only updates, got none")
	}
	if got[0].Level != "WARN" {
		t.Errorf("ESM-only updates must be WARN, got %q", got[0].Level)
	}
	if !strings.Contains(got[0].Message, "ESM") && !strings.Contains(got[0].Message, "Pro") {
		t.Errorf("ESM insight must mention ESM or Pro, got %q", got[0].Message)
	}
}

// TestCheckPackageUpdates_ESMWithSecurityUpdates covers the ESM + security updates
// combined path (line 160-168): when both SecurityUpdates and ESMUpdates are > 0
// the function emits the normal security-update insight AND the ESM WARN.
func TestCheckPackageUpdates_ESMWithSecurityUpdates(t *testing.T) {
	t.Parallel()
	pkg := models.PackagesInfo{
		Checked:         true,
		PackageManager:  "apt",
		SecurityUpdates: 2,
		ESMUpdates:      3,
	}
	got := checkPackageUpdates(pkg)
	foundESM := false
	for _, ins := range got {
		if strings.Contains(ins.Message, "ESM") || strings.Contains(ins.Message, "Pro") {
			foundESM = true
		}
	}
	if !foundESM {
		t.Errorf("combined path must still emit an ESM insight, got %+v", got)
	}
}
