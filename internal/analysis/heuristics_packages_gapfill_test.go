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
