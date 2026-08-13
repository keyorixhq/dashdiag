package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestCheckRAID_ReadFailedNotSilentlyAbsent: internal-models-11-01. /proc/mdstat
// is a kernel-provided virtual file present on virtually every Linux host
// whether or not mdadm arrays are configured — a genuine read failure (non-
// ENOENT: permission, hardened LSM policy, procfs oddities) must not read
// identically to the confirmed-clean "no RAID configured" result. It must
// surface as an unverified INFO, never fold to the same "" (no concern) a
// genuinely RAID-less host gets.
func TestCheckRAID_ReadFailedNotSilentlyAbsent(t *testing.T) {
	t.Parallel()

	insights := checkRAID(models.RAIDInfo{ReadFailed: true})
	assertLevel(t, insights, "INFO")
	if len(insights) != 1 || !insights[0].Unverified {
		t.Fatalf("expected a single Unverified INFO insight, got %+v", insights)
	}
}

// TestCheckRAID_NoArraysConfigured confirms the genuinely-clean case (mdstat
// read fine, zero arrays) still stays silent — the fix must not introduce
// noise on the common "no RAID" host.
func TestCheckRAID_NoArraysConfigured(t *testing.T) {
	t.Parallel()

	insights := checkRAID(models.RAIDInfo{})
	if len(insights) != 0 {
		t.Fatalf("expected no insights for a clean read with no arrays, got %+v", insights)
	}
}

// TestCheckRAID_ReadFailedDoesNotSuppressRealFindings: a ReadFailed disclosure
// must be ADDITIONAL to any real finding, never a replacement — if a partial
// read still parsed some array data before failing, whatever CRIT/WARN that
// data warrants must still fire alongside the disclosure.
func TestCheckRAID_ReadFailedDoesNotSuppressRealFindings(t *testing.T) {
	t.Parallel()

	insights := checkRAID(models.RAIDInfo{
		ReadFailed: true,
		Arrays: []models.RAIDDevice{
			{Name: "md0", Level: "raid1", State: "degraded", Active: 1, Total: 2},
		},
	})
	assertLevel(t, insights, "CRIT")
	if len(insights) != 2 {
		t.Fatalf("expected both the ReadFailed disclosure and the real CRIT, got %+v", insights)
	}
}
