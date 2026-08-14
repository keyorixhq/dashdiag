package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestCheckDiskExtras_DrivesListUnreadable: DiskInfo.DrivesListUnreadable
// (macOS only) is set when `diskutil list` itself failed or returned no
// output, which produces the identical empty Drives slice a genuine
// zero-physical-drives host would — impossible on real Mac hardware, but the
// analysis layer has no way to tell the two apart without this signal. It
// must surface as an unverified INFO, never fold to silence.
func TestCheckDiskExtras_DrivesListUnreadable(t *testing.T) {
	t.Parallel()

	insights := checkDiskExtras(models.DiskInfo{DrivesListUnreadable: true})
	assertLevel(t, insights, "INFO")
	if len(insights) != 1 || !insights[0].Unverified {
		t.Fatalf("expected a single Unverified INFO insight, got %+v", insights)
	}
}

// TestCheckDiskExtras_DrivesEnumeratedCleanly confirms the genuinely-clean
// case (diskutil list succeeded, drives parsed, no SMART concerns) stays
// silent — the fix must not introduce noise on the common healthy host.
func TestCheckDiskExtras_DrivesEnumeratedCleanly(t *testing.T) {
	t.Parallel()

	insights := checkDiskExtras(models.DiskInfo{
		Drives: []models.PhysicalDrive{{Name: "disk0", SMART: &models.SMARTInfo{Healthy: true}}},
	})
	if len(insights) != 0 {
		t.Fatalf("expected no insights for a clean read with healthy SMART, got %+v", insights)
	}
}

// TestCheckDiskExtras_DrivesListUnreadableDoesNotSuppressRealFindings: the
// disclosure must be ADDITIONAL to any real finding, never a replacement.
func TestCheckDiskExtras_DrivesListUnreadableDoesNotSuppressRealFindings(t *testing.T) {
	t.Parallel()

	insights := checkDiskExtras(models.DiskInfo{
		DrivesListUnreadable: true,
		Drives:               []models.PhysicalDrive{{Name: "disk0", SMART: &models.SMARTInfo{Healthy: false}}},
	})
	assertLevel(t, insights, "CRIT")
	if len(insights) != 2 {
		t.Fatalf("expected both the DrivesListUnreadable disclosure and the real CRIT, got %+v", insights)
	}
}
