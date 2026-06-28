//go:build linux

package collectors

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestMarkCVEStaleMetadataSetsScanFailed: when markCVEStaleMetadata downgrades a
// clean Total==0 result to "exposure NOT verified" (absent/stale index), it must
// set ScanFailed so the renderer shows an unverified ⚠️ rather than a green ✅.
// Without it a 781-day-stale apt index read as "you're fine" — the #565 false-OK
// class, found live on Ubuntu 24.04. Uses a package manager whose cache layout
// packageMetadataAgeDays does not read (returns found=false deterministically on
// every host, including CI runners that DO carry fresh apt metadata).
func TestMarkCVEStaleMetadataSetsScanFailed(t *testing.T) {
	clean := &models.CVEAllResult{
		PackageManager: "brew", // default case → (-1,false): metadata never "found"
		Total:          0,
		StatusReason:   "no pending security advisories — system is up to date",
	}
	got := markCVEStaleMetadata(clean)
	if !strings.Contains(got.StatusReason, "NOT verified") {
		t.Fatalf("expected a 'NOT verified' downgrade, got %q", got.StatusReason)
	}
	if !got.ScanFailed {
		t.Errorf("a downgraded-to-unverified result must set ScanFailed (else it renders a green ✅); reason=%q", got.StatusReason)
	}

	// A result with real findings is never downgraded or marked failed.
	withFindings := &models.CVEAllResult{PackageManager: "brew", Total: 3}
	if got := markCVEStaleMetadata(withFindings); got.ScanFailed {
		t.Error("a result with findings (Total>0) must not be marked ScanFailed")
	}
}
