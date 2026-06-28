//go:build linux

package collectors

import (
	"context"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
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

// TestScanAllViaPackageManagerNoPM: when NO supported package manager is present,
// the dispatch fallback must mark ScanFailed — dsd couldn't scan at all, so it must
// not render the green ✅ that reads as "no CVEs / you're fine" (false-OK found by
// auditing the `cve --all` family). An empty replay source makes every lookPath miss,
// so this is deterministic regardless of what's installed on the test host.
func TestScanAllViaPackageManagerNoPM(t *testing.T) {
	defer SetSource(SetSource(source.NewReplay(source.NewBundle())))
	res := scanAllViaPackageManager(context.Background())
	if res == nil {
		t.Fatal("expected a result, got nil")
	}
	if !res.ScanFailed {
		t.Errorf("no-package-manager fallback must set ScanFailed (else green ✅ false-OK); reason=%q", res.StatusReason)
	}
	if !strings.Contains(res.StatusReason, "NOT verified") {
		t.Errorf("no-package-manager reason should say NOT verified, got %q", res.StatusReason)
	}
}
