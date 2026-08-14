package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestCheckGrafana_IdentityUnverified is the regression test for
// internal-collectors-13-01: detectGrafana's identity check (a
// {database,version} JSON shape match) can be spoofed by any unprivileged
// local process binding :3000 first. A fully-healthy-looking spoofed
// response must still disclose the unverified identity, not read as
// silently clean.
func TestCheckGrafana_IdentityUnverified(t *testing.T) {
	t.Parallel()

	got := checkGrafana(models.GrafanaInfo{
		Detected: true, HealthRead: true, DatabaseOK: true, IdentityUnverified: true,
	})
	if !insightWithMsg(got, "INFO", "identity could not be confirmed") {
		t.Errorf("expected an identity-unverified disclosure, got %+v", got)
	}
}

// TestCheckGrafana_IdentityVerified_NoExtraNoise confirms no disclosure when
// identity IS confirmed — must not introduce noise for the common,
// legitimately-verified case.
func TestCheckGrafana_IdentityVerified_NoExtraNoise(t *testing.T) {
	t.Parallel()

	got := checkGrafana(models.GrafanaInfo{
		Detected: true, HealthRead: true, DatabaseOK: true, IdentityUnverified: false,
	})
	if len(got) != 0 {
		t.Errorf("expected no insights for a verified-healthy Grafana, got %+v", got)
	}
}
