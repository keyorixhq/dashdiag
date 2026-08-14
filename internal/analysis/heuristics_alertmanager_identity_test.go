package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestCheckAlertmanager_IdentityUnverified is the regression test for
// internal-collectors-01-02: detectAlertmanager's identity check (a JSON
// shape match on /api/v2/status) can be spoofed by any unprivileged local
// process binding :9093 first. A fully-healthy-looking spoofed response must
// still disclose the unverified identity, not read as silently clean.
func TestCheckAlertmanager_IdentityUnverified(t *testing.T) {
	t.Parallel()

	got := checkAlertmanager(models.AlertmanagerInfo{
		Detected: true, StatusRead: true, ConfigReloadRead: true, ConfigReloadOK: true,
		IdentityUnverified: true,
	})
	if !insightWithMsg(got, "INFO", "identity could not be confirmed") {
		t.Errorf("expected an identity-unverified disclosure, got %+v", got)
	}
}

// TestCheckAlertmanager_IdentityVerified_NoExtraNoise confirms no disclosure
// when identity IS confirmed — must not introduce noise for the common,
// legitimately-verified case.
func TestCheckAlertmanager_IdentityVerified_NoExtraNoise(t *testing.T) {
	t.Parallel()

	got := checkAlertmanager(models.AlertmanagerInfo{
		Detected: true, StatusRead: true, ConfigReloadRead: true, ConfigReloadOK: true,
		IdentityUnverified: false,
	})
	if len(got) != 0 {
		t.Errorf("expected no insights for a verified-healthy Alertmanager, got %+v", got)
	}
}
