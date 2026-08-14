package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestCheckVault_IdentityUnverified is the regression test for
// internal-collectors-33-05: vaultProbeBase only confirmed a non-empty HTTP
// response, not that the responder is really Vault — spoofable by any
// unprivileged local process binding :8200 first. A fully-healthy-looking
// spoofed response must still disclose the unverified identity, not read as
// silently clean.
func TestCheckVault_IdentityUnverified(t *testing.T) {
	t.Parallel()

	got := checkVault(models.VaultInfo{
		Available: true, Reachable: true, StatusRead: true,
		Initialized: true, TLSEnabled: true, IdentityUnverified: true,
	})
	if !insightWithMsg(got, "INFO", "identity could not be confirmed") {
		t.Errorf("expected an identity-unverified disclosure, got %+v", got)
	}
}

// TestCheckVault_IdentityVerified_NoExtraNoise confirms no disclosure when
// identity IS confirmed — must not introduce noise for the common,
// legitimately-verified case.
func TestCheckVault_IdentityVerified_NoExtraNoise(t *testing.T) {
	t.Parallel()

	got := checkVault(models.VaultInfo{
		Available: true, Reachable: true, StatusRead: true,
		Initialized: true, TLSEnabled: true, IdentityUnverified: false,
	})
	if len(got) != 0 {
		t.Errorf("expected no insights for a verified-healthy Vault, got %+v", got)
	}
}

// TestCheckVault_IdentityUnverifiedDoesNotSuppressRealFindings: the
// disclosure must be ADDITIVE, never a replacement — a real Sealed CRIT must
// still fire alongside the identity disclosure.
func TestCheckVault_IdentityUnverifiedDoesNotSuppressRealFindings(t *testing.T) {
	t.Parallel()

	got := checkVault(models.VaultInfo{
		Available: true, Reachable: true, StatusRead: true,
		Sealed: true, IdentityUnverified: true,
	})
	assertLevel(t, got, "CRIT")
	if !insightWithMsg(got, "INFO", "identity could not be confirmed") {
		t.Errorf("expected the identity disclosure alongside the Sealed CRIT, got %+v", got)
	}
}
