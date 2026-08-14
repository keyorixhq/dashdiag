package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestCheckEnvoy_IdentityUnverified is the regression test for
// internal-collectors-12-01 / internal-analysis-03-03: detectEnvoy's identity
// check (a {version,state} JSON shape match) can be spoofed by any
// unprivileged local process binding :9901 first. A fully-healthy-looking
// spoofed response must still disclose the unverified identity, not read as
// silently clean.
func TestCheckEnvoy_IdentityUnverified(t *testing.T) {
	t.Parallel()

	got := checkEnvoy(models.EnvoyInfo{
		Detected: true, StatsRead: true, ClustersTotal: 3,
		UpstreamsTotal: 6, UpstreamsHealthy: 6, IdentityUnverified: true,
	})
	if !insightWithMsg(got, "INFO", "identity could not be confirmed") {
		t.Errorf("expected an identity-unverified disclosure, got %+v", got)
	}
}

// TestCheckEnvoy_IdentityVerified_NoExtraNoise confirms no disclosure when
// identity IS confirmed — must not introduce noise for the common,
// legitimately-verified case.
func TestCheckEnvoy_IdentityVerified_NoExtraNoise(t *testing.T) {
	t.Parallel()

	got := checkEnvoy(models.EnvoyInfo{
		Detected: true, StatsRead: true, ClustersTotal: 3,
		UpstreamsTotal: 6, UpstreamsHealthy: 6, IdentityUnverified: false,
	})
	if len(got) != 0 {
		t.Errorf("expected no insights for a verified-healthy Envoy, got %+v", got)
	}
}

// TestCheckEnvoy_ImplausibleHealthyCount is the regression test for
// internal-analysis-03-03's plausibility-bound gap: UpstreamsHealthy greater
// than UpstreamsTotal is impossible from a real Envoy (malformed response or
// a spoofed one) and must not silently compute a negative "down" count and
// fall through as healthy.
func TestCheckEnvoy_ImplausibleHealthyCount(t *testing.T) {
	t.Parallel()

	got := checkEnvoy(models.EnvoyInfo{
		Detected: true, StatsRead: true, ClustersTotal: 1,
		UpstreamsTotal: 2, UpstreamsHealthy: 5,
	})
	if !insightWithMsg(got, "INFO", "impossible count") {
		t.Errorf("expected an implausible-count disclosure, got %+v", got)
	}
}
