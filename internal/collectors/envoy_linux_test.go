//go:build linux

package collectors

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestParseEnvoyMembership guards the cluster health-membership derivation
// from Envoy's /stats admin output: a cluster with no total members recorded
// is skipped (never queried), a fully-down cluster increments
// FullyDownClusters, and a degraded (partially healthy) cluster is sampled
// for the summary message.
func TestParseEnvoyMembership(t *testing.T) {
	stats := "cluster.backend_a.membership_total: 3\n" +
		"cluster.backend_a.membership_healthy: 3\n" +
		"cluster.backend_b.membership_total: 4\n" +
		"cluster.backend_b.membership_healthy: 1\n" +
		"cluster.backend_c.membership_total: 0\n" + // no members configured — skipped
		"cluster.backend_d.membership_total: 2\n" +
		"cluster.backend_d.membership_healthy: 0\n" // fully down
	info := &models.EnvoyInfo{}
	parseEnvoyMembership(stats, info)

	if info.ClustersTotal != 3 {
		t.Errorf("expected 3 clusters counted (backend_c with 0 total skipped), got %d", info.ClustersTotal)
	}
	if info.UpstreamsTotal != 9 || info.UpstreamsHealthy != 4 {
		t.Errorf("upstream totals should sum backend_a+b+d, got total=%d healthy=%d", info.UpstreamsTotal, info.UpstreamsHealthy)
	}
	if info.FullyDownClusters != 1 {
		t.Errorf("backend_d (0 healthy) should count as fully down, got %d", info.FullyDownClusters)
	}
	if info.DegradedSample == "" {
		t.Error("a degraded (partially healthy) cluster should populate DegradedSample")
	}
}
