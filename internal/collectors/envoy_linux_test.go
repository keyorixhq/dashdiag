//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestEnvoyCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewEnvoyCollector()
	if c.Name() != "Envoy" {
		t.Errorf("Name() = %q, want Envoy", c.Name())
	}
	if c.Timeout() != 5*time.Second {
		t.Errorf("Timeout() = %v, want 5s", c.Timeout())
	}
}

func TestEnvoyAvailable_NotReachable(t *testing.T) {
	withCombinedFixture(t, nil, nil, nil)
	if EnvoyAvailable() {
		t.Error("expected false when 9901 is unreachable")
	}
}

func TestEnvoyAvailable_ReachableButNoState(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:9901":                 {'1'},
		"http/http://127.0.0.1:9901/server_info":  promHTTPResult(t, `{"version":"1.30"}`, 200),
		"http/https://127.0.0.1:9901/server_info": promHTTPResult(t, `{"version":"1.30"}`, 200),
	}, nil, nil)
	if EnvoyAvailable() {
		t.Error("expected false when server_info has no state field")
	}
}

func TestEnvoyAvailable_ReachableHTTP(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:9901":                {'1'},
		"http/http://127.0.0.1:9901/server_info": promHTTPResult(t, `{"version":"1.30.1","state":"LIVE"}`, 200),
	}, nil, nil)
	if !EnvoyAvailable() {
		t.Error("expected true when server_info reports a state")
	}
}

func TestDetectEnvoy_HTTPSFallback(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:9901":                 {'1'},
		"http/http://127.0.0.1:9901/server_info":  promHTTPResult(t, ``, 500),
		"http/https://127.0.0.1:9901/server_info": promHTTPResult(t, `{"version":"1.30.1","state":"LIVE"}`, 200),
	}, nil, nil)
	base, info := detectEnvoy(context.Background())
	if base != "https://127.0.0.1:9901" {
		t.Errorf("base = %q, want https fallback", base)
	}
	if info == nil || info.State != "LIVE" {
		t.Errorf("info = %+v, want State=LIVE", info)
	}
}

func TestEnvoyCollector_Collect_NotDetected(t *testing.T) {
	withCombinedFixture(t, nil, nil, nil)
	c := NewEnvoyCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.EnvoyInfo)
	if info.Detected {
		t.Errorf("info = %+v, want Detected=false", info)
	}
}

func TestEnvoyCollector_Collect_StatsUnreachable(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:9901":                                            {'1'},
		"http/http://127.0.0.1:9901/server_info":                             promHTTPResult(t, `{"version":"1.30","state":"LIVE"}`, 200),
		"http/http://127.0.0.1:9901/stats?filter=membership_(healthy|total)": promHTTPResult(t, ``, 500),
	}, nil, nil)
	c := NewEnvoyCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.EnvoyInfo)
	if !info.Detected {
		t.Fatal("Detected = false, want true")
	}
	if info.StatsRead {
		t.Error("StatsRead = true, want false when /stats is unreachable")
	}
	if info.StatusReason == "" {
		t.Error("expected a StatusReason when cluster stats could not be read")
	}
}

func TestEnvoyCollector_Collect_FullHappyPath(t *testing.T) {
	stats := "cluster.foo.membership_healthy: 2\n" +
		"cluster.foo.membership_total: 2\n" +
		"cluster.bar.membership_healthy: 0\n" +
		"cluster.bar.membership_total: 3\n"
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:9901":                                            {'1'},
		"http/http://127.0.0.1:9901/server_info":                             promHTTPResult(t, `{"version":"1.30","state":"LIVE"}`, 200),
		"http/http://127.0.0.1:9901/stats?filter=membership_(healthy|total)": promHTTPResult(t, stats, 200),
	}, nil, nil)
	c := NewEnvoyCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.EnvoyInfo)
	if !info.Detected || !info.StatsRead {
		t.Fatalf("info = %+v, want Detected=true StatsRead=true", info)
	}
	if info.ClustersTotal != 2 || info.UpstreamsTotal != 5 || info.UpstreamsHealthy != 2 {
		t.Errorf("cluster totals mismatch: %+v", info)
	}
	if info.FullyDownClusters != 1 {
		t.Errorf("FullyDownClusters = %d, want 1", info.FullyDownClusters)
	}
	if info.DegradedSample != `cluster "bar": 0/3 hosts healthy` {
		t.Errorf("DegradedSample = %q", info.DegradedSample)
	}
}

func TestEnvoyStatValue(t *testing.T) {
	t.Parallel()
	tests := []struct {
		line string
		want int
	}{
		{"cluster.foo.membership_healthy: 3", 3},
		{"cluster.foo.membership_healthy:not-a-number", 0},
		{"no colon here", 0},
	}
	for _, tt := range tests {
		if got := envoyStatValue(tt.line); got != tt.want {
			t.Errorf("envoyStatValue(%q) = %d, want %d", tt.line, got, tt.want)
		}
	}
}

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
