//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestAlertmanagerCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewAlertmanagerCollector()
	if c.Name() != "Alertmanager" {
		t.Errorf("Name() = %q, want Alertmanager", c.Name())
	}
	if c.Timeout() != 6*time.Second {
		t.Errorf("Timeout() = %v, want 6s", c.Timeout())
	}
}

func TestAlertmanagerAvailable_NotReachable(t *testing.T) {
	withCombinedFixture(t, nil, nil, nil)
	if AlertmanagerAvailable() {
		t.Error("expected false when 9093 is unreachable")
	}
}

func TestAlertmanagerAvailable_ReachableButNoClusterStatus(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:9093":                   {'1'},
		"http/http://127.0.0.1:9093/api/v2/status":  promHTTPResult(t, `{}`, 200),
		"http/https://127.0.0.1:9093/api/v2/status": promHTTPResult(t, `{}`, 200),
	}, nil, nil)
	if AlertmanagerAvailable() {
		t.Error("expected false when the status response has no cluster.status")
	}
}

func TestAlertmanagerAvailable_ReachableHTTP(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:9093":                  {'1'},
		"http/http://127.0.0.1:9093/api/v2/status": promHTTPResult(t, `{"cluster":{"status":"ready","peers":[{"name":"a"}]},"versionInfo":{"version":"0.27.0"}}`, 200),
	}, nil, nil)
	if !AlertmanagerAvailable() {
		t.Error("expected true when /api/v2/status reports a cluster status")
	}
}

func TestDetectAlertmanager_HTTPSFallback(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:9093":                   {'1'},
		"http/http://127.0.0.1:9093/api/v2/status":  promHTTPResult(t, ``, 500),
		"http/https://127.0.0.1:9093/api/v2/status": promHTTPResult(t, `{"cluster":{"status":"ready","peers":[]},"versionInfo":{"version":"0.27.0"}}`, 200),
	}, nil, nil)
	base, info := detectAlertmanager(context.Background())
	if base != "https://127.0.0.1:9093" {
		t.Errorf("base = %q, want https fallback", base)
	}
	if info == nil || info.ClusterStatus != "ready" {
		t.Errorf("info = %+v, want ClusterStatus=ready", info)
	}
}

func TestAlertmanagerCollector_Collect_NotDetected(t *testing.T) {
	withCombinedFixture(t, nil, nil, nil)
	c := NewAlertmanagerCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.AlertmanagerInfo)
	if info.Detected {
		t.Errorf("info = %+v, want Detected=false", info)
	}
}

func TestAlertmanagerCollector_Collect_MetricsUnreachableStillReturnsInfo(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:9093":                  {'1'},
		"http/http://127.0.0.1:9093/api/v2/status": promHTTPResult(t, `{"cluster":{"status":"ready","peers":[{"name":"a"},{"name":"b"}]},"versionInfo":{"version":"0.27.0"}}`, 200),
		"http/http://127.0.0.1:9093/metrics":       promHTTPResult(t, ``, 500),
	}, nil, nil)
	c := NewAlertmanagerCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.AlertmanagerInfo)
	if !info.Detected || !info.StatusRead {
		t.Fatalf("info = %+v, want Detected=true StatusRead=true", info)
	}
	if info.ClusterPeers != 2 || info.Version != "0.27.0" {
		t.Errorf("cluster mismatch: %+v", info)
	}
	if info.ConfigReloadRead {
		t.Error("ConfigReloadRead = true, want false when /metrics is unreachable")
	}
}

func TestAlertmanagerCollector_Collect_FullHappyPath(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"dial/tcp/127.0.0.1:9093":                  {'1'},
		"http/http://127.0.0.1:9093/api/v2/status": promHTTPResult(t, `{"cluster":{"status":"ready","peers":[{"name":"a"}]},"versionInfo":{"version":"0.27.0"}}`, 200),
		"http/http://127.0.0.1:9093/metrics":       promHTTPResult(t, "alertmanager_config_last_reload_successful 1\n", 200),
	}, nil, nil)
	c := NewAlertmanagerCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.AlertmanagerInfo)
	if !info.Detected || !info.StatusRead {
		t.Fatalf("info = %+v, want Detected=true StatusRead=true", info)
	}
	if !info.ConfigReloadRead || !info.ConfigReloadOK {
		t.Errorf("ConfigReloadRead=%v ConfigReloadOK=%v, want true/true", info.ConfigReloadRead, info.ConfigReloadOK)
	}
}

func TestParseAMConfigReload(t *testing.T) {
	tests := []struct {
		name      string
		metrics   string
		wantOK    bool
		wantFound bool
	}{
		{
			name:      "success no timestamp",
			metrics:   "alertmanager_config_last_reload_successful 1",
			wantOK:    true,
			wantFound: true,
		},
		{
			name:      "failed no timestamp",
			metrics:   "alertmanager_config_last_reload_successful 0",
			wantOK:    false,
			wantFound: true,
		},
		{
			// The regression: an optional Prometheus exposition timestamp after the
			// value must NOT be read as the value. A failed reload with a timestamp
			// previously parsed as success (HasPrefix of the timestamp "17…").
			name:      "failed WITH timestamp must stay failed",
			metrics:   "alertmanager_config_last_reload_successful 0 1700000000000",
			wantOK:    false,
			wantFound: true,
		},
		{
			name:      "success WITH timestamp",
			metrics:   "alertmanager_config_last_reload_successful 1 1700000000000",
			wantOK:    true,
			wantFound: true,
		},
		{
			name: "real exposition block with HELP/TYPE comments",
			metrics: "# HELP alertmanager_config_last_reload_successful Whether the last configuration reload attempt was successful.\n" +
				"# TYPE alertmanager_config_last_reload_successful gauge\n" +
				"alertmanager_config_last_reload_successful 0\n",
			wantOK:    false,
			wantFound: true,
		},
		{
			name:      "metric absent",
			metrics:   "alertmanager_notifications_total 5\n",
			wantOK:    false,
			wantFound: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ok, found := parseAMConfigReload(tc.metrics)
			if ok != tc.wantOK || found != tc.wantFound {
				t.Errorf("parseAMConfigReload(%q) = (ok=%v, found=%v), want (ok=%v, found=%v)",
					tc.metrics, ok, found, tc.wantOK, tc.wantFound)
			}
		})
	}
}
