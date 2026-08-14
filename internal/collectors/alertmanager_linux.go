//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// detectAlertmanager finds a local Alertmanager on 9093 and returns its base URL,
// version, cluster status, and peer count. Identity is confirmed via /api/v2/status
// (an Alertmanager-specific endpoint returning a cluster object) so a different
// service on 9093 isn't mislabelled.
func detectAlertmanager(ctx context.Context) (base string, info *models.AlertmanagerInfo) {
	if !dialReachable("tcp", "127.0.0.1:9093", 300*time.Millisecond) {
		return "", nil
	}

	for _, b := range []string{"http://127.0.0.1:9093", "https://127.0.0.1:9093"} {
		body, code, err := promHTTPGet(ctx, b+"/api/v2/status")
		if err != nil || code != http.StatusOK {
			continue
		}
		var s struct {
			Cluster struct {
				Status string `json:"status"`
				Peers  []struct {
					Name string `json:"name"`
				} `json:"peers"`
			} `json:"cluster"`
			VersionInfo struct {
				Version string `json:"version"`
			} `json:"versionInfo"`
		}
		if json.Unmarshal(body, &s) != nil || s.Cluster.Status == "" {
			continue
		}
		// internal-collectors-01-02: the JSON-shape check above confirms
		// "something Alertmanager-shaped answered", not "this is really
		// Alertmanager" — any unprivileged local process can bind :9093 first
		// and serve a crafted cluster.status. Cross-check the listener's own
		// cmdline before trusting the response at full confidence.
		return b, &models.AlertmanagerInfo{
			Detected: true, StatusRead: true, Version: s.VersionInfo.Version,
			ClusterStatus: s.Cluster.Status, ClusterPeers: len(s.Cluster.Peers),
			IdentityUnverified: !tcpPortIdentityVerified(ctx, "9093", "alertmanager"),
		}
	}
	return "", nil
}

// AlertmanagerAvailable reports whether a local Alertmanager is answering.
func AlertmanagerAvailable() bool {
	base, _ := detectAlertmanager(context.Background())
	return base != ""
}

type AlertmanagerCollector struct{}

func NewAlertmanagerCollector() *AlertmanagerCollector { return &AlertmanagerCollector{} }

func (c *AlertmanagerCollector) Name() string           { return "Alertmanager" }
func (c *AlertmanagerCollector) Timeout() time.Duration { return 6 * time.Second }

func (c *AlertmanagerCollector) Collect(ctx context.Context) (interface{}, error) {
	base, info := detectAlertmanager(ctx)
	if info == nil {
		return &models.AlertmanagerInfo{Detected: false}, nil
	}

	// Config reload success comes from /metrics (the API status has no such flag).
	if body, code, err := promHTTPGet(ctx, base+"/metrics"); err == nil && code == http.StatusOK {
		if ok, found := parseAMConfigReload(string(body)); found {
			info.ConfigReloadRead = true
			info.ConfigReloadOK = ok
		}
	}
	return info, nil
}

// parseAMConfigReload reads alertmanager_config_last_reload_successful from the
// Prometheus text exposition format: the sample line's value is 1 (ok) or 0 (failed).
func parseAMConfigReload(metrics string) (ok, found bool) {
	for _, line := range strings.Split(metrics, "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "alertmanager_config_last_reload_successful") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				// The value is the field right AFTER the metric name. Prometheus
				// exposition allows an optional timestamp appended after the value
				// ("<metric> <value> <timestamp>"), so taking the last field would
				// read the timestamp — and a failed reload ("… 0 1700000000") would
				// then parse as success. (This metric is unlabeled, so fields[1] is
				// always the value.)
				v, err := strconv.ParseFloat(fields[1], 64)
				if err != nil {
					continue
				}
				return v != 0, true
			}
		}
	}
	return false, false
}
