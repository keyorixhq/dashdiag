//go:build linux

package collectors

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// promHTTPGet fetches url with a short timeout, tolerating self-signed TLS (a
// Prometheus behind a reverse proxy may present one). Returns body, status, err.
func promHTTPGet(ctx context.Context, url string) ([]byte, int, error) {
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // local health probe, not a trust decision
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close() //nolint:errcheck
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return body, resp.StatusCode, nil
}

// detectPrometheus finds a local Prometheus on 9090 and returns its base URL +
// version. It confirms identity via /api/v1/status/buildinfo (a Prometheus-specific
// endpoint) so a different service on 9090 isn't mislabelled.
func detectPrometheus(ctx context.Context) (base, version string) {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:9090", 300*time.Millisecond)
	if err != nil {
		return "", ""
	}
	conn.Close() //nolint:errcheck

	for _, b := range []string{"http://127.0.0.1:9090", "https://127.0.0.1:9090"} {
		body, code, err := promHTTPGet(ctx, b+"/api/v1/status/buildinfo")
		if err != nil || code != http.StatusOK {
			continue
		}
		var r struct {
			Status string `json:"status"`
			Data   struct {
				Version string `json:"version"`
			} `json:"data"`
		}
		if json.Unmarshal(body, &r) == nil && r.Status == "success" {
			return b, r.Data.Version
		}
	}
	return "", ""
}

// PrometheusAvailable reports whether a local Prometheus server is answering.
func PrometheusAvailable() bool {
	base, _ := detectPrometheus(context.Background())
	return base != ""
}

type PrometheusCollector struct{}

func NewPrometheusCollector() *PrometheusCollector { return &PrometheusCollector{} }

func (c *PrometheusCollector) Name() string           { return "Prometheus" }
func (c *PrometheusCollector) Timeout() time.Duration { return 6 * time.Second }

func (c *PrometheusCollector) Collect(ctx context.Context) (interface{}, error) {
	base, version := detectPrometheus(ctx)
	if base == "" {
		return &models.PrometheusInfo{Detected: false}, nil
	}
	info := &models.PrometheusInfo{Detected: true, Version: version}

	// Scrape-target health: a down target's series are silently not collected.
	body, code, err := promHTTPGet(ctx, base+"/api/v1/targets?state=active")
	if err != nil || code != http.StatusOK {
		info.StatusReason = "Prometheus targets API could not be read"
		return info, nil
	}
	var t struct {
		Status string `json:"status"`
		Data   struct {
			ActiveTargets []struct {
				Health     string `json:"health"`
				ScrapeURL  string `json:"scrapeUrl"`
				LastError  string `json:"lastError"`
				ScrapePool string `json:"scrapePool"`
			} `json:"activeTargets"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &t) != nil || t.Status != "success" {
		info.StatusReason = "Prometheus targets response could not be parsed"
		return info, nil
	}
	info.MetricsRead = true
	info.TargetsTotal = len(t.Data.ActiveTargets)
	for _, tg := range t.Data.ActiveTargets {
		if tg.Health == "down" {
			info.TargetsDown++
			if info.DownSample == "" {
				info.DownSample = tg.ScrapeURL
				if tg.LastError != "" {
					info.DownSample += " (" + tg.LastError + ")"
				}
			}
		}
	}

	// Config reload: prometheus_config_last_reload_successful == 0 means the last
	// reload FAILED and Prometheus is serving its previous config.
	parsePromConfigReload(ctx, base, info)
	return info, nil
}

func parsePromConfigReload(ctx context.Context, base string, info *models.PrometheusInfo) {
	body, code, err := promHTTPGet(ctx, base+"/api/v1/query?query=prometheus_config_last_reload_successful")
	if err != nil || code != http.StatusOK {
		return
	}
	var q struct {
		Status string `json:"status"`
		Data   struct {
			Result []struct {
				Value []interface{} `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &q) != nil || q.Status != "success" || len(q.Data.Result) == 0 {
		return
	}
	val := q.Data.Result[0].Value
	if len(val) < 2 {
		return
	}
	s, ok := val[1].(string)
	if !ok {
		return
	}
	info.ConfigReloadRead = true
	info.ConfigReloadOK = s == "1"
}
