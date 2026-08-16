//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// promHTTPGet fetches url with a short timeout, tolerating self-signed TLS (a
// Prometheus behind a reverse proxy may present one). Returns body, status, err.
// Routed through the source cache (httpGetCached) so the response replays from the
// bundle instead of re-fetching the replaying machine.
func promHTTPGet(ctx context.Context, url string) ([]byte, int, error) {
	return httpGetCached(ctx, url)
}

// detectPrometheus finds a local Prometheus on 9090 and returns its base URL +
// version. It confirms identity via /api/v1/status/buildinfo (a Prometheus-specific
// endpoint) so a different service on 9090 isn't mislabelled.
func detectPrometheus(ctx context.Context) (base, version string) {
	if !dialReachable("tcp", "127.0.0.1:9090", 300*time.Millisecond) {
		return "", ""
	}

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
				sample := tg.ScrapeURL
				if tg.LastError != "" {
					sample += " (" + tg.LastError + ")"
				}
				// internal-collectors-27-04: DownSample flows through
				// Insight.Hints (control-char sanitization is already closed
				// via that render choke point), but a remote scrapeUrl/lastError
				// pair had no length cap — an adversarial target could grow this
				// unboundedly. Cap it here at the point of assignment.
				info.DownSample = truncateRunes(sample, 200)
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
