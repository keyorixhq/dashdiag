//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// detectGrafana finds a local Grafana on 3000 via /api/health (an unauthenticated,
// Grafana-specific endpoint) and returns its base URL plus the parsed health. A
// non-Grafana service on 3000 won't return the {database,version} shape, so it
// isn't mislabelled.
func detectGrafana(ctx context.Context) (base string, info *models.GrafanaInfo) {
	if !dialReachable("tcp", "127.0.0.1:3000", 300*time.Millisecond) {
		return "", nil
	}

	for _, b := range []string{"http://127.0.0.1:3000", "https://127.0.0.1:3000"} {
		// /api/health returns 200 when healthy and 503 when the database is down —
		// both carry the JSON body, so parse regardless of status code.
		body, _, err := promHTTPGet(ctx, b+"/api/health")
		if err != nil {
			continue
		}
		var h struct {
			Database string `json:"database"`
			Version  string `json:"version"`
			Commit   string `json:"commit"`
		}
		if json.Unmarshal(body, &h) != nil || (h.Database == "" && h.Version == "") {
			continue
		}
		// internal-collectors-13-01: the {database,version} shape check above
		// confirms "something Grafana-shaped answered", not "this is really
		// Grafana" — any unprivileged local process can bind :3000 first and
		// serve a crafted /api/health. Cross-check the listener's own cmdline
		// before trusting it at full confidence.
		//
		// internal-collectors-13-02: h.Version/h.Database come straight from
		// the remote HTTP response body — sanitize before they land in the
		// model so a crafted /api/health response can't smuggle control/ANSI
		// bytes into a future renderer.
		version := source.SanitizeControl(h.Version)
		database := source.SanitizeControl(h.Database)
		return b, &models.GrafanaInfo{
			Detected: true, HealthRead: true, Version: version,
			DatabaseStatus: database, DatabaseOK: database == "ok",
			IdentityUnverified: !tcpPortIdentityVerified(ctx, "3000", "grafana"),
		}
	}
	return "", nil
}

// GrafanaAvailable reports whether a local Grafana server is answering.
func GrafanaAvailable() bool {
	base, _ := detectGrafana(context.Background())
	return base != ""
}

type GrafanaCollector struct{}

func NewGrafanaCollector() *GrafanaCollector { return &GrafanaCollector{} }

func (c *GrafanaCollector) Name() string           { return "Grafana" }
func (c *GrafanaCollector) Timeout() time.Duration { return 5 * time.Second }

func (c *GrafanaCollector) Collect(ctx context.Context) (interface{}, error) {
	_, info := detectGrafana(ctx)
	if info == nil {
		return &models.GrafanaInfo{Detected: false}, nil
	}
	return info, nil
}
