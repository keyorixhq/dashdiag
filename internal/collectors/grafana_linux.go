//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
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
		return b, &models.GrafanaInfo{
			Detected: true, HealthRead: true, Version: h.Version,
			DatabaseStatus: h.Database, DatabaseOK: h.Database == "ok",
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
