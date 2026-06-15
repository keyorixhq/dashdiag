//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// traefikOverview is the shape of /api/overview — it conveniently carries the
// router/service/middleware error+warning counts directly, so the collector doesn't
// have to iterate every router.
type traefikOverview struct {
	HTTP struct {
		Routers     traefikCounts `json:"routers"`
		Services    traefikCounts `json:"services"`
		Middlewares traefikCounts `json:"middlewares"`
	} `json:"http"`
}

type traefikCounts struct {
	Total    int `json:"total"`
	Warnings int `json:"warnings"`
	Errors   int `json:"errors"`
}

// traefikPorts are the common API/dashboard ports to probe: 8080 is the classic
// api.insecure dashboard; 80 covers a Traefik fronting itself.
var traefikPorts = []string{"8080", "80"}

// detectTraefik finds a local Traefik API and returns its base URL + parsed
// overview. Identity is confirmed by /api/overview returning the http/{routers,...}
// shape, so a different service on 8080 isn't mislabelled.
func detectTraefik(ctx context.Context) (base string, ov *traefikOverview) {
	for _, port := range traefikPorts {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+port, 200*time.Millisecond)
		if err != nil {
			continue
		}
		conn.Close() //nolint:errcheck
		for _, scheme := range []string{"http://", "https://"} {
			b := scheme + "127.0.0.1:" + port
			body, code, err := promHTTPGet(ctx, b+"/api/overview")
			if err != nil || code != http.StatusOK {
				continue
			}
			var o traefikOverview
			if json.Unmarshal(body, &o) == nil && o.HTTP.Routers.Total > 0 {
				return b, &o
			}
		}
	}
	return "", nil
}

// TraefikAvailable reports whether a local Traefik API is answering.
func TraefikAvailable() bool {
	base, _ := detectTraefik(context.Background())
	return base != ""
}

type TraefikCollector struct{}

func NewTraefikCollector() *TraefikCollector { return &TraefikCollector{} }

func (c *TraefikCollector) Name() string           { return "Traefik" }
func (c *TraefikCollector) Timeout() time.Duration { return 5 * time.Second }

func (c *TraefikCollector) Collect(ctx context.Context) (interface{}, error) {
	base, ov := detectTraefik(ctx)
	if ov == nil {
		return &models.TraefikInfo{Detected: false}, nil
	}
	info := &models.TraefikInfo{
		Detected: true, APIRead: true,
		RoutersTotal:     ov.HTTP.Routers.Total,
		RoutersErrors:    ov.HTTP.Routers.Errors,
		RoutersWarnings:  ov.HTTP.Routers.Warnings,
		ServicesErrors:   ov.HTTP.Services.Errors,
		MiddlewareErrors: ov.HTTP.Middlewares.Errors,
	}

	// Version is best-effort context.
	if body, code, err := promHTTPGet(ctx, base+"/api/version"); err == nil && code == http.StatusOK {
		var v struct {
			Version string `json:"Version"`
		}
		if json.Unmarshal(body, &v) == nil {
			info.Version = v.Version
		}
	}
	return info, nil
}
