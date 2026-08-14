//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

const envoyClusterPfx = "cluster."

// detectEnvoy finds a local Envoy admin interface on 9901 and returns its base URL
// plus version/state from /server_info. Identity is confirmed by the {version,state}
// JSON shape so a different service on 9901 isn't mislabelled.
func detectEnvoy(ctx context.Context) (base string, info *models.EnvoyInfo) {
	if !dialReachable("tcp", "127.0.0.1:9901", 300*time.Millisecond) {
		return "", nil
	}

	for _, b := range []string{"http://127.0.0.1:9901", "https://127.0.0.1:9901"} {
		body, code, err := promHTTPGet(ctx, b+"/server_info")
		if err != nil || code != http.StatusOK {
			continue
		}
		var s struct {
			Version string `json:"version"`
			State   string `json:"state"`
		}
		if json.Unmarshal(body, &s) == nil && s.State != "" {
			// internal-collectors-12-01: the {version,state} shape check above
			// confirms "something Envoy-admin-shaped answered", not "this is
			// really Envoy" — any unprivileged local process can bind :9901
			// first and serve a crafted /server_info. Cross-check the
			// listener's own cmdline before trusting it at full confidence.
			return b, &models.EnvoyInfo{
				Detected: true, Version: s.Version, State: s.State,
				IdentityUnverified: !tcpPortIdentityVerified(ctx, "9901", "envoy"),
			}
		}
	}
	return "", nil
}

// EnvoyAvailable reports whether a local Envoy admin interface is answering.
func EnvoyAvailable() bool {
	base, _ := detectEnvoy(context.Background())
	return base != ""
}

type EnvoyCollector struct{}

func NewEnvoyCollector() *EnvoyCollector { return &EnvoyCollector{} }

func (c *EnvoyCollector) Name() string           { return "Envoy" }
func (c *EnvoyCollector) Timeout() time.Duration { return 5 * time.Second }

func (c *EnvoyCollector) Collect(ctx context.Context) (interface{}, error) {
	base, info := detectEnvoy(ctx)
	if info == nil {
		return &models.EnvoyInfo{Detected: false}, nil
	}

	// Per-cluster membership counts come from /stats; the filter keeps the response
	// small on a proxy with many clusters.
	body, code, err := promHTTPGet(ctx, base+"/stats?filter=membership_(healthy|total)")
	if err != nil || code != http.StatusOK {
		info.StatusReason = "Envoy cluster stats could not be read"
		return info, nil
	}
	info.StatsRead = true
	parseEnvoyMembership(string(body), info)
	return info, nil
}

// parseEnvoyMembership reads `cluster.<name>.membership_healthy` /
// `membership_total` lines from /stats and aggregates upstream host health. A
// cluster with zero healthy hosts (but a non-zero membership) is a full outage for
// everything behind it.
func parseEnvoyMembership(stats string, info *models.EnvoyInfo) {
	type cm struct{ healthy, total int }
	clusters := map[string]*cm{}
	get := func(name string) *cm {
		if clusters[name] == nil {
			clusters[name] = &cm{}
		}
		return clusters[name]
	}
	for _, line := range strings.Split(stats, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, envoyClusterPfx) {
			continue
		}
		switch {
		case strings.Contains(line, ".membership_healthy:"):
			name := strings.TrimPrefix(line[:strings.Index(line, ".membership_healthy:")], envoyClusterPfx)
			get(name).healthy = envoyStatValue(line)
		case strings.Contains(line, ".membership_total:"):
			name := strings.TrimPrefix(line[:strings.Index(line, ".membership_total:")], envoyClusterPfx)
			get(name).total = envoyStatValue(line)
		}
	}

	// Stable sample order so the reported degraded cluster is deterministic.
	names := make([]string, 0, len(clusters))
	for n := range clusters {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		c := clusters[n]
		if c.total == 0 {
			continue
		}
		info.ClustersTotal++
		info.UpstreamsTotal += c.total
		info.UpstreamsHealthy += c.healthy
		if c.healthy == 0 {
			info.FullyDownClusters++
		}
		if c.healthy < c.total && info.DegradedSample == "" {
			info.DegradedSample = fmt.Sprintf("cluster %q: %d/%d hosts healthy", n, c.healthy, c.total)
		}
	}
}

func envoyStatValue(line string) int {
	if i := strings.LastIndex(line, ":"); i >= 0 {
		n, _ := strconv.Atoi(strings.TrimSpace(line[i+1:]))
		return n
	}
	return 0
}
