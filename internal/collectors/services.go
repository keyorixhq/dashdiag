package collectors

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/keyorixhq/dashdiag/internal/config"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
)

type ServicesCollector struct{}

func NewServicesCollector() *ServicesCollector { return &ServicesCollector{} }

func (c *ServicesCollector) Name() string           { return "Services" }
func (c *ServicesCollector) Timeout() time.Duration { return 10 * time.Second }

func (c *ServicesCollector) Collect(ctx context.Context) (any, error) {
	cfg, err := config.Load("")
	if err != nil {
		// internal-config-01-01: config.Load falls back to defaults (an empty
		// Services list) on a malformed/unreadable ~/.dsd.yaml, which reads
		// identically to a host with no custom services configured at all —
		// propagate the error so it surfaces as a disclosed INFO instead of
		// a silent "nothing to monitor".
		return &models.ServicesInfo{Status: "OK"}, fmt.Errorf("loading dsd config: %w", err)
	}
	if cfg == nil || len(cfg.Services) == 0 {
		return &models.ServicesInfo{Status: "OK"}, nil
	}

	results := make([]models.ServiceResult, len(cfg.Services))
	var wg sync.WaitGroup
	for i, svc := range cfg.Services {
		wg.Add(1)
		go func(idx int, s config.ServiceConfig) {
			defer wg.Done()
			results[idx] = checkService(ctx, s)
		}(i, svc)
	}
	wg.Wait()

	info := &models.ServicesInfo{Results: results, Status: "OK"}
	for _, r := range results {
		switch {
		case r.Status == "CRIT":
			info.Status = "CRIT"
		case !r.Reachable && info.Status != "CRIT":
			info.Status = "WARN"
		}
	}
	return info, nil
}

// checkService caches checkServiceLive through the source so a configured-service
// probe (a live HTTP/TCP dial + latency) replays from the bundle instead of
// re-probing the replaying machine. Keyed by protocol+name+addr (one probe per
// configured service). A recording gap (service not in the bundle) surfaces as an
// explicit unreachable WARN rather than a misleading zero-value OK.
//
// svc.Host is operator-configured, but not operator-supplied AT THIS
// INVOCATION: it comes from an implicit config.Load("") lookup ($HOME/.dsd.yaml),
// never a CLI flag — dsd services has no --host/--config flag for a target to be
// typed on the command line. That makes it indistinguishable, at the point this
// runs, from any other implicitly-discovered value this project already gates
// (see platform.NetworkAllowed's doc comment) — an arbitrary, non-loopback
// host:port dialed with no per-run opt-in. Gated here, before the Cached() call,
// same placement as nfs_linux.go's reachability gate and network_quick.go's
// probeConnectivity: sourceIsReplaying short-circuits under `dsd replay` so a
// bundle recorded before this fix still replays its captured probe result
// instead of the gate fabricating a "skipped" over it.
func checkService(ctx context.Context, svc config.ServiceConfig) models.ServiceResult {
	if !platform.NetworkAllowed() && !sourceIsReplaying() {
		return models.ServiceResult{
			Name: svc.Name, Host: svc.Host, Port: svc.Port, Protocol: svc.Protocol,
			Status: "WARN",
			Error:  "port probe skipped — network is off by default; pass --network or set DSD_ALLOW_NETWORK=1",
		}
	}
	key := "service/" + svc.Protocol + "/" + svc.Name + "/" + net.JoinHostPort(svc.Host, strconv.Itoa(svc.Port))
	var res models.ServiceResult
	if err := cachedJSON(key, func() (any, error) {
		return checkServiceLive(ctx, svc), nil
	}, &res); err != nil {
		return models.ServiceResult{
			Name: svc.Name, Host: svc.Host, Port: svc.Port, Protocol: svc.Protocol,
			Status: "WARN", Error: "not recorded in replay bundle",
		}
	}
	return res
}

func checkServiceLive(ctx context.Context, svc config.ServiceConfig) models.ServiceResult {
	res := models.ServiceResult{
		Name:     svc.Name,
		Host:     svc.Host,
		Port:     svc.Port,
		Protocol: svc.Protocol,
		Status:   "OK",
	}

	addr := net.JoinHostPort(svc.Host, strconv.Itoa(svc.Port))

	switch svc.Protocol {
	case "http", "https":
		url := fmt.Sprintf("%s://%s", svc.Protocol, addr)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			res.Error = err.Error()
			res.Status = "WARN"
			return res
		}
		start := time.Now()
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		res.LatencyMs = float64(time.Since(start).Milliseconds())
		if err != nil {
			res.Error = err.Error()
			res.Status = "WARN"
			return res
		}
		_ = resp.Body.Close()
		res.StatusCode = resp.StatusCode
		res.Reachable = true
		if resp.StatusCode >= 500 {
			res.Status = "CRIT"
		}
	default: // tcp
		d := &net.Dialer{Timeout: 5 * time.Second}
		start := time.Now()
		conn, err := d.DialContext(ctx, "tcp", addr)
		res.LatencyMs = float64(time.Since(start).Milliseconds())
		if err != nil {
			res.Error = err.Error()
			res.Status = "WARN"
			return res
		}
		_ = conn.Close()
		res.Reachable = true
	}
	return res
}
