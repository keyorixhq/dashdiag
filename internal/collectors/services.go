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
)

type ServicesCollector struct{}

func NewServicesCollector() *ServicesCollector { return &ServicesCollector{} }

func (c *ServicesCollector) Name() string           { return "Services" }
func (c *ServicesCollector) Timeout() time.Duration { return 10 * time.Second }

func (c *ServicesCollector) Collect(ctx context.Context) (any, error) {
	cfg, _ := config.Load("")
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
		if !r.Reachable && info.Status == "OK" {
			info.Status = "WARN"
		}
	}
	return info, nil
}

func checkService(ctx context.Context, svc config.ServiceConfig) models.ServiceResult {
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
		resp.Body.Close()
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
		conn.Close()
		res.Reachable = true
	}
	return res
}
