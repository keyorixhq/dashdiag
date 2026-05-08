package collectors

import (
	"context"
	"math"
	"time"

	goping "github.com/go-ping/ping"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type NetworkDeepCollector struct{}

func NewNetworkDeepCollector() *NetworkDeepCollector { return &NetworkDeepCollector{} }

func (c *NetworkDeepCollector) Name() string           { return "NetworkDeep" }
func (c *NetworkDeepCollector) Timeout() time.Duration { return 30 * time.Second }

func (c *NetworkDeepCollector) Collect(ctx context.Context) (any, error) {
	base := &NetworkCollector{}
	raw, err := base.Collect(ctx)
	if err != nil {
		return &models.NetworkInfo{}, err
	}
	info := raw.(*models.NetworkInfo)

	// 20-sample jitter against gateway
	if info.GatewayPingMs > 0 {
		if gw := detectDefaultGateway(ctx); gw.GatewayIP != "" {
			info.JitterMs = measureJitter(ctx, gw.GatewayIP, 20)
		}
	}

	return info, nil
}

func measureJitter(ctx context.Context, host string, samples int) float64 {
	var rtts []float64
	for range samples {
		if ctx.Err() != nil {
			break
		}
		if ms := singlePingRTT(ctx, host); ms >= 0 {
			rtts = append(rtts, ms)
		}
		select {
		case <-ctx.Done():
			return 0
		case <-time.After(50 * time.Millisecond):
		}
	}
	return jitterStddev(rtts)
}

func singlePingRTT(ctx context.Context, host string) float64 {
	for _, privileged := range []bool{true, false} {
		p, err := goping.NewPinger(host)
		if err != nil {
			continue
		}
		p.Count = 1
		p.Timeout = 500 * time.Millisecond
		p.SetPrivileged(privileged)

		errCh := make(chan error, 1)
		go func() { errCh <- p.Run() }()

		select {
		case <-ctx.Done():
			p.Stop()
			return -1
		case err := <-errCh:
			if err != nil {
				continue
			}
		}
		stats := p.Statistics()
		if stats.PacketsRecv > 0 {
			return float64(stats.AvgRtt) / float64(time.Millisecond)
		}
	}
	return -1
}

func jitterStddev(values []float64) float64 {
	n := len(values)
	if n < 2 {
		return 0
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	mean := sum / float64(n)
	sq := 0.0
	for _, v := range values {
		d := v - mean
		sq += d * d
	}
	return math.Sqrt(sq / float64(n))
}
