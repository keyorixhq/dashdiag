package collectors

import (
	"context"
	"math"
	"os"
	"strconv"
	"strings"
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

	// TCP kernel counters from /proc/net/netstat and /proc/net/sockstat
	parseTCPCounters(info)

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

// parseTCPCounters reads TCP statistics from /proc/net/netstat and /proc/net/sockstat.
// These are cumulative counters since boot — we report current values, not deltas.
// High values indicate persistent network stress, not momentary spikes.
func parseTCPCounters(info *models.NetworkInfo) {
	// /proc/net/sockstat: current socket counts including TIME_WAIT
	if data, err := os.ReadFile("/proc/net/sockstat"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "TCP:") {
				fields := strings.Fields(line)
				// Format: "TCP: inuse N orphan N tw N alloc N mem N"
				for i, f := range fields {
					if f == "tw" && i+1 < len(fields) {
						if n, err := strconv.Atoi(fields[i+1]); err == nil {
							info.TimeWaitCount = n
						}
					}
				}
			}
		}
	}

	// /proc/net/netstat: TcpExt counters — two rows: header then values
	data, err := os.ReadFile("/proc/net/netstat")
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	for i := 0; i+1 < len(lines); i++ {
		if !strings.HasPrefix(lines[i], "TcpExt:") {
			continue
		}
		headers := strings.Fields(lines[i])
		values := strings.Fields(lines[i+1])
		if len(headers) != len(values) {
			continue
		}
		idx := make(map[string]int, len(headers))
		for j, h := range headers {
			idx[h] = j
		}
		get := func(name string) int {
			j, ok := idx[name]
			if !ok || j >= len(values) {
				return 0
			}
			n, _ := strconv.Atoi(values[j])
			return n
		}
		info.SynRetransCount = get("TCPSynRetrans")
		info.ListenOverflows = get("ListenOverflows")
		info.RetransFailCount = get("TCPRetransFail")
		break
	}

	// /proc/sys/net/netfilter/nf_conntrack_{count,max} — optional, needs nf_conntrack module
	countData, err1 := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_count")
	maxData, err2 := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_max")
	if err1 == nil && err2 == nil {
		count, _ := strconv.Atoi(strings.TrimSpace(string(countData)))
		max, _ := strconv.Atoi(strings.TrimSpace(string(maxData)))
		if max > 0 {
			info.ConntrackUsedPct = float64(count) / float64(max) * 100
		}
	}
}
