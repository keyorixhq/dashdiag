//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	gopsutilnet "github.com/shirou/gopsutil/v3/net"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestNetworkDeepCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewNetworkDeepCollector()
	if c.Name() != "Network" {
		t.Errorf("Name() = %q, want Network (must match NetworkCollector's — shared section)", c.Name())
	}
	if c.Timeout() != 30*time.Second {
		t.Errorf("Timeout() = %v, want 30s", c.Timeout())
	}
}

// TestJitterStddev guards the pure stddev helper: n<2 must return 0 (not
// divide-by-zero or NaN), and a known dataset must produce the correct value.
func TestJitterStddev(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		values []float64
		want   float64
	}{
		{"empty", nil, 0},
		{"single value", []float64{5}, 0},
		{"two equal values", []float64{3, 3}, 0},
		{"known stddev", []float64{2, 4, 4, 4, 5, 5, 7, 9}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := jitterStddev(tt.values); got != tt.want {
				t.Errorf("jitterStddev(%v) = %v, want %v", tt.values, got, tt.want)
			}
		})
	}
}

// TestNetworkDeepCollector_Collect_NoGatewayPing guards the branch where the
// base NetworkCollector's GatewayPingMs is 0 (no reachable gateway) — the
// jitter measurement must be skipped entirely, and Collect must still succeed.
func TestNetworkDeepCollector_Collect_NoGatewayPing(t *testing.T) {
	ifaces := gopsutilnet.InterfaceStatList{
		{Name: "eth0", Flags: []string{"up"}, Addrs: gopsutilnet.InterfaceAddrList{{Addr: "10.0.0.5/24"}}},
	}
	probe := connectivityProbe{GatewayMs: 0, GatewayLoss: 100}
	ifacesJSON, err := json.Marshal(ifaces)
	if err != nil {
		t.Fatalf("marshaling ifaces fixture: %v", err)
	}
	probeJSON, err := json.Marshal(probe)
	if err != nil {
		t.Fatalf("marshaling probe fixture: %v", err)
	}

	withCombinedFixture(t, map[string][]byte{
		"gopsutil/net/interfaces": ifacesJSON,
		"net/connectivity":        probeJSON,
	}, nil, func(b *source.Bundle) {
		b.PutFile("/proc/net/sockstat", []byte("TCP: inuse 1 orphan 0 tw 2 alloc 3 mem 4\n"))
	})

	c := NewNetworkDeepCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.NetworkInfo)
	if info.GatewayPingMs != 0 {
		t.Errorf("GatewayPingMs = %v, want 0 (no reachable gateway)", info.GatewayPingMs)
	}
	if info.JitterMs != 0 {
		t.Errorf("JitterMs = %v, want 0 (jitter branch must be skipped)", info.JitterMs)
	}
	if info.TimeWaitCount != 2 {
		t.Errorf("TimeWaitCount = %d, want 2 (parseTCPCounters must still run)", info.TimeWaitCount)
	}
}

// TestNetworkDeepCollector_Collect_JitterFullPath guards the branch where
// GatewayPingMs > 0 and a gateway IP is detected: measureJitter is routed
// through cachedJSON("net/jitter", ...), so seeding that Cached key directly
// exercises the full Collect() path without a real ping.
func TestNetworkDeepCollector_Collect_JitterFullPath(t *testing.T) {
	ifaces := gopsutilnet.InterfaceStatList{
		{Name: "eth0", Flags: []string{"up"}, Addrs: gopsutilnet.InterfaceAddrList{{Addr: "10.0.0.5/24"}}},
	}
	probe := connectivityProbe{GatewayMs: 1.5, GatewayLoss: 0, InternetMs: 20.3, InternetLoss: 0, DNSMs: 5.0}
	ifacesJSON, err := json.Marshal(ifaces)
	if err != nil {
		t.Fatalf("marshaling ifaces fixture: %v", err)
	}
	probeJSON, err := json.Marshal(probe)
	if err != nil {
		t.Fatalf("marshaling probe fixture: %v", err)
	}
	jitterJSON, err := json.Marshal(3.75)
	if err != nil {
		t.Fatalf("marshaling jitter fixture: %v", err)
	}

	withCombinedFixture(t, map[string][]byte{
		"gopsutil/net/interfaces": ifacesJSON,
		"net/connectivity":        probeJSON,
		"net/jitter":              jitterJSON,
	}, nil, func(b *source.Bundle) {
		b.PutFile("/proc/net/route",
			[]byte("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"+
				"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"))
		b.PutCmd("ip", []string{"route", "get", "192.168.1.1"},
			"192.168.1.1 dev eth0 src 192.168.1.50 uid 0\n", 0)
	})

	c := NewNetworkDeepCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.NetworkInfo)
	if info.GatewayPingMs != 1.5 {
		t.Fatalf("GatewayPingMs = %v, want 1.5 (base collector result)", info.GatewayPingMs)
	}
	if info.JitterMs != 3.75 {
		t.Errorf("JitterMs = %v, want 3.75 (from the seeded net/jitter Cached key, not a real ping)", info.JitterMs)
	}
}

// TestParseTCPCounters guards the deep TCP-counter parser — the project's most
// bug-prone diagnostic area (TIME_WAIT / SYN-retrans / listen-overflow /
// conntrack, per the #686/#687 wiring history). All five inputs are separate
// /proc files, each independently optional.
func TestParseTCPCounters(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/net/sockstat", []byte("sockets: used 300\nTCP: inuse 12 orphan 0 tw 542 alloc 20 mem 10\n"))
		b.PutFile("/proc/net/netstat", []byte(
			"TcpExt: SyncookiesSent TCPSynRetrans ListenOverflows TCPRetransFail\n"+
				"TcpExt: 0 37 4 2\n",
		))
		b.PutFile("/proc/uptime", []byte("123456.78 98765.43\n"))
		b.PutFile("/proc/sys/net/netfilter/nf_conntrack_count", []byte("6000\n"))
		b.PutFile("/proc/sys/net/netfilter/nf_conntrack_max", []byte("10000\n"))
	})
	info := &models.NetworkInfo{}
	parseTCPCounters(info)

	if info.TimeWaitCount != 542 {
		t.Errorf("TIME_WAIT count should be parsed from sockstat, got %d", info.TimeWaitCount)
	}
	if info.SynRetransCount != 37 || info.ListenOverflows != 4 || info.RetransFailCount != 2 {
		t.Errorf("TcpExt counters should be parsed by column name (header/value row alignment), got %+v", info)
	}
	if info.UptimeSec != 123456.78 {
		t.Errorf("uptime should be parsed from the first field, got %v", info.UptimeSec)
	}
	if info.ConntrackUsedPct != 60 {
		t.Errorf("conntrack used pct should be count/max*100 = 60, got %v", info.ConntrackUsedPct)
	}
}

// TestMeasureJitterCanceledContext guards the early-exit branch: a context
// canceled before the sampling loop starts must make measureJitter return
// immediately without attempting any real ping (ctx.Err() check at top of
// the loop body).
func TestMeasureJitterCanceledContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := measureJitter(ctx, "127.0.0.1", 5)
	if got != 0 {
		t.Errorf("measureJitter() with canceled context = %v, want 0 (no samples collected)", got)
	}
}

// TestSinglePingRTTCanceledContext guards singlePingRTT's ctx.Done() select
// branch: a context canceled before Run() completes must return -1 (no RTT)
// rather than blocking or panicking. This never depends on real network
// reachability — the pinger is started against localhost and the context is
// already canceled, so the ctx.Done() case always wins the select.
func TestSinglePingRTTCanceledContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := singlePingRTT(ctx, "127.0.0.1")
	if got != -1 {
		t.Errorf("singlePingRTT() with canceled context = %v, want -1", got)
	}
}

// TestSinglePingRTTInvalidHost guards the goping.NewPinger error branch: an
// unparsable/invalid host string must make NewPinger fail for both privileged
// and unprivileged attempts, falling through the loop to return -1.
func TestSinglePingRTTInvalidHost(t *testing.T) {
	t.Parallel()
	got := singlePingRTT(context.Background(), "")
	if got != -1 {
		t.Errorf("singlePingRTT() with empty host = %v, want -1 (NewPinger should fail)", got)
	}
}

// TestParseTCPCountersMissingConntrack guards the "module not loaded" case:
// without both nf_conntrack files present, ConntrackUsedPct must stay 0, not
// divide-by-zero or read a partial value.
func TestParseTCPCountersMissingConntrack(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/net/netstat", []byte("TcpExt: TCPSynRetrans\nTcpExt: 5\n"))
	})
	info := &models.NetworkInfo{}
	parseTCPCounters(info)
	if info.ConntrackUsedPct != 0 {
		t.Errorf("without nf_conntrack files, ConntrackUsedPct must stay 0, got %v", info.ConntrackUsedPct)
	}
	if info.SynRetransCount != 5 {
		t.Errorf("the present netstat data should still be parsed, got %+v", info)
	}
}
