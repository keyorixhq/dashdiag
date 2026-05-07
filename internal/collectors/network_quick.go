package collectors

import (
	"bufio"
	"context"
	"encoding/hex"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	goping "github.com/go-ping/ping"
	gopsutilnet "github.com/shirou/gopsutil/v3/net"

	"github.com/keyorixhq/dashdiag/internal/models"
)

type NetworkCollector struct{}

func NewNetworkCollector() *NetworkCollector { return &NetworkCollector{} }

func (c *NetworkCollector) Name() string           { return "Network" }
func (c *NetworkCollector) Timeout() time.Duration { return 3 * time.Second }

var skipIfaceExact = map[string]bool{"lo": true, "docker0": true}
var skipIfacePrefixes = []string{"veth", "br-", "virbr"}

func shouldSkipIface(name string) bool {
	if skipIfaceExact[name] {
		return true
	}
	for _, p := range skipIfacePrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func (c *NetworkCollector) Collect(ctx context.Context) (interface{}, error) {
	result := &models.NetworkInfo{}

	ifaces, _ := gopsutilnet.InterfacesWithContext(ctx)
	ioCounters, _ := gopsutilnet.IOCountersWithContext(ctx, true)
	counterMap := make(map[string]gopsutilnet.IOCountersStat, len(ioCounters))
	for _, cnt := range ioCounters {
		counterMap[cnt.Name] = cnt
	}
	for _, iface := range ifaces {
		if shouldSkipIface(iface.Name) {
			continue
		}
		up := false
		for _, flag := range iface.Flags {
			if flag == "up" {
				up = true
				break
			}
		}
		ip := firstIPv4(iface.Addrs)
		cnt := counterMap[iface.Name]
		result.Interfaces = append(result.Interfaces, models.InterfaceInfo{
			Name:    iface.Name,
			Up:      up,
			IP:      ip,
			RxDrops: cnt.Dropin,
			TxDrops: cnt.Dropout,
		})
	}

	gw := detectDefaultGateway(ctx)

	var gwMs, internetMs, dnsMs float64
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		if gw != "" {
			gwMs = pingRTT(ctx, gw)
		} else {
			gwMs = -1
		}
	}()
	go func() {
		defer wg.Done()
		internetMs = pingRTT(ctx, "8.8.8.8")
	}()
	go func() {
		defer wg.Done()
		start := time.Now()
		_, err := net.DefaultResolver.LookupHost(ctx, "github.com")
		if err != nil {
			dnsMs = -1
			return
		}
		dnsMs = float64(time.Since(start).Milliseconds())
	}()
	wg.Wait()

	result.GatewayPingMs = gwMs
	result.InternetPingMs = internetMs
	result.DNSResolvesMs = dnsMs

	conns, _ := gopsutilnet.ConnectionsWithContext(ctx, "tcp")
	for _, conn := range conns {
		if conn.Status == "CLOSE_WAIT" {
			result.CloseWaitCount++
		}
	}
	return result, nil
}

func firstIPv4(addrs gopsutilnet.InterfaceAddrList) string {
	for _, addr := range addrs {
		a, _, err := net.ParseCIDR(addr.Addr)
		if err == nil && a.To4() != nil {
			return a.String()
		}
	}
	return ""
}

// pingRTT tries privileged ICMP first, then unprivileged UDP.
// Returns average RTT in ms, or -1 on failure.
func pingRTT(ctx context.Context, host string) float64 {
	for _, privileged := range []bool{true, false} {
		if ctx.Err() != nil {
			return -1
		}
		if ms, ok := tryOnePing(ctx, host, privileged); ok {
			return ms
		}
	}
	return -1
}

func tryOnePing(ctx context.Context, host string, privileged bool) (ms float64, ok bool) {
	p, err := goping.NewPinger(host)
	if err != nil {
		return -1, false
	}
	p.Count = 3
	p.Timeout = 1200 * time.Millisecond
	p.SetPrivileged(privileged)

	errCh := make(chan error, 1)
	go func() { errCh <- p.Run() }()

	select {
	case <-ctx.Done():
		p.Stop()
		return -1, false
	case err := <-errCh:
		if err != nil {
			return -1, false
		}
	}
	stats := p.Statistics()
	if stats.PacketsRecv == 0 {
		return -1, false
	}
	return float64(stats.AvgRtt) / float64(time.Millisecond), true
}

func detectDefaultGateway(ctx context.Context) string {
	if runtime.GOOS == "darwin" {
		return detectGatewayDarwin(ctx)
	}
	return detectGatewayLinux()
}

// parseGatewayLinux finds the default route in /proc/net/route format.
// Gateway field is 4-byte little-endian hex (e.g. "0101A8C0" = 192.168.1.1).
func parseGatewayLinux(r io.Reader) string {
	scanner := bufio.NewScanner(r)
	scanner.Scan() // skip header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 || fields[1] != "00000000" {
			continue
		}
		b, err := hex.DecodeString(fields[2])
		if err != nil || len(b) != 4 {
			continue
		}
		return net.IP([]byte{b[3], b[2], b[1], b[0]}).String()
	}
	return ""
}

func detectGatewayLinux() string {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer f.Close()
	return parseGatewayLinux(f)
}

func detectGatewayDarwin(ctx context.Context) string {
	out, err := exec.CommandContext(ctx, "route", "-n", "get", "default").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "gateway:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1]
			}
		}
	}
	return ""
}
