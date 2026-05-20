package collectors

import (
	"bufio"
	"context"
	"encoding/hex"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	goping "github.com/go-ping/ping"
	gopsutilnet "github.com/shirou/gopsutil/v3/net"

	"github.com/keyorixhq/dashdiag/internal/debug"
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

	// macOS: build USB interface map upfront from networksetup
	darwinUSB := map[string]string{}
	if runtime.GOOS == "darwin" {
		darwinUSB = darwinUSBInterfaces(ctx)
	}

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
		speedMbps := readIfaceSpeed(iface.Name)
		isUSB, driver := readIfaceUSB(iface.Name)
		// macOS: override with networksetup detection
		if portName, ok := darwinUSB[iface.Name]; ok {
			isUSB = true
			if driver == "" {
				driver = portName // e.g. "USB 10/100/1G/2.5G LAN"
			}
		}
		result.Interfaces = append(result.Interfaces, models.InterfaceInfo{
			Name:      iface.Name,
			Up:        up,
			IP:        ip,
			RxDrops:   cnt.Dropin,
			TxDrops:   cnt.Dropout,
			RxErrors:  cnt.Errin,
			TxErrors:  cnt.Errout,
			SpeedMbps: speedMbps,
			IsUSB:     isUSB,
			Driver:    driver,
		})
	}

	route := detectDefaultGateway(ctx)
	debug.Log(ctx, "Network", "gateway", "ip", route.GatewayIP, "iface", route.Iface)

	// Detect primary interface state by scanning all interfaces (before skip filter).
	if route.Iface != "" {
		result.PrimaryInterface = route.Iface
		result.PrimaryInterfaceDown = true // assume down until we find it UP
		for _, iface := range ifaces {
			if iface.Name == route.Iface {
				for _, flag := range iface.Flags {
					if flag == "up" {
						result.PrimaryInterfaceDown = false
						break
					}
				}
				break
			}
		}
	}

	probeConnectivity(ctx, route.GatewayIP, result)

	conns, _ := gopsutilnet.ConnectionsWithContext(ctx, "tcp")
	for _, conn := range conns {
		if conn.Status == "CLOSE_WAIT" {
			result.CloseWaitCount++
		}
	}
	return result, nil
}

func probeConnectivity(ctx context.Context, gatewayIP string, result *models.NetworkInfo) {
	var gwMs, gwLoss, internetMs, internetLoss, dnsMs float64
	var dnsFailed, gwICMPBlocked, inetICMPBlocked bool
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		if gatewayIP != "" {
			gwMs, gwLoss, gwICMPBlocked = pingRTT(ctx, gatewayIP)
		} else {
			gwMs, gwLoss = -1, 100
		}
	}()
	go func() {
		defer wg.Done()
		internetMs, internetLoss, inetICMPBlocked = pingRTT(ctx, "8.8.8.8")
	}()
	go func() {
		defer wg.Done()
		dnsCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		start := time.Now()
		_, err := net.DefaultResolver.LookupHost(dnsCtx, "github.com")
		if err != nil {
			dnsFailed = true
			dnsMs = -1
			return
		}
		dnsMs = float64(time.Since(start).Milliseconds())
	}()
	wg.Wait()
	debug.Log(ctx, "Network", "probe results",
		"gw_ms", gwMs, "gw_loss_pct", gwLoss,
		"inet_ms", internetMs, "inet_loss_pct", internetLoss,
		"dns_ms", dnsMs, "dns_failed", dnsFailed)
	result.GatewayPingMs = gwMs
	result.GatewayPacketLossPct = gwLoss
	result.InternetPingMs = internetMs
	result.InternetPacketLossPct = internetLoss
	result.DNSResolvesMs = dnsMs
	result.DNSFailed = dnsFailed
	// Mark ICMP as blocked if either probe fell back to TCP.
	result.ICMPBlocked = gwICMPBlocked || inetICMPBlocked

	// Bond health — reads /proc/net/bonding/* (no-op if no bonds)
	result.Bonds = collectBonds()
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

// pingRTT tries privileged ICMP, then unprivileged UDP, then TCP as a
// privilege-free fallback. Returns (average RTT in ms, packet loss pct,
// icmpBlocked). icmpBlocked is true when ICMP was unavailable or failed
// and TCP was used instead — callers can surface this in UX.
// RTT is -1 on total failure.
//
// Optimisation: when icmpAvailable() returns false (typical Linux non-root
// user with restrictive ping_group_range and no CAP_NET_RAW), skip both
// ICMP attempts entirely. This avoids producing two EPERM syscalls per
// host per run — important for systems with auditd or SOC log monitoring
// that would otherwise see denied raw-socket attempts on every cron run.
func pingRTT(ctx context.Context, host string) (ms, lossPct float64, icmpBlocked bool) {
	if !icmpAvailable() {
		debug.Log(ctx, "Network", "ICMP unavailable for this process — skipping to TCP", "host", host)
		if ms, ok := tcpProbe(ctx, host); ok {
			return ms, 0, true
		}
		debug.Log(ctx, "Network", "all probes failed", "host", host)
		return -1, 100, false
	}
	for _, privileged := range []bool{true, false} {
		if ctx.Err() != nil {
			return -1, 100, false
		}
		if ms, loss, ok := tryOnePing(ctx, host, privileged); ok {
			return ms, loss, false
		}
	}
	// ICMP detection said it should work but probes failed anyway.
	// Fall back to TCP — this can happen if e.g. iptables blocks ICMP
	// despite our process having permission to send it.
	if ms, ok := tcpProbe(ctx, host); ok {
		debug.Log(ctx, "Network", "ICMP probes failed despite availability — TCP fallback", "host", host, "ms", ms)
		return ms, 0, true
	}
	debug.Log(ctx, "Network", "all probes failed", "host", host)
	return -1, 100, false
}

// icmpAvailable reports whether this process can send ICMP probes
// without hitting EPERM. Cached via sync.Once — capabilities and
// ping_group_range don't change at runtime.
//
// On Linux, ICMP works if either:
//  1. Process has CAP_NET_RAW (raw ICMP socket), OR
//  2. Process GID (or any supplementary GID) is inside
//     /proc/sys/net/ipv4/ping_group_range (unprivileged ICMP via UDP).
//
// On non-Linux platforms (macOS), ICMP semantics differ; return true
// and let the existing privileged/unprivileged go-ping fallback handle it.
var (
	icmpAvailableOnce  sync.Once
	icmpAvailableValue bool
)

func icmpAvailable() bool {
	icmpAvailableOnce.Do(func() {
		icmpAvailableValue = detectICMPAvailability()
	})
	return icmpAvailableValue
}

func detectICMPAvailability() bool {
	if runtime.GOOS != "linux" {
		return true
	}
	if hasCapNetRaw() {
		return true
	}
	if gidInPingGroupRange() {
		return true
	}
	return false
}

// hasCapNetRaw reads /proc/self/status and checks the effective
// capabilities bitmap for CAP_NET_RAW (capability 13).
func hasCapNetRaw() bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	return parseCapEffHasNetRaw(string(data))
}

func parseCapEffHasNetRaw(status string) bool {
	for _, line := range strings.Split(status, "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			return false
		}
		capBits, err := strconv.ParseUint(parts[1], 16, 64)
		if err != nil {
			return false
		}
		const capNetRaw = 13 // see capabilities(7) man page
		return capBits&(1<<capNetRaw) != 0
	}
	return false
}

// gidInPingGroupRange reads /proc/sys/net/ipv4/ping_group_range and
// checks whether the process's primary or supplementary GIDs fall
// inside the allowed range. "1 0" (low > high) means no groups allowed.
func gidInPingGroupRange() bool {
	data, err := os.ReadFile("/proc/sys/net/ipv4/ping_group_range")
	if err != nil {
		return false
	}
	low, high, ok := parsePingGroupRange(string(data))
	if !ok {
		return false
	}
	gids := []int{os.Getgid()}
	if sup, err := os.Getgroups(); err == nil {
		gids = append(gids, sup...)
	}
	for _, g := range gids {
		if g >= low && g <= high {
			return true
		}
	}
	return false
}

func parsePingGroupRange(s string) (low, high int, ok bool) {
	fields := strings.Fields(s)
	if len(fields) != 2 {
		return 0, 0, false
	}
	l, err1 := strconv.Atoi(fields[0])
	h, err2 := strconv.Atoi(fields[1])
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	if l > h {
		// "1 0" — explicit "no groups allowed" sentinel.
		return 0, 0, false
	}
	return l, h, true
}

// tcpProbe dials host on common ports (53, 80) to check L3 reachability
// without ICMP privileges. Both a successful connection AND a "connection
// refused" response prove the host is reachable — the packet made a round
// trip. Returns (rtt_ms, ok).
func tcpProbe(ctx context.Context, host string) (ms float64, ok bool) {
	for _, port := range []string{"53", "80"} {
		tctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		start := time.Now()
		conn, err := (&net.Dialer{}).DialContext(tctx, "tcp", net.JoinHostPort(host, port))
		cancel()
		rtt := float64(time.Since(start).Milliseconds())
		if conn != nil {
			_ = conn.Close()
			debug.Log(ctx, "Network", "TCP probe connected", "host", host, "port", port, "ms", rtt)
			return rtt, true
		}
		if err != nil && strings.Contains(err.Error(), "connection refused") {
			debug.Log(ctx, "Network", "TCP probe refused (reachable)", "host", host, "port", port, "ms", rtt)
			return rtt, true
		}
		debug.Log(ctx, "Network", "TCP probe failed", "host", host, "port", port, "err", err)
	}
	return -1, false
}

func tryOnePing(ctx context.Context, host string, privileged bool) (ms, lossPct float64, ok bool) {
	mode := "unprivileged"
	if privileged {
		mode = "privileged"
	}
	debug.Log(ctx, "Network", "ping attempt", "host", host, "mode", mode)

	p, err := goping.NewPinger(host)
	if err != nil {
		debug.Log(ctx, "Network", "ping new pinger failed", "host", host, "mode", mode, "err", err)
		return -1, 100, false
	}
	p.Count = 3
	p.Timeout = 1200 * time.Millisecond
	p.SetPrivileged(privileged)

	errCh := make(chan error, 1)
	go func() { errCh <- p.Run() }()

	select {
	case <-ctx.Done():
		p.Stop()
		debug.Log(ctx, "Network", "ping cancelled", "host", host, "mode", mode)
		return -1, 100, false
	case err := <-errCh:
		if err != nil {
			debug.Log(ctx, "Network", "ping run failed", "host", host, "mode", mode, "err", err)
			return -1, 100, false
		}
	}
	stats := p.Statistics()
	if stats.PacketsRecv == 0 {
		debug.Log(ctx, "Network", "ping 100% loss", "host", host, "mode", mode, "sent", stats.PacketsSent)
		return -1, 100, false
	}
	avgMs := float64(stats.AvgRtt) / float64(time.Millisecond)
	debug.Log(ctx, "Network", "ping ok", "host", host, "mode", mode, "ms", avgMs, "loss_pct", stats.PacketLoss)
	return avgMs, stats.PacketLoss, true
}

type routeInfo struct {
	GatewayIP string
	Iface     string
}

func detectDefaultGateway(ctx context.Context) routeInfo {
	if runtime.GOOS == "darwin" {
		return detectGatewayDarwin(ctx)
	}
	return detectGatewayLinux()
}

// parseGatewayLinux finds the default route in /proc/net/route format.
// Gateway field is 4-byte little-endian hex (e.g. "0101A8C0" = 192.168.1.1).
func parseGatewayLinux(r io.Reader) routeInfo {
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
		return routeInfo{
			GatewayIP: net.IP([]byte{b[3], b[2], b[1], b[0]}).String(),
			Iface:     fields[0],
		}
	}
	return routeInfo{}
}

func detectGatewayLinux() routeInfo {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return routeInfo{}
	}
	defer f.Close()
	return parseGatewayLinux(f)
}

func detectGatewayDarwin(ctx context.Context) routeInfo {
	out, err := exec.CommandContext(ctx, "route", "-n", "get", "default").Output()
	if err != nil {
		return routeInfo{}
	}
	var info routeInfo
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		switch parts[0] {
		case "gateway:":
			info.GatewayIP = parts[1]
		case "interface:":
			info.Iface = parts[1]
		}
	}
	return info
}

// readIfaceSpeed reads the link speed for a network interface.
// On Linux: reads from /sys/class/net/<name>/speed.
// On macOS: parses 'networksetup -getmedia <name>' output.
// Returns 0 when unavailable (loopback, tunnel, wifi with driver quirks).
func readIfaceSpeed(name string) int {
	if runtime.GOOS == "darwin" {
		return readIfaceSpeedDarwin(name)
	}
	data, err := os.ReadFile("/sys/class/net/" + name + "/speed") // #nosec G304
	if err != nil {
		return 0
	}
	v := strings.TrimSpace(string(data))
	// Speed of -1 or 4294967295 means unknown/not connected
	if v == "-1" || v == "4294967295" || v == "65535" {
		return 0
	}
	speed, err := strconv.Atoi(v)
	if err != nil || speed <= 0 {
		return 0
	}
	return speed
}

// readIfaceSpeedDarwin reads link speed on macOS via networksetup -getmedia.
// Output: "Current: autoselect\nActive: 1000baseT <full-duplex>"
func readIfaceSpeedDarwin(name string) int {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := runCmd(ctx, "networksetup", "-getmedia", name)
	if err != nil || out == "" {
		return 0
	}
	// Parse "Active: 1000baseT", "Active: 100baseTX", "Active: autoselect" etc.
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "Active:") {
			continue
		}
		line = strings.TrimPrefix(line, "Active:")
		line = strings.TrimSpace(line)
		// Extract leading number: "1000baseT" -> 1000, "100baseTX" -> 100, "2500baseT" -> 2500
		for i, ch := range line {
			if ch < '0' || ch > '9' {
				if i > 0 {
					speed, _ := strconv.Atoi(line[:i])
					return speed
				}
				break
			}
		}
	}
	return 0
}

// readIfaceUSB returns true when the network interface is USB-attached.
// Detected by checking if the sysfs device path passes through a USB bus.
func readIfaceUSB(name string) (bool, string) {
	devPath := "/sys/class/net/" + name + "/device"
	resolved, err := os.Readlink(devPath)
	if err != nil {
		return false, ""
	}
	// Resolve relative symlink
	if !strings.HasPrefix(resolved, "/") {
		resolved = "/sys/class/net/" + name + "/" + resolved
	}
	isUSB := strings.Contains(resolved, "/usb") || strings.Contains(resolved, "usb/")

	// Read driver name from driver symlink
	driver := ""
	driverPath := devPath + "/driver"
	driverResolved, err := os.Readlink(driverPath)
	if err == nil {
		driver = filepath.Base(driverResolved)
	}

	return isUSB, driver
}

// darwinUSBInterfaces parses `networksetup -listallhardwareports` to find
// USB-attached network interfaces on macOS. Returns a map of interface name
// → hardware port description (e.g. "en7" → "USB 10/100/1G/2.5G LAN").
func darwinUSBInterfaces(ctx context.Context) map[string]string {
	out, err := runCmd(ctx, "networksetup", "-listallhardwareports")
	if err != nil {
		return nil
	}
	result := make(map[string]string)
	var currentPort, currentDevice string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Hardware Port:") {
			currentPort = strings.TrimSpace(strings.TrimPrefix(line, "Hardware Port:"))
			_ = currentDevice // reset intentional — new port starts fresh
			currentDevice = ""
		} else if strings.HasPrefix(line, "Device:") {
			currentDevice = strings.TrimSpace(strings.TrimPrefix(line, "Device:"))
			if currentDevice != "" && currentPort != "" {
				// Flag any interface with "USB" in the port name
				if strings.Contains(strings.ToUpper(currentPort), "USB") {
					result[currentDevice] = currentPort
				}
			}
		}
	}
	return result
}
