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

// fakeReadlinkSource overrides Readlink for an exact path map — the Bundle API
// has no public PutReadlink/PutSymlink method, so readIfaceUSB (which reads
// sysfs symlinks) needs this custom wrapper, mirroring the fakeStatfsOverrideSource
// pattern used for logs_linux.go's Statfs testing.
type fakeReadlinkSource struct {
	*source.Replay
	links map[string]string
}

func (f *fakeReadlinkSource) Readlink(path string) (string, error) {
	if target, ok := f.links[path]; ok {
		return target, nil
	}
	return f.Replay.Readlink(path)
}

func withReadlinkFixture(t *testing.T, links map[string]string, seed func(b *source.Bundle)) {
	t.Helper()
	b := source.NewBundle()
	if seed != nil {
		seed(b)
	}
	prev := SetSource(&fakeReadlinkSource{Replay: source.NewReplay(b), links: links})
	t.Cleanup(func() { SetSource(prev) })
}

func TestNetworkCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewNetworkCollector()
	if c.Name() != "Network" {
		t.Errorf("Name() = %q, want Network", c.Name())
	}
	if c.Timeout() <= 0 {
		t.Error("Timeout() must be positive")
	}
}

func TestFirstIPv4(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		addrs gopsutilnet.InterfaceAddrList
		want  string
	}{
		{"ipv4 present", gopsutilnet.InterfaceAddrList{{Addr: "192.168.1.100/24"}}, "192.168.1.100"},
		{"ipv6 only", gopsutilnet.InterfaceAddrList{{Addr: "fe80::1/64"}}, ""},
		{"ipv6 then ipv4", gopsutilnet.InterfaceAddrList{{Addr: "fe80::1/64"}, {Addr: "10.0.0.5/8"}}, "10.0.0.5"},
		{"malformed CIDR", gopsutilnet.InterfaceAddrList{{Addr: "not-an-addr"}}, ""},
		{"empty", nil, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := firstIPv4(c.addrs); got != c.want {
				t.Errorf("firstIPv4(%v) = %q, want %q", c.addrs, got, c.want)
			}
		})
	}
}

func TestHasCapNetRaw(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/self/status", []byte("Name:\troot\nCapEff:\t0000000000002000\n"))
	})
	if !hasCapNetRaw() {
		t.Error("expected true with CAP_NET_RAW bit set")
	}
}

func TestHasCapNetRaw_Unreadable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if hasCapNetRaw() {
		t.Error("expected false when /proc/self/status unreadable")
	}
}

func TestGidInPingGroupRange(t *testing.T) {
	// os.Getgid() is real (not Source-routed) — the Docker test container's
	// default root user has GID 0, so a range that includes 0 is deterministic.
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/sys/net/ipv4/ping_group_range", []byte("0 2147483647\n"))
	})
	if !gidInPingGroupRange() {
		t.Error("expected true — GID 0 within an all-allowed range")
	}
}

func TestGidInPingGroupRange_NoGroupsAllowed(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/sys/net/ipv4/ping_group_range", []byte("1 0\n"))
	})
	if gidInPingGroupRange() {
		t.Error("expected false — '1 0' means no groups allowed")
	}
}

func TestGidInPingGroupRange_Unreadable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if gidInPingGroupRange() {
		t.Error("expected false when ping_group_range unreadable")
	}
}

func TestDetectICMPAvailability_CapNetRaw(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/self/status", []byte("CapEff:\t0000000000002000\n"))
		b.PutFile("/proc/sys/net/ipv4/ping_group_range", []byte("1 0\n"))
	})
	if !detectICMPAvailability() {
		t.Error("expected true via CAP_NET_RAW")
	}
}

func TestDetectICMPAvailability_PingGroupRange(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/self/status", []byte("CapEff:\t0000000000000000\n"))
		b.PutFile("/proc/sys/net/ipv4/ping_group_range", []byte("0 2147483647\n"))
	})
	if !detectICMPAvailability() {
		t.Error("expected true via ping_group_range")
	}
}

func TestDetectICMPAvailability_Neither(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/self/status", []byte("CapEff:\t0000000000000000\n"))
		b.PutFile("/proc/sys/net/ipv4/ping_group_range", []byte("1 0\n"))
	})
	if detectICMPAvailability() {
		t.Error("expected false when neither CAP_NET_RAW nor ping_group_range grant access")
	}
}

func TestDetectGatewayLinux(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/net/route",
			[]byte("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"+
				"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"))
	})
	got := detectGatewayLinux()
	if got.GatewayIP != "192.168.1.1" || got.Iface != "eth0" {
		t.Errorf("detectGatewayLinux() = %+v, want gw=192.168.1.1 iface=eth0", got)
	}
}

func TestDetectGatewayLinux_Unreadable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	got := detectGatewayLinux()
	if got.GatewayIP != "" || got.Iface != "" {
		t.Errorf("expected zero routeInfo, got %+v", got)
	}
}

func TestDetectRouteSrcIP(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("ip", []string{"route", "get", "192.168.1.1"},
			"192.168.1.1 dev bond0 src 192.168.1.147 uid 1000\n", 0)
	})
	if got := detectRouteSrcIP(context.Background(), "192.168.1.1"); got != "192.168.1.147" {
		t.Errorf("detectRouteSrcIP() = %q, want 192.168.1.147", got)
	}
}

func TestDetectRouteSrcIP_CommandFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("ip", []string{"route", "get", "192.168.1.1"})
	})
	if got := detectRouteSrcIP(context.Background(), "192.168.1.1"); got != "" {
		t.Errorf("detectRouteSrcIP() = %q, want empty", got)
	}
}

func TestDetectRouteSrcIP_NoSrcField(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("ip", []string{"route", "get", "192.168.1.1"}, "192.168.1.1 dev eth0\n", 0)
	})
	if got := detectRouteSrcIP(context.Background(), "192.168.1.1"); got != "" {
		t.Errorf("detectRouteSrcIP() = %q, want empty", got)
	}
}

// TestDetectGatewayDarwin_NoRouteBinary exercises the failure branch on the
// real environment (the golang:1.26 test container genuinely has no `route`
// binary) — detectGatewayDarwin uses a raw exec.Command (not Source-routed),
// so this is the only branch testable without touching the live network.
func TestDetectGatewayDarwin_NoRouteBinary(t *testing.T) {
	t.Parallel()
	got := detectGatewayDarwin(context.Background())
	if got.GatewayIP != "" || got.Iface != "" {
		t.Errorf("expected zero routeInfo when route binary absent, got %+v", got)
	}
}

func TestReadIfaceSpeed(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/class/net/eth0/speed", []byte("1000\n"))
	})
	if got := readIfaceSpeed("eth0"); got != 1000 {
		t.Errorf("readIfaceSpeed() = %d, want 1000", got)
	}
}

func TestReadIfaceSpeed_UnknownSentinels(t *testing.T) {
	cases := []string{"-1", "4294967295", "65535"}
	for _, sentinel := range cases {
		t.Run(sentinel, func(t *testing.T) {
			withFixtureSource(t, func(b *source.Bundle) {
				b.PutFile("/sys/class/net/wlan0/speed", []byte(sentinel+"\n"))
			})
			if got := readIfaceSpeed("wlan0"); got != 0 {
				t.Errorf("readIfaceSpeed() = %d, want 0 for sentinel %q", got, sentinel)
			}
		})
	}
}

func TestReadIfaceSpeed_Unreadable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if got := readIfaceSpeed("lo"); got != 0 {
		t.Errorf("readIfaceSpeed() = %d, want 0", got)
	}
}

// TestReadIfaceSpeed_GarbledOrNonPositive guards the strconv.Atoi failure /
// non-positive branch: a non-numeric or zero-or-negative value (other than the
// documented sentinels) must not be ingested as a real speed reading.
func TestReadIfaceSpeed_GarbledOrNonPositive(t *testing.T) {
	cases := []string{"not-a-number", "0", "-5"}
	for _, val := range cases {
		t.Run(val, func(t *testing.T) {
			withFixtureSource(t, func(b *source.Bundle) {
				b.PutFile("/sys/class/net/eth1/speed", []byte(val+"\n"))
			})
			if got := readIfaceSpeed("eth1"); got != 0 {
				t.Errorf("readIfaceSpeed() = %d, want 0 for value %q", got, val)
			}
		})
	}
}

func TestReadIfaceSpeedDarwin(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("networksetup", []string{"-getmedia", "en0"},
			"Current: autoselect\nActive: 1000baseT <full-duplex>\n", 0)
	})
	if got := readIfaceSpeedDarwin("en0"); got != 1000 {
		t.Errorf("readIfaceSpeedDarwin() = %d, want 1000", got)
	}
}

func TestReadIfaceSpeedDarwin_CommandFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("networksetup", []string{"-getmedia", "en0"})
	})
	if got := readIfaceSpeedDarwin("en0"); got != 0 {
		t.Errorf("readIfaceSpeedDarwin() = %d, want 0", got)
	}
}

func TestReadIfaceUSB(t *testing.T) {
	withReadlinkFixture(t, map[string]string{
		"/sys/class/net/eth1/device":        "../../../devices/pci0000:00/usb1/1-1/1-1:1.0",
		"/sys/class/net/eth1/device/driver": "../../../../bus/usb/drivers/r8152",
	}, nil)
	isUSB, driver := readIfaceUSB("eth1")
	if !isUSB {
		t.Error("expected isUSB=true for a device path through /usb")
	}
	if driver != "r8152" {
		t.Errorf("driver = %q, want r8152", driver)
	}
}

func TestReadIfaceUSB_NotUSB(t *testing.T) {
	withReadlinkFixture(t, map[string]string{
		"/sys/class/net/eth0/device":        "../../../devices/pci0000:00/0000:00:1f.6",
		"/sys/class/net/eth0/device/driver": "../../../../bus/pci/drivers/e1000e",
	}, nil)
	isUSB, driver := readIfaceUSB("eth0")
	if isUSB {
		t.Error("expected isUSB=false for a PCI device path")
	}
	if driver != "e1000e" {
		t.Errorf("driver = %q, want e1000e", driver)
	}
}

func TestReadIfaceUSB_Unresolvable(t *testing.T) {
	withReadlinkFixture(t, map[string]string{}, nil)
	isUSB, driver := readIfaceUSB("lo")
	if isUSB || driver != "" {
		t.Errorf("expected false/empty, got isUSB=%v driver=%q", isUSB, driver)
	}
}

func TestDarwinUSBInterfaces(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("networksetup", []string{"-listallhardwareports"},
			"Hardware Port: USB 10/100/1G/2.5G LAN\nDevice: en7\nEthernet Address: N/A\n\n"+
				"Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: aa:bb:cc:dd:ee:ff\n", 0)
	})
	got := darwinUSBInterfaces(context.Background())
	if len(got) != 1 || got["en7"] != "USB 10/100/1G/2.5G LAN" {
		t.Errorf("darwinUSBInterfaces() = %v, want {en7: USB 10/100/1G/2.5G LAN}", got)
	}
}

func TestDarwinUSBInterfaces_CommandFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("networksetup", []string{"-listallhardwareports"})
	})
	if got := darwinUSBInterfaces(context.Background()); got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

func TestCollectWiFiInfo_NotWireless(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	if got := collectWiFiInfo("eth0"); got != nil {
		t.Errorf("expected nil for non-wireless iface, got %+v", got)
	}
}

func TestCollectWiFiInfo_FullPath(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/sys/class/net/wlan0/wireless", source.FileMeta{})
		b.PutFile("/sys/class/net/wlan0/device/uevent", []byte("DRIVER=iwlwifi\n"))
		b.PutFile("/proc/net/wireless",
			[]byte("Inter-| sta-|   Quality        |   Discarded packets\n"+
				" face | tus | link level noise |  nwid  crypt   frag  retry   misc\n"+
				"wlan0: 0000   70.  -30.  -256        0      0      0      0      0\n"))
		b.PutCmdNotFound("nmcli", []string{"-t", "-f", "ACTIVE,SSID,SIGNAL,RATE,CHAN,BSSID", "dev", "wifi", "list"})
		b.PutCmdNotFound("nmcli", []string{"-t", "-f", "ACTIVE,SSID,SIGNAL,RATE,CHAN,BSSID", "dev", "wifi", "list", "ifname", "wlan0"})
		b.PutCmdNotFound("iwconfig", []string{"wlan0"})
	})
	got := collectWiFiInfo("wlan0")
	if got == nil {
		t.Fatal("expected non-nil WiFiInfo for wireless iface")
	}
	if got.Driver != "iwlwifi" {
		t.Errorf("Driver = %q, want iwlwifi", got.Driver)
	}
	if got.SignalPct != 100 {
		t.Errorf("SignalPct = %d, want 100 (70/70 scaled)", got.SignalPct)
	}
	if got.SignalDBm != -30 {
		t.Errorf("SignalDBm = %d, want -30", got.SignalDBm)
	}
}

func TestCollectWiFiIwconfig(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("iwconfig", []string{"wlan0"},
			`wlan0     IEEE 802.11  ESSID:"HomeNet"  `+"\n"+
				`          Bit Rate=866.7 Mb/s   Tx-Power=20 dBm   `+"\n"+
				`          Frequency:5.32 GHz  Access Point: 7C:7D:21:86:E7:A5   `+"\n"+
				`          Link Quality=70/70  Signal level=-30 dBm  `+"\n", 0)
	})
	w := &models.WiFiInfo{}
	collectWiFiIwconfig("wlan0", w)
	if w.SSID != "HomeNet" {
		t.Errorf("SSID = %q, want HomeNet", w.SSID)
	}
	if w.RateMbps != 866 {
		t.Errorf("RateMbps = %d, want 866", w.RateMbps)
	}
	if w.FreqGHz != 5.32 || w.Band != "5GHz" {
		t.Errorf("FreqGHz=%v Band=%q, want 5.32/5GHz", w.FreqGHz, w.Band)
	}
	if w.BSSID != "7C:7D:21:86:E7:A5" {
		t.Errorf("BSSID = %q, want 7C:7D:21:86:E7:A5", w.BSSID)
	}
	if w.SignalDBm != -30 {
		t.Errorf("SignalDBm = %d, want -30", w.SignalDBm)
	}
}

func TestCollectWiFiIwconfig_NotAssociated(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("iwconfig", []string{"wlan0"},
			`wlan0     IEEE 802.11  ESSID:off/any  `+"\n"+`          Access Point: Not-Associated   `+"\n", 0)
	})
	w := &models.WiFiInfo{}
	collectWiFiIwconfig("wlan0", w)
	if w.SSID != "" || w.BSSID != "" {
		t.Errorf("expected empty SSID/BSSID when off/any + Not-Associated, got %+v", w)
	}
}

func TestCollectWiFiIwconfig_CommandFails(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("iwconfig", []string{"wlan0"})
	})
	w := &models.WiFiInfo{}
	collectWiFiIwconfig("wlan0", w)
	if *w != (models.WiFiInfo{}) {
		t.Errorf("expected untouched WiFiInfo, got %+v", w)
	}
}

func TestCollectWiFiNmcli(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("nmcli", []string{"-t", "-f", "ACTIVE,SSID,SIGNAL,RATE,CHAN,BSSID", "dev", "wifi", "list"},
			"no:OtherNet:40:100 Mbit/s:6:AA\\:BB\\:CC\\:DD\\:EE\\:FF\n"+
				"yes:HomeNet:80:270 Mbit/s:36:7C\\:7D\\:21\\:86\\:E7\\:A5\n", 0)
	})
	w := &models.WiFiInfo{}
	collectWiFiNmcli("wlan0", w)
	if w.SSID != "HomeNet" {
		t.Errorf("SSID = %q, want HomeNet", w.SSID)
	}
	if w.SignalPct != 80 {
		t.Errorf("SignalPct = %d, want 80", w.SignalPct)
	}
	if w.RateMbps != 270 {
		t.Errorf("RateMbps = %d, want 270", w.RateMbps)
	}
	if w.Channel != 36 || w.Band != "5GHz" {
		t.Errorf("Channel=%d Band=%q, want 36/5GHz", w.Channel, w.Band)
	}
	if w.BSSID != "7C:7D:21:86:E7:A5" {
		t.Errorf("BSSID = %q, want 7C:7D:21:86:E7:A5", w.BSSID)
	}
}

func TestCollectWiFiNmcli_FallsBackToIfnameFilter(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("nmcli", []string{"-t", "-f", "ACTIVE,SSID,SIGNAL,RATE,CHAN,BSSID", "dev", "wifi", "list"})
		b.PutCmd("nmcli", []string{"-t", "-f", "ACTIVE,SSID,SIGNAL,RATE,CHAN,BSSID", "dev", "wifi", "list", "ifname", "wlan0"},
			"yes:HomeNet:60:100 Mbit/s:1:AA\\:BB\\:CC\\:DD\\:EE\\:FF\n", 0)
	})
	w := &models.WiFiInfo{}
	collectWiFiNmcli("wlan0", w)
	if w.SSID != "HomeNet" || w.Band != "2.4GHz" {
		t.Errorf("SSID=%q Band=%q, want HomeNet/2.4GHz", w.SSID, w.Band)
	}
}

func TestCollectWiFiNmcli_BothFail(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("nmcli", []string{"-t", "-f", "ACTIVE,SSID,SIGNAL,RATE,CHAN,BSSID", "dev", "wifi", "list"})
		b.PutCmdNotFound("nmcli", []string{"-t", "-f", "ACTIVE,SSID,SIGNAL,RATE,CHAN,BSSID", "dev", "wifi", "list", "ifname", "wlan0"})
	})
	w := &models.WiFiInfo{}
	collectWiFiNmcli("wlan0", w)
	if *w != (models.WiFiInfo{}) {
		t.Errorf("expected untouched WiFiInfo, got %+v", w)
	}
}

// ── detectDefaultGateway ──────────────────────────────────────────────────────

func TestDetectDefaultGateway_Linux(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/net/route",
			[]byte("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"+
				"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"))
		b.PutCmd("ip", []string{"route", "get", "192.168.1.1"},
			"192.168.1.1 dev eth0 src 192.168.1.50 uid 0\n", 0)
	})
	got := detectDefaultGateway(context.Background())
	if got.GatewayIP != "192.168.1.1" || got.Iface != "eth0" || got.SrcIP != "192.168.1.50" {
		t.Errorf("detectDefaultGateway() = %+v, want gw=192.168.1.1 iface=eth0 src=192.168.1.50", got)
	}
}

func TestDetectDefaultGateway_Linux_NoGateway(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	got := detectDefaultGateway(context.Background())
	if got.GatewayIP != "" || got.SrcIP != "" {
		t.Errorf("detectDefaultGateway() = %+v, want empty (no route enrichment attempted)", got)
	}
}

// ── icmpAvailable ──────────────────────────────────────────────────────────────

// icmpAvailable is a sync.Once-guarded singleton — this just exercises the
// wrapper's own statements (Do call + return); detectICMPAvailability's actual
// branches are already covered directly above.
func TestIcmpAvailable_Wrapper(t *testing.T) {
	_ = icmpAvailable()
}

// ── sysPing / parseSysPingOutput ─────────────────────────────────────────────

func TestParseSysPingOutput(t *testing.T) {
	tests := []struct {
		name     string
		out      string
		wantMs   float64
		wantLoss float64
		wantOK   bool
	}{
		{
			name: "clean run, no loss",
			out: "PING 8.8.8.8: 5 data bytes\n" +
				"5 packets transmitted, 5 received, 0% packet loss\n" +
				"rtt min/avg/max/mdev = 0.585/0.660/0.806/0.102 ms\n",
			wantMs: 0.660, wantLoss: 0, wantOK: true,
		},
		{
			name: "partial loss",
			out: "5 packets transmitted, 4 received, 20% packet loss\n" +
				"rtt min/avg/max/mdev = 1.0/2.0/3.0/0.5 ms\n",
			wantMs: 2.0, wantLoss: 20, wantOK: true,
		},
		{
			name:     "total loss",
			out:      "5 packets transmitted, 0 received, 100% packet loss\n",
			wantLoss: 100, wantOK: false,
		},
		{
			name:     "empty output",
			out:      "",
			wantMs:   -1,
			wantLoss: 100,
			wantOK:   false,
		},
		{
			name:     "unparseable output still defaults to full loss",
			out:      "garbage line with no packet stats\n",
			wantLoss: 100,
			wantOK:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ms, loss, ok := parseSysPingOutput(tt.out)
			if ms != tt.wantMs || loss != tt.wantLoss || ok != tt.wantOK {
				t.Errorf("parseSysPingOutput(%q) = (%v,%v,%v), want (%v,%v,%v)",
					tt.out, ms, loss, ok, tt.wantMs, tt.wantLoss, tt.wantOK)
			}
		})
	}
}

// TestSysPing_NoPingBinary exercises the real environment (the golang:1.26
// test container genuinely has no `ping` binary) — mirrors
// TestDetectGatewayDarwin_NoRouteBinary's approach for an unmockable raw exec.
func TestSysPing_NoPingBinary(t *testing.T) {
	t.Parallel()
	ms, loss, ok := sysPing(context.Background(), "127.0.0.1", "")
	if ok || ms != -1 || loss != 100 {
		t.Errorf("sysPing() = (%v,%v,%v), want (-1,100,false) with no ping binary installed", ms, loss, ok)
	}
}

// ── tcpProbe ──────────────────────────────────────────────────────────────────

// TestTcpProbe_Loopback relies only on loopback routing (no external network
// needed): connecting to 127.0.0.1 on ports 53/80, which nothing listens on in
// the test container, deterministically yields a fast "connection refused" —
// itself a successful reachability signal per tcpProbe's contract.
func TestTcpProbe_Loopback(t *testing.T) {
	t.Parallel()
	ms, ok := tcpProbe(context.Background(), "127.0.0.1")
	if !ok {
		t.Error("expected ok=true — a refused connection on loopback still proves reachability")
	}
	if ms < 0 {
		t.Errorf("ms = %v, want >= 0", ms)
	}
}

// ── tryOnePing ────────────────────────────────────────────────────────────────

// TestTryOnePing_ContextCancelled is deterministic regardless of host network
// or ping privileges: the context is already cancelled before Run() can
// complete, so the ctx.Done() branch fires.
func TestTryOnePing_ContextCancelled(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ms, loss, ok := tryOnePing(ctx, "127.0.0.1", "", false)
	if ok || ms != -1 || loss != 100 {
		t.Errorf("tryOnePing() with pre-cancelled ctx = (%v,%v,%v), want (-1,100,false)", ms, loss, ok)
	}
}

// TestTryOnePing_UnresolvableHost drives goping.NewPinger's error branch: a
// hostname under the reserved .invalid TLD (RFC 2606) can never resolve, so
// this is deterministic without depending on the sandbox's network egress
// policy — unlike a real remote host, whose reachability varies by environment.
func TestTryOnePing_UnresolvableHost(t *testing.T) {
	t.Parallel()
	ms, loss, ok := tryOnePing(context.Background(), "does-not-exist.invalid", "", false)
	if ok || ms != -1 || loss != 100 {
		t.Errorf("tryOnePing() with unresolvable host = (%v,%v,%v), want (-1,100,false)", ms, loss, ok)
	}
}

// ── runConnectivityProbes / pingRTT / probeConnectivity / Collect ───────────

// TestRunConnectivityProbes exercises the real concurrent probe path. This
// container has no `ping` binary (sysPing always fails) and unprivileged ICMP
// is typically unavailable (falls to tcpProbe) or blocked entirely, so the
// exact reachability of 8.8.8.8/github.com depends on the sandbox's network
// egress policy — the assertions below accept either outcome and only check
// internal consistency, since the goal is exercising the code paths (pingRTT,
// icmpAvailable, tcpProbe/tryOnePing, DNS lookup), not asserting connectivity.
func TestRunConnectivityProbes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p := runConnectivityProbes(ctx, "", "")
	if p.GatewayMs != -1 || p.GatewayLoss != 100 {
		t.Errorf("empty gatewayIP must short-circuit to (-1,100), got (%v,%v)", p.GatewayMs, p.GatewayLoss)
	}
	if p.InternetLoss == 100 && p.InternetMs != -1 {
		t.Errorf("100%% internet loss must report ms=-1, got %v", p.InternetMs)
	}
	if p.DNSFailed && p.DNSMs != -1 {
		t.Errorf("DNSFailed=true must report DNSMs=-1, got %v", p.DNSMs)
	}
	if !p.DNSFailed && p.DNSMs < 0 {
		t.Errorf("DNSFailed=false must report a non-negative DNSMs, got %v", p.DNSMs)
	}
}

func TestProbeConnectivity(t *testing.T) {
	probe := connectivityProbe{GatewayMs: 1.5, GatewayLoss: 0, InternetMs: 20.3, InternetLoss: 0, DNSMs: 5.0}
	probeJSON, err := json.Marshal(probe)
	if err != nil {
		t.Fatalf("marshaling fixture probe: %v", err)
	}
	withCombinedFixture(t, map[string][]byte{
		"net/connectivity": probeJSON,
	}, nil, nil)

	var result models.NetworkInfo
	probeConnectivity(context.Background(), "192.168.1.1", "192.168.1.50", &result)
	if result.GatewayPingMs != 1.5 || result.InternetPingMs != 20.3 || result.DNSResolvesMs != 5.0 {
		t.Errorf("result = %+v, want gw=1.5 inet=20.3 dns=5.0", result)
	}
	if result.ICMPBlocked {
		t.Error("expected ICMPBlocked=false (neither probe fell back to TCP)")
	}
}

func TestNetworkCollector_Collect(t *testing.T) {
	ifaces := gopsutilnet.InterfaceStatList{
		{Name: "eth0", Flags: []string{"up"}, Addrs: gopsutilnet.InterfaceAddrList{{Addr: "10.0.0.5/24"}}},
		{Name: "lo", Flags: []string{"up"}, Addrs: gopsutilnet.InterfaceAddrList{{Addr: "127.0.0.1/8"}}},
	}
	ioCounters := []gopsutilnet.IOCountersStat{
		{Name: "eth0", Dropin: 1, Dropout: 2, Errin: 3, Errout: 4, PacketsRecv: 100, PacketsSent: 200},
	}
	conns := []gopsutilnet.ConnectionStat{
		{Status: "CLOSE_WAIT"},
		{Status: "ESTABLISHED"},
		{Status: "CLOSE_WAIT"},
	}
	probe := connectivityProbe{GatewayMs: 1.5, InternetMs: 20.3, DNSMs: 5.0}

	ifacesJSON, err := json.Marshal(ifaces)
	if err != nil {
		t.Fatalf("marshaling ifaces fixture: %v", err)
	}
	ioJSON, err := json.Marshal(ioCounters)
	if err != nil {
		t.Fatalf("marshaling iocounters fixture: %v", err)
	}
	connsJSON, err := json.Marshal(conns)
	if err != nil {
		t.Fatalf("marshaling connections fixture: %v", err)
	}
	probeJSON, err := json.Marshal(probe)
	if err != nil {
		t.Fatalf("marshaling probe fixture: %v", err)
	}

	withCombinedFixture(t, map[string][]byte{
		"gopsutil/net/interfaces":      ifacesJSON,
		"gopsutil/net/iocounters":      ioJSON,
		"net/connectivity":             probeJSON,
		"gopsutil/net/connections/tcp": connsJSON,
	}, nil, func(b *source.Bundle) {
		// /proc/net/route left unseeded -> detectDefaultGateway returns an empty
		// route -> no PrimaryInterface, no route-enrichment lookup attempted.
	})

	c := NewNetworkCollector()
	result, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info, ok := result.(*models.NetworkInfo)
	if !ok {
		t.Fatalf("Collect() returned %T, want *models.NetworkInfo", result)
	}
	if len(info.Interfaces) != 1 || info.Interfaces[0].Name != "eth0" {
		t.Fatalf("Interfaces = %+v, want exactly eth0 (lo skipped)", info.Interfaces)
	}
	iface := info.Interfaces[0]
	if !iface.Up || iface.IP != "10.0.0.5" || iface.RxDrops != 1 || iface.TxDrops != 2 {
		t.Errorf("eth0 = %+v, want Up IP=10.0.0.5 RxDrops=1 TxDrops=2", iface)
	}
	if info.GatewayPingMs != 1.5 || info.InternetPingMs != 20.3 || info.DNSResolvesMs != 5.0 {
		t.Errorf("info probe fields = %+v, want gw=1.5 inet=20.3 dns=5.0", info)
	}
	if info.CloseWaitCount != 2 {
		t.Errorf("CloseWaitCount = %d, want 2", info.CloseWaitCount)
	}
	if info.PrimaryInterface != "" {
		t.Errorf("PrimaryInterface = %q, want empty (no route seeded)", info.PrimaryInterface)
	}
}
