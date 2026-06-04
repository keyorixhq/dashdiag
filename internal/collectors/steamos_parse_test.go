package collectors

import (
	"strconv"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestParseSteamOSChannel(t *testing.T) {
	cases := []struct {
		name      string
		content   string
		wantRaw   string
		wantLabel string
	}{
		{"variant rel", "[Server]\nVariant = rel\n", "rel", "stable"},
		{"variant beta", "Variant=beta", "beta", "beta"},
		{"channel key", "Channel = main\n", "main", "main"},
		{"bc", "Variant = bc", "bc", "beta-candidate"},
		{"unknown passes through", "Variant = experimental", "experimental", "experimental"},
		{"absent", "[Server]\nMetaUrl = https://...\n", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, label := parseSteamOSChannel(tc.content)
			if raw != tc.wantRaw || label != tc.wantLabel {
				t.Errorf("got (%q,%q), want (%q,%q)", raw, label, tc.wantRaw, tc.wantLabel)
			}
		})
	}
}

func TestOSReleaseValue(t *testing.T) {
	content := `NAME="SteamOS"
VERSION_ID="3.7.13"
BUILD_ID=20250501.1
VARIANT_ID=steamdeck`
	if got := osReleaseValue(content, "BUILD_ID"); got != "20250501.1" {
		t.Errorf("BUILD_ID: got %q", got)
	}
	if got := osReleaseValue(content, "VERSION_ID"); got != "3.7.13" {
		t.Errorf("VERSION_ID: got %q (quotes should be stripped)", got)
	}
	if got := osReleaseValue(content, "MISSING"); got != "" {
		t.Errorf("missing key: got %q, want empty", got)
	}
}

func TestApplyRAUCJSON(t *testing.T) {
	out := `{
  "booted": "rootfs.0",
  "slots": [
    {"rootfs.0": {"state": "booted",   "boot_status": "good", "bootname": "A"}},
    {"rootfs.1": {"state": "inactive", "boot_status": "bad",  "bootname": "B"}}
  ]
}`
	var info models.SteamOSInfo
	if !applyRAUCJSON(out, &info) {
		t.Fatal("expected JSON to parse")
	}
	if info.RAUCBootedSlot != "A" || info.RAUCBootedStatus != "good" {
		t.Errorf("booted: got %s/%s, want A/good", info.RAUCBootedSlot, info.RAUCBootedStatus)
	}
	if info.RAUCInactiveSlot != "B" || info.RAUCInactiveStatus != "bad" {
		t.Errorf("inactive: got %s/%s, want B/bad", info.RAUCInactiveSlot, info.RAUCInactiveStatus)
	}
}

func TestApplyRAUCJSONRejectsNonRAUC(t *testing.T) {
	var info models.SteamOSInfo
	if applyRAUCJSON(`{"unrelated": true}`, &info) {
		t.Error("should return false when no slots present (caller falls back to text)")
	}
}

// TestApplyRAUCJSONReal113 locks in the exact `rauc status --output-format=json`
// shape captured from rauc 1.13 — the full per-slot object (class/device/type/
// mountpoint/parent alongside state/boot_status/bootname) and the slots array of
// single-key objects in inactive-then-booted order.
func TestApplyRAUCJSONReal113(t *testing.T) {
	out := `{"compatible":"steamos-amd64","variant":"","booted":"/dev/sda1","boot_primary":"rootfs.0","slots":[{"rootfs.1":{"class":"rootfs","device":"/dev/loop0","type":"ext4","bootname":"B","state":"inactive","parent":null,"mountpoint":null,"boot_status":"good"}},{"rootfs.0":{"class":"rootfs","device":"/dev/sda1","type":"ext4","bootname":"A","state":"booted","parent":null,"mountpoint":"/","boot_status":"good"}}],"artifact-repositories":[]}`
	var info models.SteamOSInfo
	if !applyRAUCJSON(out, &info) {
		t.Fatal("expected real rauc 1.13 JSON to parse")
	}
	if info.RAUCBootedSlot != "A" || info.RAUCBootedStatus != "good" {
		t.Errorf("booted: got %s/%s, want A/good", info.RAUCBootedSlot, info.RAUCBootedStatus)
	}
	if info.RAUCInactiveSlot != "B" || info.RAUCInactiveStatus != "good" {
		t.Errorf("inactive: got %s/%s, want B/good", info.RAUCInactiveSlot, info.RAUCInactiveStatus)
	}
}

func TestApplyRAUCText(t *testing.T) {
	// Real rauc 1.13 output captured on a SteamOS-spoofed host: status glyphs
	// (○ inactive, ⏺ booted) plus ANSI color codes around the field values.
	// rauc emits these even over a pipe, so the parser must strip them.
	real113 := "=== System Info ===\n" +
		"Compatible:  steamos-amd64\n" +
		"=== Slot States ===\n" +
		"○ \x1b[1m[rootfs.1]\x1b[0m (/dev/loop0, ext4, inactive\x1b[0m)\n" +
		"      bootname: \x1b[34mB\x1b[0m\n" +
		"      boot status: \x1b[32mgood\x1b[0m\n" +
		"⏺ \x1b[32m\x1b[1m[rootfs.0]\x1b[0m (/dev/sda1, ext4, \x1b[1mbooted\x1b[0m)\n" +
		"      bootname: \x1b[34mA\x1b[0m\n" +
		"      mounted: /\n" +
		"      boot status: \x1b[32mgood\x1b[0m"
	// Legacy ASCII marker form must still parse (backward compatibility).
	legacy := `=== Slot States ===
o [rootfs.0] (/dev/nvme0n1p4, ext4, booted)
        bootname: A
        boot status: good
x [rootfs.1] (/dev/nvme0n1p5, ext4, inactive)
        bootname: B
        boot status: bad`
	cases := []struct {
		name                                         string
		out                                          string
		wantBoot, wantBootStat, wantIna, wantInaStat string
	}{
		{"rauc 1.13 glyphs+ansi", real113, "A", "good", "B", "good"},
		{"legacy ascii markers", legacy, "A", "good", "B", "bad"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var info models.SteamOSInfo
			applyRAUCText(tc.out, &info)
			if info.RAUCBootedSlot != tc.wantBoot || info.RAUCBootedStatus != tc.wantBootStat {
				t.Errorf("booted: got %s/%s, want %s/%s", info.RAUCBootedSlot, info.RAUCBootedStatus, tc.wantBoot, tc.wantBootStat)
			}
			if info.RAUCInactiveSlot != tc.wantIna || info.RAUCInactiveStatus != tc.wantInaStat {
				t.Errorf("inactive: got %s/%s, want %s/%s", info.RAUCInactiveSlot, info.RAUCInactiveStatus, tc.wantIna, tc.wantInaStat)
			}
		})
	}
}

func TestMapSteamOSDevice(t *testing.T) {
	cases := []struct {
		raw            string
		wantName       string
		wantRecognised bool
		wantDeck       bool
	}{
		{"Jupiter", "Steam Deck LCD", true, true},
		{"Galileo", "Steam Deck OLED", true, true},
		{"ROG Ally RC71L", "ASUS ROG Ally", true, false},
		{"ROG Ally X RC72LA", "ASUS ROG Ally X", true, false}, // X must win over plain Ally
		{"83E1", "Lenovo Legion Go S", true, false},
		{"OEMDEVICE", "Unknown AMD handheld", false, false},
		{"", "", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			name, rec, deck := mapSteamOSDevice(tc.raw)
			if name != tc.wantName || rec != tc.wantRecognised || deck != tc.wantDeck {
				t.Errorf("got (%q,%v,%v), want (%q,%v,%v)", name, rec, deck, tc.wantName, tc.wantRecognised, tc.wantDeck)
			}
		})
	}
}

func TestParseSecureBootVar(t *testing.T) {
	enabled, ok := parseSecureBootVar([]byte{0x06, 0x00, 0x00, 0x00, 0x01})
	if !ok || !enabled {
		t.Errorf("byte 4 = 0x01 should be enabled+ok, got enabled=%v ok=%v", enabled, ok)
	}
	disabled, ok := parseSecureBootVar([]byte{0x06, 0x00, 0x00, 0x00, 0x00})
	if !ok || disabled {
		t.Errorf("byte 4 = 0x00 should be disabled+ok, got enabled=%v ok=%v", disabled, ok)
	}
	if _, ok := parseSecureBootVar([]byte{0x06, 0x00}); ok {
		t.Error("too-short var should return ok=false")
	}
}

func TestFilterGamescopeErrors(t *testing.T) {
	out := `May 01 10:00:00 deck gamescope[1]: starting up
May 01 10:00:01 deck gamescope[1]: drm failed to set mode
May 01 10:00:02 deck gamescope[1]: frame presented
May 01 10:00:03 deck gamescope[1]: assert failed in xwm`
	hits := filterGamescopeErrors(out, 5)
	if len(hits) != 2 {
		t.Fatalf("expected 2 error lines, got %d: %v", len(hits), hits)
	}
}

func TestFilterGamescopeErrorsCaps(t *testing.T) {
	var sb string
	for i := 0; i < 10; i++ {
		sb += "line error here\n"
	}
	hits := filterGamescopeErrors(sb, 3)
	if len(hits) != 3 {
		t.Errorf("expected cap of 3, got %d", len(hits))
	}
}

func TestParseSSSocketsAndResolve(t *testing.T) {
	out := `Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
udp   UNCONN 0      0            0.0.0.0:27031      0.0.0.0:*    users:(("steam",pid=1842,fd=50))
tcp   LISTEN 0      128             [::]:27036         [::]:*    users:(("steam",pid=1842,fd=51))
tcp   LISTEN 0      128          0.0.0.0:22           0.0.0.0:*    users:(("sshd",pid=900,fd=3))`
	socks := parseSSSockets(out)
	resolved := resolveRemotePlayPorts(remotePlayWantedPorts(), socks)

	byKey := map[string]models.RemotePlayPort{}
	for _, p := range resolved {
		byKey[p.Protocol+"/"+itoaPort(p.Port)] = p
	}
	if u := byKey["udp/27031"]; !u.Bound || u.Process != "steam" || u.PID != 1842 {
		t.Errorf("udp/27031 should be bound to steam/1842, got %+v", u)
	}
	if u := byKey["tcp/27036"]; !u.Bound { // parsed from [::]:27036
		t.Errorf("tcp/27036 should be bound, got %+v", u)
	}
	if u := byKey["tcp/27037"]; u.Bound {
		t.Errorf("tcp/27037 should be unbound, got %+v", u)
	}
	if u := byKey["udp/10400"]; !u.Optional {
		t.Errorf("udp/10400 should be flagged optional (VR)")
	}
}

func TestParseDefaultGateway(t *testing.T) {
	out := "default via 192.168.10.1 dev wlan0 proto dhcp metric 600"
	if gw := parseDefaultGateway(out); gw != "192.168.10.1" {
		t.Errorf("got %q, want 192.168.10.1", gw)
	}
	if gw := parseDefaultGateway("no default route here"); gw != "" {
		t.Errorf("expected empty gateway, got %q", gw)
	}
}

func TestParseARPPeers(t *testing.T) {
	out := `192.168.10.1 dev wlan0 lladdr aa:bb:cc:dd:ee:01 REACHABLE
192.168.10.50 dev wlan0 lladdr aa:bb:cc:dd:ee:02 STALE
192.168.10.99 dev wlan0 FAILED
192.168.10.77 dev wlan0  INCOMPLETE`
	// gateway .1 excluded; .50 counts; .99 FAILED and .77 INCOMPLETE excluded.
	if n := parseARPPeers(out, "192.168.10.1"); n != 1 {
		t.Errorf("expected 1 peer, got %d", n)
	}
	// Empty ARP table → 0 peers (AP isolation signal).
	if n := parseARPPeers("192.168.10.1 dev wlan0 lladdr aa:bb:cc:dd:ee:01 REACHABLE", "192.168.10.1"); n != 0 {
		t.Errorf("gateway-only table should be 0 peers, got %d", n)
	}
}

func TestFirewallBlocksPorts(t *testing.T) {
	blocking := "chain input { udp dport 27031 drop }"
	if !firewallBlocksPorts(blocking, remotePlayPrimaryPorts) {
		t.Error("drop rule on 27031 should be detected as blocking")
	}
	allow := "chain input { udp dport 27031 accept }"
	if firewallBlocksPorts(allow, remotePlayPrimaryPorts) {
		t.Error("accept rule must not count as blocking")
	}
	// Whole-number match: 270319 must not match 27031.
	if firewallBlocksPorts("udp dport 270319 drop", remotePlayPrimaryPorts) {
		t.Error("270319 should not match port 27031")
	}
}

func itoaPort(p int) string {
	return strconv.Itoa(p)
}

func TestParseMountPointSet(t *testing.T) {
	out := `/dev/nvme0n1p4 / btrfs rw 0 0
/dev/nvme0n1p4 /opt btrfs rw 0 0
proc /proc proc rw 0 0`
	set := parseMountPointSet(out)
	if !set["/"] || !set["/opt"] || !set["/proc"] {
		t.Errorf("expected /, /opt, /proc present, got %v", set)
	}
	if set["/root"] {
		t.Error("/root should not be present")
	}
}

func TestParseIwDevAndChannel(t *testing.T) {
	out := `phy#0
	Interface wlan0
		ifindex 3
		type managed
		channel 149 (5745 MHz), width: 80 MHz, center1: 5775 MHz
		ssid HomeNet
		txpower 20.00 dBm`
	ifaces := parseIwDev(out)
	if len(ifaces) != 1 {
		t.Fatalf("expected 1 interface, got %d", len(ifaces))
	}
	w := ifaces[0]
	if w.Name != "wlan0" || w.SSID != "HomeNet" || w.Channel != 149 || w.FreqMHz != 5745 || w.WidthMHz != 80 {
		t.Errorf("unexpected parse: %+v", w)
	}
}

func TestParseIwChannelLine24(t *testing.T) {
	ch, freq, width := parseIwChannelLine("channel 6 (2437 MHz), width: 20 MHz")
	if ch != 6 || freq != 2437 || width != 20 {
		t.Errorf("got ch=%d freq=%d width=%d, want 6/2437/20", ch, freq, width)
	}
}

func TestParseIwLinkSignal(t *testing.T) {
	connected, sig := parseIwLinkSignal("Connected to aa:bb (on wlan0)\n\tSSID: HomeNet\n\tsignal: -52 dBm")
	if !connected || sig != -52 {
		t.Errorf("got connected=%v sig=%d, want true/-52", connected, sig)
	}
	if c, _ := parseIwLinkSignal("Not connected."); c {
		t.Error("'Not connected.' should report disconnected")
	}
}

func TestBandFromFreqMHz(t *testing.T) {
	cases := map[int]float64{2437: 2.4, 5745: 5, 5180: 5, 6075: 6, 100: 0}
	for freq, want := range cases {
		if got := bandFromFreqMHz(freq); got != want {
			t.Errorf("freq %d: got %v, want %v", freq, got, want)
		}
	}
}

func TestDetectSSIDConflict(t *testing.T) {
	conflict, ssid := detectSSIDConflict([]iwIface{
		{Name: "wlan0", SSID: "Home", FreqMHz: 2437},
		{Name: "wlan1", SSID: "Home", FreqMHz: 5745},
	})
	if !conflict || ssid != "Home" {
		t.Errorf("expected conflict on 'Home', got %v/%q", conflict, ssid)
	}
	if c, _ := detectSSIDConflict([]iwIface{{SSID: "A"}, {SSID: "B"}}); c {
		t.Error("distinct SSIDs should not conflict")
	}
	if c, _ := detectSSIDConflict([]iwIface{{SSID: ""}, {SSID: ""}}); c {
		t.Error("empty SSIDs must not count as a conflict")
	}
}
