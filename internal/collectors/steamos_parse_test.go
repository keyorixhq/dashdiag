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

func TestApplyRAUCText(t *testing.T) {
	out := `=== System Info ===
  Compatible:  Valve Steam Deck
=== Slot States ===
o [rootfs.0] (/dev/nvme0n1p4, ext4, booted)
        bootname: A
        boot status: good
x [rootfs.1] (/dev/nvme0n1p5, ext4, inactive)
        bootname: B
        boot status: bad`
	var info models.SteamOSInfo
	applyRAUCText(out, &info)
	if info.RAUCBootedSlot != "A" || info.RAUCBootedStatus != "good" {
		t.Errorf("booted: got %s/%s, want A/good", info.RAUCBootedSlot, info.RAUCBootedStatus)
	}
	if info.RAUCInactiveSlot != "B" || info.RAUCInactiveStatus != "bad" {
		t.Errorf("inactive: got %s/%s, want B/bad", info.RAUCInactiveSlot, info.RAUCInactiveStatus)
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
