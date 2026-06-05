package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Round-10 characterization tests for the two large top-level functions:
// checkNetwork (WiFi signal, gateway/internet reachability + latency, DNS, TCP
// socket states, conntrack) and checkDisk (filesystem + inode usage).

func TestCheckNetwork(t *testing.T) {
	wifi := func(dbm int) models.NetworkInfo {
		return models.NetworkInfo{Interfaces: []models.InterfaceInfo{{Name: "wlan0", WiFi: &models.WiFiInfo{SignalDBm: dbm, SSID: "home"}}}}
	}
	primary := func(speed int) models.NetworkInfo {
		return models.NetworkInfo{PrimaryInterface: "eth0", Interfaces: []models.InterfaceInfo{{Name: "eth0", SpeedMbps: speed}}}
	}
	tests := []struct {
		name string
		net  models.NetworkInfo
		want string
	}{
		{"healthy is clean", models.NetworkInfo{GatewayPingMs: 5, InternetPingMs: 8}, ""},
		{"wifi very weak is CRIT", wifi(-85), "CRIT"},
		{"wifi weak is WARN", wifi(-75), "WARN"},
		{"primary down is CRIT", models.NetworkInfo{PrimaryInterface: "eth0", PrimaryInterfaceDown: true}, "CRIT"},
		{"offline is CRIT", models.NetworkInfo{GatewayPingMs: -1, InternetPingMs: -1}, "CRIT"},
		{"gateway silent but internet up is INFO", models.NetworkInfo{GatewayPingMs: -1, InternetPingMs: 10}, "INFO"},
		{"severe gateway latency is CRIT", models.NetworkInfo{GatewayPingMs: 250}, "CRIT"},
		{"elevated gateway latency is WARN", models.NetworkInfo{GatewayPingMs: 60}, "WARN"},
		{"heavy packet loss is CRIT", models.NetworkInfo{GatewayPingMs: 10, GatewayPacketLossPct: 60}, "CRIT"},
		{"moderate packet loss is WARN", models.NetworkInfo{GatewayPingMs: 10, GatewayPacketLossPct: 20}, "WARN"},
		{"DNS failed is CRIT", models.NetworkInfo{DNSFailed: true}, "CRIT"},
		{"slow DNS is CRIT", models.NetworkInfo{DNSResolvesMs: 1500}, "CRIT"},
		{"elevated DNS is WARN", models.NetworkInfo{DNSResolvesMs: 300}, "WARN"},
		{"close_wait leak is CRIT", models.NetworkInfo{CloseWaitCount: 600}, "CRIT"},
		{"close_wait elevated is WARN", models.NetworkInfo{CloseWaitCount: 150}, "WARN"},
		{"conntrack near full is CRIT", models.NetworkInfo{ConntrackUsedPct: 85}, "CRIT"},
		{"conntrack elevated is WARN", models.NetworkInfo{ConntrackUsedPct: 65}, "WARN"},
		{"listen overflows is CRIT", models.NetworkInfo{ListenOverflows: 1}, "CRIT"},
		{"slow primary link is WARN", primary(100), "WARN"},
		{"NIC hardware errors is WARN", models.NetworkInfo{Interfaces: []models.InterfaceInfo{{Name: "eth0", RxErrors: 200}}}, "WARN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkNetwork(tt.net), tt.want)
		})
	}
}

func TestCheckDisk(t *testing.T) {
	fs := func(f models.FilesystemInfo) models.DiskInfo {
		f.Mount, f.Device = "/", "/dev/sda1"
		return models.DiskInfo{Filesystems: []models.FilesystemInfo{f}}
	}
	tests := []struct {
		name string
		disk models.DiskInfo
		want string
	}{
		{"no filesystems is clean", models.DiskInfo{}, ""},
		{"normal usage is clean", fs(models.FilesystemInfo{UsedPct: 50}), ""},
		{"usage at warn is WARN", fs(models.FilesystemInfo{UsedPct: defaultThresh.DiskWarnPct}), "WARN"},
		{"usage at crit is CRIT", fs(models.FilesystemInfo{UsedPct: defaultThresh.DiskCritPct}), "CRIT"},
		{"inode exhaustion is CRIT", fs(models.FilesystemInfo{UsedPct: 10, InodesUsedPct: 95}), "CRIT"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertLevel(t, checkDisk(tt.disk, defaultThresh), tt.want)
		})
	}
}
