//go:build linux

package collectors

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// systemd-networkd runs as an unprivileged dynamic user, so it can only read a
// config file that has the world-read bit. 0644/0444 are fine; 0600/0640 (the
// common root-created case on Photon) are silently ignored.
func TestNetworkdCanRead(t *testing.T) {
	t.Parallel()
	cases := []struct {
		mode os.FileMode
		want bool
	}{
		{0o644, true},
		{0o444, true},
		{0o664, true},
		{0o600, false}, // the Photon footgun
		{0o640, false}, // group-readable but not other-readable
		{0o660, false},
	}
	for _, tc := range cases {
		if got := networkdCanRead(tc.mode); got != tc.want {
			t.Errorf("networkdCanRead(%04o) = %v, want %v", tc.mode.Perm(), got, tc.want)
		}
	}
}

func TestNetworkdConfigCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewNetworkdConfigCollector()
	if c.Name() != "Networkd" {
		t.Errorf("Name() = %q, want Networkd", c.Name())
	}
	if c.Timeout() != 3*time.Second {
		t.Errorf("Timeout() = %v, want 3s", c.Timeout())
	}
}

// NOTE: withFixtureSource swaps a package-level global (activeSource) — these
// tests deliberately do NOT call t.Parallel(), matching the established
// convention in security_linux_source_test.go / vmware_linux_collectors_test.go.

func TestNetworkdIsActive(t *testing.T) {
	t.Run("active", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutCmd("systemctl", []string{"is-active", "systemd-networkd"}, "active\n", 0)
		})
		if !networkdIsActive() {
			t.Error("networkdIsActive() = false, want true")
		}
	})
	t.Run("inactive", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutCmd("systemctl", []string{"is-active", "systemd-networkd"}, "inactive\n", 3)
		})
		if networkdIsActive() {
			t.Error("networkdIsActive() = true, want false")
		}
	})
	t.Run("systemctl missing", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutCmdNotFound("systemctl", []string{"is-active", "systemd-networkd"})
		})
		if networkdIsActive() {
			t.Error("networkdIsActive() = true, want false")
		}
	})
}

func TestNetworkdAvailable(t *testing.T) {
	t.Run("config file present", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutGlob("/etc/systemd/network/*.network", []string{"/etc/systemd/network/10-eth0.network"})
			b.PutGlob("/etc/systemd/network/*.link", []string{})
			b.PutGlob("/etc/systemd/network/*.netdev", []string{})
			b.PutCmdNotFound("systemctl", []string{"is-active", "systemd-networkd"})
		})
		if !NetworkdAvailable() {
			t.Error("NetworkdAvailable() = false, want true (config file present)")
		}
	})
	t.Run("no config but is-active fallback", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutGlob("/etc/systemd/network/*.network", []string{})
			b.PutGlob("/etc/systemd/network/*.link", []string{})
			b.PutGlob("/etc/systemd/network/*.netdev", []string{})
			b.PutCmd("systemctl", []string{"is-active", "systemd-networkd"}, "active\n", 0)
		})
		if !NetworkdAvailable() {
			t.Error("NetworkdAvailable() = false, want true (is-active fallback)")
		}
	})
	t.Run("neither present nor active", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutGlob("/etc/systemd/network/*.network", []string{})
			b.PutGlob("/etc/systemd/network/*.link", []string{})
			b.PutGlob("/etc/systemd/network/*.netdev", []string{})
			b.PutCmdNotFound("systemctl", []string{"is-active", "systemd-networkd"})
		})
		if NetworkdAvailable() {
			t.Error("NetworkdAvailable() = true, want false")
		}
	})
}

func TestNetworkdConfigCollector_Collect_NotDetected(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("systemctl", []string{"is-active", "systemd-networkd"})
	})
	c := NewNetworkdConfigCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.NetworkdConfigInfo)
	if info.Detected {
		t.Errorf("info = %+v, want Detected=false", info)
	}
}

func TestNetworkdConfigCollector_Collect_FullHappyPath(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "systemd-networkd"}, "active\n", 0)
		b.PutGlob("/etc/systemd/network/*.network", []string{
			"/etc/systemd/network/10-eth0.network",
			"/etc/systemd/network/20-eth1.network",
		})
		b.PutGlob("/etc/systemd/network/*.link", []string{})
		b.PutGlob("/etc/systemd/network/*.netdev", []string{})
		b.PutStat("/etc/systemd/network/10-eth0.network", source.FileMeta{Mode: 0o644})
		b.PutStat("/etc/systemd/network/20-eth1.network", source.FileMeta{Mode: 0o600})
		b.PutCmd("networkctl", []string{"--json=short", "list"}, networkctlJSONFixture, 0)
	})

	c := NewNetworkdConfigCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.NetworkdConfigInfo)
	if !info.Detected {
		t.Fatal("Detected = false, want true")
	}
	if info.TotalFiles != 2 {
		t.Errorf("TotalFiles = %d, want 2", info.TotalFiles)
	}
	if len(info.UnreadableFiles) != 1 || info.UnreadableFiles[0].Path != "/etc/systemd/network/20-eth1.network" {
		t.Fatalf("UnreadableFiles = %+v, want only the 0600 file", info.UnreadableFiles)
	}
	if info.UnreadableFiles[0].Mode != "0600" {
		t.Errorf("UnreadableFiles[0].Mode = %q, want 0600", info.UnreadableFiles[0].Mode)
	}
	if len(info.FailedLinks) != 1 || info.FailedLinks[0].Name != "eth1" {
		t.Errorf("FailedLinks = %+v, want [eth1]", info.FailedLinks)
	}
}

func TestCollectNetworkdLinks(t *testing.T) {
	t.Run("json path succeeds", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutCmd("networkctl", []string{"--json=short", "list"}, networkctlJSONFixture, 0)
		})
		links := collectNetworkdLinks(context.Background())
		if len(links) != 3 {
			t.Fatalf("collectNetworkdLinks() = %+v, want 3 links from JSON", links)
		}
	})
	t.Run("json parse error falls back to columns", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutCmd("networkctl", []string{"--json=short", "list"}, "not json", 0)
			b.PutCmd("networkctl", []string{"list", "--no-legend"},
				"  1 lo   loopback carrier    unmanaged\n  2 eth0 ether    routable   configured\n", 0)
		})
		links := collectNetworkdLinks(context.Background())
		if len(links) != 2 {
			t.Fatalf("collectNetworkdLinks() = %+v, want 2 links from columns fallback", links)
		}
	})
	t.Run("both fail returns nil", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutCmdNotFound("networkctl", []string{"--json=short", "list"})
			b.PutCmdNotFound("networkctl", []string{"list", "--no-legend"})
		})
		if got := collectNetworkdLinks(context.Background()); got != nil {
			t.Errorf("collectNetworkdLinks() = %+v, want nil", got)
		}
	})
}

func TestParseNetworkctlLinksColumns_ShortLinesSkipped(t *testing.T) {
	t.Parallel()
	const out = "  1 lo   loopback carrier    unmanaged\n" +
		"too short\n" +
		"\n" +
		"  2 eth0 ether    routable   configured\n"
	got := parseNetworkctlLinksColumns(out)
	if len(got) != 2 {
		t.Fatalf("want 2 links (short/blank lines skipped), got %+v", got)
	}
}

func TestNetworkdSetupConfiguring(t *testing.T) {
	t.Parallel()
	tests := []struct {
		setup string
		want  bool
	}{
		{"configuring", true},
		{"pending", true},
		{"  Configuring  ", true},
		{"PENDING", true},
		{"configured", false},
		{"failed", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := networkdSetupConfiguring(tt.setup); got != tt.want {
			t.Errorf("networkdSetupConfiguring(%q) = %v, want %v", tt.setup, got, tt.want)
		}
	}
}

func TestSystemUptimeSeconds(t *testing.T) {
	t.Run("readable", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/proc/uptime", []byte("12345.67 54321.00\n"))
		})
		if got := systemUptimeSeconds(); got != 12345.67 {
			t.Errorf("systemUptimeSeconds() = %v, want 12345.67", got)
		}
	})
	t.Run("unreadable returns 0", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {})
		if got := systemUptimeSeconds(); got != 0 {
			t.Errorf("systemUptimeSeconds() = %v, want 0", got)
		}
	})
	t.Run("empty file returns 0", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile("/proc/uptime", []byte(""))
		})
		if got := systemUptimeSeconds(); got != 0 {
			t.Errorf("systemUptimeSeconds() = %v, want 0", got)
		}
	})
}

func TestNetworkdSetupFailed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		setup string
		want  bool
	}{
		{"failed", true},
		{"FAILED", true},
		{"  Failed  ", true},
		{"configuring", false},
		{"configured", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := networkdSetupFailed(tt.setup); got != tt.want {
			t.Errorf("networkdSetupFailed(%q) = %v, want %v", tt.setup, got, tt.want)
		}
	}
}

// Faithful to the key names emitted by `networkctl --json=short list` on systemd
// 253 (Photon 5.0): Name / OperationalState / AdministrativeState (+ many other
// keys the parser ignores). lo is unmanaged, eth0 configured, eth1 failed.
const networkctlJSONFixture = `{"Interfaces":[` +
	`{"Index":1,"Name":"lo","Type":"loopback","MTU":65536,"OperationalState":"carrier","AdministrativeState":"unmanaged"},` +
	`{"Index":2,"Name":"eth0","Type":"ether","MTU":1500,"OperationalState":"routable","AdministrativeState":"configured"},` +
	`{"Index":3,"Name":"eth1","Type":"ether","MTU":1500,"OperationalState":"no-carrier","AdministrativeState":"failed"}` +
	`]}`

func TestParseNetworkctlLinksJSON(t *testing.T) {
	t.Parallel()
	got := parseNetworkctlLinksJSON(networkctlJSONFixture)
	if len(got) != 3 { // ALL links now (lo, eth0, eth1) — classification happens later
		t.Fatalf("want 3 links, got %d: %+v", len(got), got)
	}
	failed, _ := classifyNetworkdLinks(got, 99999)
	if len(failed) != 1 || failed[0].Name != "eth1" || failed[0].Operational != "no-carrier" {
		t.Errorf("eth1 should classify as failed: %+v", failed)
	}
	// Garbage → nil so the caller falls back to column parsing.
	if parseNetworkctlLinksJSON("not json") != nil {
		t.Error("non-JSON must return nil (triggers column fallback)")
	}
}

// Real `networkctl list --no-legend` columns: IDX LINK TYPE OPERATIONAL SETUP.
func TestParseNetworkctlLinksColumns(t *testing.T) {
	t.Parallel()
	const out = "  1 lo   loopback carrier    unmanaged\n" +
		"  2 eth0 ether    routable   configured\n" +
		"  3 eth1 ether    no-carrier failed\n"
	got := parseNetworkctlLinksColumns(out)
	if len(got) != 3 {
		t.Fatalf("want 3 links, got %+v", got)
	}
	failed, _ := classifyNetworkdLinks(got, 99999)
	if len(failed) != 1 || failed[0].Name != "eth1" {
		t.Fatalf("want only eth1 failed, got %+v", failed)
	}
}

// A link stuck in SETUP=configuring is a STUCK fault only once boot has settled
// (uptime gate) — at boot it's a normal transient and must not flag.
func TestClassifyNetworkdLinks_StuckUptimeGated(t *testing.T) {
	t.Parallel()
	links := []models.NetworkdLink{
		{Name: "eth0", Setup: "configured", Operational: "routable"},
		{Name: "eth1", Setup: "configuring", Operational: "no-carrier"},
		{Name: "lo", Setup: "unmanaged", Operational: "carrier"},
	}
	// Fresh boot (uptime 30s) — configuring is a transient, not stuck.
	if _, stuck := classifyNetworkdLinks(links, 30); len(stuck) != 0 {
		t.Errorf("configuring at boot must NOT be stuck, got %+v", stuck)
	}
	// Long after boot — still configuring = genuinely stuck.
	_, stuck := classifyNetworkdLinks(links, 6000)
	if len(stuck) != 1 || stuck[0].Name != "eth1" {
		t.Fatalf("configuring long after boot must be stuck, got %+v", stuck)
	}
}
