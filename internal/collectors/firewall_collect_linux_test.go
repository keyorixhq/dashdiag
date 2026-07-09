//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// TestFirewallCollectorIdentity guards the Collector interface wiring (Name,
// Timeout) — cheap, no fixture dependency, safe to parallelize.
func TestFirewallCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewFirewallCollector()
	if c.Name() != "Firewall" {
		t.Errorf("Name() = %q, want Firewall", c.Name())
	}
	if c.Timeout() != 5*time.Second {
		t.Errorf("Timeout() = %v, want 5s", c.Timeout())
	}
}

// TestSbinToolPath exercises both branches: found on $PATH (lookPath succeeds)
// and found only in a standard sbin dir (lookPath fails, fileExists succeeds),
// plus the fully-absent case.
func TestSbinToolPath(t *testing.T) {
	t.Run("found on PATH", func(t *testing.T) {
		withLookPathFixture(t, map[string]bool{"nft": true}, func(b *source.Bundle) {})
		if got := sbinToolPath("nft"); got == "" {
			t.Error("expected a non-empty path when lookPath succeeds")
		}
	})

	t.Run("found in sbin fallback", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			// No lookpath/ entry -> lookPath fails; /usr/sbin/nft exists via Stat.
			b.PutStat("/usr/sbin/nft", source.FileMeta{Mode: 0o755})
		})
		got := sbinToolPath("nft")
		if got != "/usr/sbin/nft" {
			t.Errorf("sbinToolPath = %q, want /usr/sbin/nft", got)
		}
	})

	t.Run("absent everywhere", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {})
		if got := sbinToolPath("nft"); got != "" {
			t.Errorf("sbinToolPath = %q, want empty when tool is nowhere", got)
		}
	})
}

// TestCloudGuestProvider exercises all four branches of the AWS/Azure/GCP/none
// dispatch, via the DMI-file fixtures each *GuestAvailable gate reads.
func TestCloudGuestProvider(t *testing.T) {
	t.Run("aws", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile(dmiIDDir+"/sys_vendor", []byte("Amazon EC2\n"))
			b.PutFile(dmiIDDir+"/bios_vendor", []byte("Amazon EC2\n"))
			b.PutFile(dmiIDDir+"/product_name", []byte("\n"))
			b.PutFile("/sys/hypervisor/uuid", []byte("\n"))
		})
		if got := cloudGuestProvider(); got != "aws" {
			t.Errorf("cloudGuestProvider() = %q, want aws", got)
		}
	})

	t.Run("azure", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile(dmiIDDir+"/sys_vendor", []byte("\n"))
			b.PutFile(dmiIDDir+"/bios_vendor", []byte("\n"))
			b.PutFile(dmiIDDir+"/product_name", []byte("Virtual Machine\n"))
			b.PutFile(dmiIDDir+"/chassis_asset_tag", []byte("7783-7084-3265-9085-8269-3286-77\n"))
			b.PutFile("/sys/hypervisor/uuid", []byte("\n"))
		})
		if got := cloudGuestProvider(); got != "azure" {
			t.Errorf("cloudGuestProvider() = %q, want azure", got)
		}
	})

	t.Run("gcp", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile(dmiIDDir+"/sys_vendor", []byte("Google\n"))
			b.PutFile(dmiIDDir+"/bios_vendor", []byte("\n"))
			b.PutFile(dmiIDDir+"/product_name", []byte("Google Compute Engine\n"))
			b.PutFile(dmiIDDir+"/chassis_asset_tag", []byte("\n"))
			b.PutFile("/sys/hypervisor/uuid", []byte("\n"))
		})
		if got := cloudGuestProvider(); got != "gcp" {
			t.Errorf("cloudGuestProvider() = %q, want gcp", got)
		}
	})

	t.Run("none", func(t *testing.T) {
		withFixtureSource(t, func(b *source.Bundle) {
			b.PutFile(dmiIDDir+"/sys_vendor", []byte("Dell Inc.\n"))
			b.PutFile(dmiIDDir+"/bios_vendor", []byte("Dell Inc.\n"))
			b.PutFile(dmiIDDir+"/product_name", []byte("PowerEdge R740\n"))
			b.PutFile(dmiIDDir+"/chassis_asset_tag", []byte("\n"))
			b.PutFile("/sys/hypervisor/uuid", []byte("\n"))
		})
		if got := cloudGuestProvider(); got != "" {
			t.Errorf("cloudGuestProvider() = %q, want empty for bare metal", got)
		}
	})
}

// TestFirewallCollector_Collect_NFTPath exercises the full Collect() happy path
// through the nft branch: tool present, ruleset read, DefaultDrop -> correlate.
func TestFirewallCollector_Collect_NFTPath(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/usr/sbin/nft", source.FileMeta{Mode: 0o755})
		b.PutCmd("nft", []string{"list", "ruleset"}, realNFTRuleset, 0)
		b.PutFile("/proc/net/tcp", []byte(procNetTCPListening(22, 9090)))
		b.PutFile("/proc/net/tcp6", []byte(""))
	})

	c := NewFirewallCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.FirewallInfo)
	if info.Backend != "nftables" || !info.Available || !info.Active {
		t.Errorf("expected nftables backend active, got %+v", info)
	}
	if !info.DefaultDrop {
		t.Fatal("expected DefaultDrop=true for realNFTRuleset")
	}
	if len(info.BlockedListeners) != 1 || info.BlockedListeners[0] != 9090 {
		t.Errorf("expected port 9090 flagged as blocked (22 is accepted), got %v", info.BlockedListeners)
	}
}

// TestFirewallCollector_Collect_IPTablesFallback exercises the iptables branch:
// nft absent, iptables present.
func TestFirewallCollector_Collect_IPTablesFallback(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		// nft absent everywhere (no lookpath entry, no sbin Stat entry).
		b.PutStat("/usr/sbin/iptables", source.FileMeta{Mode: 0o755})
		b.PutCmd("iptables", []string{"-L", "-n", "--line-numbers"}, iptListLineNumbersDropPort22, 0)
		b.PutCmd("iptables", []string{"-t", "filter", "-nvL", "INPUT"}, iptInputPhotonDefault, 0)
		b.PutFile("/proc/net/tcp", []byte(procNetTCPListening(22, 8080)))
		b.PutFile("/proc/net/tcp6", []byte(""))
	})

	c := NewFirewallCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.FirewallInfo)
	if info.Backend != "iptables" || !info.Available {
		t.Errorf("expected iptables backend, got %+v", info)
	}
	if !info.DefaultDrop {
		t.Fatal("expected DefaultDrop=true")
	}
	if len(info.BlockedListeners) != 1 || info.BlockedListeners[0] != 8080 {
		t.Errorf("expected port 8080 flagged as blocked, got %v", info.BlockedListeners)
	}
}

// TestFirewallCollector_Collect_NoTooling guards the "no firewall userspace
// tooling" branch: neither nft nor iptables present anywhere -> unverified,
// not a silent false-OK.
func TestFirewallCollector_Collect_NoTooling(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})

	c := NewFirewallCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.FirewallInfo)
	if info.Status != "unverified" {
		t.Errorf("expected Status=unverified with no firewall tooling, got %+v", info)
	}
	if info.Available {
		t.Errorf("expected Available=false with no firewall tooling, got %+v", info)
	}
}

// TestFirewallCollector_Collect_PVEHost guards the pve-firewall correlation:
// on a Proxmox host with pve-firewall active, PVEFirewallActive must be set
// even though IsPVEHost/pveFirewallActive live in a different file
// (pve_linux.go) than FirewallCollector.Collect.
func TestFirewallCollector_Collect_PVEHost(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutStat("/usr/bin/pvedaemon", source.FileMeta{Mode: 0o755})
		b.PutStat("/usr/sbin/nft", source.FileMeta{Mode: 0o755})
		b.PutCmd("nft", []string{"list", "ruleset"}, "", 0) // empty ruleset
		b.PutCmd("systemctl", []string{"is-active", "pve-firewall"}, "active\n", 0)
	})

	c := NewFirewallCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.FirewallInfo)
	if !info.PVEFirewallActive {
		t.Errorf("expected PVEFirewallActive=true on a PVE host with the unit active, got %+v", info)
	}
}

// TestFirewallCollector_Collect_CloudGuest guards the cloud-guest correlation:
// on a detected AWS guest, CloudGuest/CloudProvider must be set on the same
// info the nft/iptables branch populated.
func TestFirewallCollector_Collect_CloudGuest(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile(dmiIDDir+"/sys_vendor", []byte("Amazon EC2\n"))
		b.PutFile(dmiIDDir+"/bios_vendor", []byte("Amazon EC2\n"))
		b.PutFile(dmiIDDir+"/product_name", []byte("\n"))
		b.PutFile("/sys/hypervisor/uuid", []byte("\n"))
		// No firewall tooling seeded -> unverified branch, still must record cloud guest.
	})

	c := NewFirewallCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.FirewallInfo)
	if !info.CloudGuest || info.CloudProvider != "aws" {
		t.Errorf("expected CloudGuest=true CloudProvider=aws, got %+v", info)
	}
}
