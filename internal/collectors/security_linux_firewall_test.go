//go:build linux

package collectors

import (
	"context"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestDetectFirewalld_ActiveSSHAllowedViaService(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("firewall-cmd", []string{"--state"}, "running\n", 0)
		b.PutCmd("firewall-cmd", []string{"--get-default-zone"}, "public\n", 0)
		b.PutCmd("firewall-cmd", []string{"--list-services"}, "dhcpv6-client ssh\n", 0)
	})

	info := &models.SecurityInfo{}
	if !detectFirewalld(context.Background(), info) {
		t.Fatal("expected detectFirewalld to report true for a running firewalld")
	}
	if !info.FirewallActive || info.FirewallType != "firewalld" {
		t.Errorf("expected FirewallActive=true FirewallType=firewalld, got %+v", info)
	}
	if info.FirewallZone != "public" {
		t.Errorf("expected FirewallZone=public, got %q", info.FirewallZone)
	}
	if !info.SSHAllowed {
		t.Error("ssh listed in --list-services must set SSHAllowed=true")
	}
}

func TestDetectFirewalld_SSHViaExplicitPort(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("firewall-cmd", []string{"--state"}, "running\n", 0)
		b.PutCmd("firewall-cmd", []string{"--get-default-zone"}, "public\n", 0)
		b.PutCmd("firewall-cmd", []string{"--list-services"}, "dhcpv6-client\n", 0) // no "ssh" service
		b.PutCmd("firewall-cmd", []string{"--list-ports"}, "22/tcp 8080/tcp\n", 0)
	})

	info := &models.SecurityInfo{}
	if !detectFirewalld(context.Background(), info) {
		t.Fatal("expected detectFirewalld to report true")
	}
	if !info.SSHAllowed {
		t.Error("explicit 22/tcp port rule must set SSHAllowed=true even without the ssh service")
	}
}

// TestDetectFirewalld_RulesUnreadable guards the conservative default: when
// neither --list-services nor --list-ports succeeds, SSH reachability is
// unknown, not "blocked" — a false "you may lose remote access" WARN would be
// worse than silence here.
func TestDetectFirewalld_RulesUnreadable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("firewall-cmd", []string{"--state"}, "running\n", 0)
		b.PutCmdNotFound("firewall-cmd", []string{"--get-default-zone"})
		b.PutCmdNotFound("firewall-cmd", []string{"--list-services"})
		b.PutCmdNotFound("firewall-cmd", []string{"--list-ports"})
	})

	info := &models.SecurityInfo{}
	if !detectFirewalld(context.Background(), info) {
		t.Fatal("expected detectFirewalld to report true (firewalld is running)")
	}
	if !info.SSHAllowed {
		t.Error("unreadable rules must default SSHAllowed=true (unknown, not blocked)")
	}
}

func TestDetectFirewalld_NotRunning(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("firewall-cmd", []string{"--state"}, "not running\n", 0)
	})
	info := &models.SecurityInfo{}
	if detectFirewalld(context.Background(), info) {
		t.Error("expected detectFirewalld to report false when firewalld is not running")
	}
}

func TestDetectFirewalld_NotInstalled(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("firewall-cmd", []string{"--state"})
	})
	info := &models.SecurityInfo{}
	if detectFirewalld(context.Background(), info) {
		t.Error("expected detectFirewalld to report false when firewall-cmd is absent")
	}
}

func TestDetectUFW_ActiveSSHAllowed(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("ufw", []string{"status"}, "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       Anywhere\n", 0)
	})
	info := &models.SecurityInfo{}
	if !detectUFW(context.Background(), info) {
		t.Fatal("expected detectUFW to report true for an active ufw")
	}
	if !info.FirewallActive || info.FirewallType != "ufw" {
		t.Errorf("expected FirewallActive=true FirewallType=ufw, got %+v", info)
	}
	if !info.SSHAllowed {
		t.Error("explicit 22/tcp ALLOW rule must set SSHAllowed=true")
	}
}

func TestDetectUFW_Inactive(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("ufw", []string{"status"}, "Status: inactive\n", 0)
	})
	info := &models.SecurityInfo{}
	if detectUFW(context.Background(), info) {
		t.Error("expected detectUFW to report false when ufw status is inactive")
	}
}

func TestDetectUFW_NotInstalled(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("ufw", []string{"status"})
	})
	info := &models.SecurityInfo{}
	if detectUFW(context.Background(), info) {
		t.Error("expected detectUFW to report false when ufw is absent")
	}
}

// TestDetectNFTables_ActiveWithSSHRule exercises the non-empty-ruleset branch,
// the case not covered by TestFirewallInvokedByBareName (which only covers
// empty-ruleset and unreadable). Reuses realNFTRuleset from
// firewall_active_linux_test.go and recordingFWSource from
// firewall_barename_linux_test.go, both in this package already.
func TestDetectNFTables_ActiveWithSSHRule(t *testing.T) {
	rec := &recordingFWSource{runOut: realNFTRuleset}
	defer SetSource(SetSource(rec))

	info := &models.SecurityInfo{}
	if !detectNFTables(context.Background(), info) {
		t.Fatal("expected detectNFTables to report true for a non-empty ruleset")
	}
	if !info.FirewallActive || info.FirewallType != "nftables" {
		t.Errorf("expected FirewallActive=true FirewallType=nftables, got %+v", info)
	}
	if !info.SSHAllowed {
		t.Error("realNFTRuleset accepts tcp dport 22 — SSHAllowed must be true")
	}
}

// TestDetectNFTables_ConfigFileFallback exercises the on-disk-config branch:
// nft binary absent from $PATH and sbin, but /etc/nftables.conf exists.
//
// internal-collectors-29-03: config-file PRESENCE does not prove a ruleset is
// actually loaded — the nft binary itself is absent, so it can never be
// confirmed. This must NOT claim FirewallActive=true (the exact false-OK the
// live-ruleset rewrite exists to prevent for the tool-present case); it must
// disclose FirewallConfigOnlyUnverified and return false so parseFirewall's
// backend chain still checks iptables, since the real active backend might
// not be nftables at all.
func TestDetectNFTables_ConfigFileFallback(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		// No lookPath / sbin PutStat entries at all -> sbinToolPath("nft") == "".
		b.PutGlob("/etc/nftables.conf", []string{"/etc/nftables.conf"})
	})
	info := &models.SecurityInfo{}
	if detectNFTables(context.Background(), info) {
		t.Fatal("expected detectNFTables to report false via the config-file fallback (chain must continue to iptables)")
	}
	if info.FirewallActive {
		t.Error("expected FirewallActive=false — a config file does not prove a loaded ruleset")
	}
	if !info.FirewallConfigOnlyUnverified {
		t.Error("expected FirewallConfigOnlyUnverified=true")
	}
	if info.FirewallType != "nftables" {
		t.Errorf("FirewallType = %q, want nftables", info.FirewallType)
	}
}

func TestDetectNFTables_NoToolNoConfig(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutGlob("/etc/nftables.conf", nil)
		b.PutGlob("/etc/nftables.d/*.nft", nil)
	})
	info := &models.SecurityInfo{}
	if detectNFTables(context.Background(), info) {
		t.Error("expected detectNFTables to report false with no tool and no config")
	}
}

// TestParseFirewall_FallsThroughToUFW guards the dispatcher chain: firewalld
// absent, ufw active -> parseFirewall must report the ufw verdict, not
// silently stop at "no firewall".
func TestParseFirewall_FallsThroughToUFW(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("firewall-cmd", []string{"--state"})
		b.PutCmd("ufw", []string{"status"}, "Status: active\n\n22/tcp ALLOW Anywhere\n", 0)
	})
	info := &models.SecurityInfo{}
	parseFirewall(context.Background(), info)
	if !info.FirewallActive || info.FirewallType != "ufw" {
		t.Errorf("expected the dispatcher to fall through to ufw, got %+v", info)
	}
}

// TestParseFirewall_NFTConfigOnlyFallsThroughToIPTables guards the
// internal-collectors-29-03 fix at the dispatcher-chain level: an nftables
// config file on disk with no nft binary must NOT stop the chain at a
// confident "active" — it must fall through and let a live iptables ruleset
// (the actually-enforced backend) win the verdict.
func TestParseFirewall_NFTConfigOnlyFallsThroughToIPTables(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{"lookpath/iptables": []byte("/usr/sbin/iptables")}, nil, func(b *source.Bundle) {
		b.PutCmdNotFound("firewall-cmd", []string{"--state"})
		b.PutCmdNotFound("ufw", []string{"status"})
		// No lookPath/sbin entries for "nft" -> sbinToolPath("nft") == "".
		b.PutGlob("/etc/nftables.conf", []string{"/etc/nftables.conf"})
		b.PutCmd("iptables", []string{"-L", "-n", "--line-numbers"},
			"Chain INPUT (policy DROP)\nnum  target     prot opt source               destination\n1    ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:22\n", 0)
	})
	info := &models.SecurityInfo{}
	parseFirewall(context.Background(), info)
	if !info.FirewallActive || info.FirewallType != "iptables" {
		t.Errorf("expected the dispatcher to fall through to the live iptables ruleset, got %+v", info)
	}
	if !info.FirewallConfigOnlyUnverified {
		t.Error("expected FirewallConfigOnlyUnverified=true to survive from the nftables probe")
	}
}

// TestParseFirewall_FirewalldHitReturnsImmediately guards the dispatcher's
// first (highest-priority) branch: a running firewalld must short-circuit
// parseFirewall — ufw/nft/iptables must never even be consulted.
func TestParseFirewall_FirewalldHitReturnsImmediately(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("firewall-cmd", []string{"--state"}, "running\n", 0)
		b.PutCmd("firewall-cmd", []string{"--get-default-zone"}, "public\n", 0)
		b.PutCmd("firewall-cmd", []string{"--list-services"}, "ssh\n", 0)
		// Deliberately no ufw/nft/iptables fixtures seeded — if the dispatcher
		// fell through past firewalld, those unresolved lookups would panic or
		// mis-report rather than silently succeed, making this a real guard.
	})
	info := &models.SecurityInfo{}
	parseFirewall(context.Background(), info)
	if !info.FirewallActive || info.FirewallType != "firewalld" {
		t.Errorf("expected the dispatcher to stop at firewalld, got %+v", info)
	}
}

// TestParseFirewall_FallsThroughToNFTables guards the third dispatcher branch:
// firewalld and ufw both absent, but nftables has a live non-empty ruleset.
func TestParseFirewall_FallsThroughToNFTables(t *testing.T) {
	rec := &recordingFWSource{runOut: realNFTRuleset}
	defer SetSource(SetSource(rec))

	info := &models.SecurityInfo{}
	parseFirewall(context.Background(), info)
	if !info.FirewallActive || info.FirewallType != "nftables" {
		t.Errorf("expected the dispatcher to fall through to nftables, got %+v", info)
	}
}

// TestParseFirewall_FallsThroughToIPTables guards the fourth (last non-empty)
// dispatcher branch: firewalld, ufw, and nftables all absent, but a legacy
// iptables ruleset with rules is present.
func TestParseFirewall_FallsThroughToIPTables(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{"lookpath/iptables": []byte("/usr/sbin/iptables")}, nil, func(b *source.Bundle) {
		b.PutCmdNotFound("firewall-cmd", []string{"--state"})
		b.PutCmdNotFound("ufw", []string{"status"})
		b.PutGlob("/etc/nftables.conf", nil)
		b.PutGlob("/etc/nftables.d/*.nft", nil)
		b.PutCmd("iptables", []string{"-L", "-n", "--line-numbers"},
			"Chain INPUT (policy DROP)\nnum  target     prot opt source               destination\n1    ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:22\n", 0)
	})
	info := &models.SecurityInfo{}
	parseFirewall(context.Background(), info)
	if !info.FirewallActive || info.FirewallType != "iptables" {
		t.Errorf("expected the dispatcher to fall through to iptables, got %+v", info)
	}
}

// TestParseFirewall_NoneDetected guards the terminal "no firewall" branch: all
// four backends absent must set FirewallActive=false and SSHAllowed=true
// (everything reachable), not leave SSHAllowed at its zero value (false),
// which would misreport SSH as blocked on a completely unprotected host.
func TestParseFirewall_NoneDetected(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("firewall-cmd", []string{"--state"})
		b.PutCmdNotFound("ufw", []string{"status"})
		b.PutGlob("/etc/nftables.conf", nil)
		b.PutGlob("/etc/nftables.d/*.nft", nil)
	})
	info := &models.SecurityInfo{}
	parseFirewall(context.Background(), info)
	if info.FirewallActive {
		t.Errorf("expected FirewallActive=false with no backend detected, got %+v", info)
	}
	if !info.SSHAllowed {
		t.Error("no firewall detected must set SSHAllowed=true (everything reachable), not leave it false")
	}
}
