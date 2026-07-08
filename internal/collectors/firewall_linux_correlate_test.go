//go:build linux

package collectors

import (
	"context"
	"fmt"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// procNetTCPListening builds a fake /proc/net/tcp body with one LISTEN entry
// per port, bound to the wildcard address (0.0.0.0) so it counts as exposed.
func procNetTCPListening(ports ...int) string {
	body := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	for i, p := range ports {
		body += fmt.Sprintf("%4d: 00000000:%04X 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 %d 1 0000000000000000 100 0 0 10 0\n",
			i+1, p, 10000+i)
	}
	return body
}

func TestListeningExposedTCPPorts(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/net/tcp", []byte(procNetTCPListening(22, 8080)))
		b.PutFile("/proc/net/tcp6", []byte(""))
	})
	ports := listeningExposedTCPPorts()
	if len(ports) != 2 || ports[0] != 22 || ports[1] != 8080 {
		t.Errorf("expected [22 8080], got %v", ports)
	}
}

func TestListeningExposedTCPPorts_NoProcFiles(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {})
	ports := listeningExposedTCPPorts()
	if len(ports) != 0 {
		t.Errorf("expected no ports when /proc/net/tcp{,6} are unreadable, got %v", ports)
	}
}

const iptListLineNumbersDropPort22 = `Chain INPUT (policy DROP)
num  target     prot opt source               destination
1    ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:22`

func TestCollectIPTables_CorrelatesBlockedListeners(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("iptables", []string{"-L", "-n", "--line-numbers"}, iptListLineNumbersDropPort22, 0)
		b.PutCmd("iptables", []string{"-t", "filter", "-nvL", "INPUT"}, iptInputPhotonDefault, 0)
		b.PutFile("/proc/net/tcp", []byte(procNetTCPListening(22, 8080)))
		b.PutFile("/proc/net/tcp6", []byte(""))
	})

	info := &models.FirewallInfo{}
	if _, err := collectIPTables(context.Background(), info); err != nil {
		t.Fatalf("collectIPTables: %v", err)
	}
	if !info.DefaultDrop {
		t.Fatal("expected DefaultDrop=true for a DROP-policy INPUT chain")
	}
	if len(info.BlockedListeners) != 1 || info.BlockedListeners[0] != 8080 {
		t.Errorf("expected only port 8080 flagged as blocked (22 is accepted), got %v", info.BlockedListeners)
	}
}

func TestCollectIPTables_Unreadable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("iptables", []string{"-L", "-n", "--line-numbers"})
	})
	info := &models.FirewallInfo{}
	if _, err := collectIPTables(context.Background(), info); err != nil {
		t.Fatalf("collectIPTables: %v", err)
	}
	if info.Status != "unverified" {
		t.Errorf("expected Status=unverified when iptables is unreadable, got %q", info.Status)
	}
}

func TestCorrelateBlockedListenersNFT(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/net/tcp", []byte(procNetTCPListening(22, 9090)))
		b.PutFile("/proc/net/tcp6", []byte(""))
	})
	info := &models.FirewallInfo{}
	correlateBlockedListenersNFT(realNFTRuleset, info) // realNFTRuleset (firewall_active_linux_test.go) accepts only tcp dport 22
	if len(info.BlockedListeners) != 1 || info.BlockedListeners[0] != 9090 {
		t.Errorf("expected only port 9090 flagged as blocked, got %v", info.BlockedListeners)
	}
}

func TestLookPathOK(t *testing.T) {
	withLookPathFixture(t, map[string]bool{"nft": true}, func(b *source.Bundle) {})
	if !lookPathOK("nft") {
		t.Error("expected lookPathOK(nft) to report true when present")
	}
	if lookPathOK("iptables") {
		t.Error("expected lookPathOK(iptables) to report false when absent")
	}
}

func TestPveFirewallActive(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "pve-firewall"}, "active\n", 0)
	})
	if !pveFirewallActive(context.Background()) {
		t.Error("expected pveFirewallActive() to report true when the unit is active")
	}
}

func TestPveFirewallActive_NotActive(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "pve-firewall"}, "inactive\n", 3)
	})
	if pveFirewallActive(context.Background()) {
		t.Error("expected pveFirewallActive() to report false when the unit is inactive")
	}
}
