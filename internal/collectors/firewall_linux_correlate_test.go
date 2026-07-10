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

// TestCollectNFTables_Unreadable guards the nft-ruleset-read error branch: an
// installed-but-unreadable nft (non-root EPERM, the dominant case) must set
// Status=unverified with an explanatory reason, never a silent Available=false
// that reads as "no firewall".
func TestCollectNFTables_Unreadable(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("nft", []string{"list", "ruleset"})
	})
	info := &models.FirewallInfo{}
	got, err := collectNFTables(context.Background(), info)
	if err != nil {
		t.Fatalf("collectNFTables: %v", err)
	}
	if got.Status != "unverified" || got.StatusReason == "" {
		t.Errorf("expected Status=unverified with a reason when nft ruleset is unreadable, got %+v", got)
	}
}

// TestCorrelateBlockedListeners_IPTables_UnreadableSecondRead guards the
// re-read error branch: correlateBlockedListeners issues its OWN `-nvL`
// iptables invocation (distinct from the `-L -n --line-numbers` call in
// collectIPTables), so a race/permission change between the two calls must
// leave BlockedListeners nil rather than crashing or reporting stale data.
func TestCorrelateBlockedListeners_IPTables_UnreadableSecondRead(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmdNotFound("iptables", []string{"-t", "filter", "-nvL", "INPUT"})
	})
	info := &models.FirewallInfo{}
	correlateBlockedListeners(context.Background(), info)
	if info.BlockedListeners != nil {
		t.Errorf("expected nil BlockedListeners when the -nvL re-read fails, got %v", info.BlockedListeners)
	}
}

// TestCorrelateBlockedListeners_IPTables_Indeterminable guards the
// !determinable bail-out: a ruleset with a custom-chain jump (fail2ban,
// firewalld, docker, …) can't be fully reasoned about, so BlockedListeners
// must stay nil rather than mis-flagging a reachable service as blocked.
func TestCorrelateBlockedListeners_IPTables_Indeterminable(t *testing.T) {
	const jumpRuleset = `Chain INPUT (policy DROP)
 pkts bytes target prot opt in out source destination
    0 0 ACCEPT tcp -- * * 0.0.0.0/0 0.0.0.0/0 tcp dpt:22
    0 0 f2b-sshd tcp -- * * 0.0.0.0/0 0.0.0.0/0 multiport dports 22`
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutCmd("iptables", []string{"-t", "filter", "-nvL", "INPUT"}, jumpRuleset, 0)
		b.PutFile("/proc/net/tcp", []byte(procNetTCPListening(22, 8080)))
		b.PutFile("/proc/net/tcp6", []byte(""))
	})
	info := &models.FirewallInfo{}
	correlateBlockedListeners(context.Background(), info)
	if info.BlockedListeners != nil {
		t.Errorf("expected nil BlockedListeners for an indeterminable (jump) ruleset, got %v", info.BlockedListeners)
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

// TestCorrelateBlockedListenersNFT_Indeterminable guards the early-return bail:
// a ruleset with a jump to a custom chain can't be fully reasoned about, so
// BlockedListeners must stay nil rather than risk a false "blocked" flag on a
// port that chain might actually accept.
func TestCorrelateBlockedListenersNFT_Indeterminable(t *testing.T) {
	const jumpRuleset = `table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		jump custom_chain
	}
}
`
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/proc/net/tcp", []byte(procNetTCPListening(9090)))
		b.PutFile("/proc/net/tcp6", []byte(""))
	})
	info := &models.FirewallInfo{}
	correlateBlockedListenersNFT(jumpRuleset, info)
	if info.BlockedListeners != nil {
		t.Errorf("expected nil BlockedListeners for an indeterminable (jump) ruleset, got %v", info.BlockedListeners)
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

// ── parseNFTRange / expandNFTPortElem ───────────────────────────────────────

func TestParseNFTRange(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		s      string
		wantLo int
		wantHi int
		wantOK bool
	}{
		{"valid range", "8000-8002", 8000, 8002, true},
		{"bare number is not a range", "80", 0, 0, false},
		{"reversed range invalid", "100-50", 0, 0, false},
		{"non-numeric invalid", "abc-def", 0, 0, false},
		{"too many hyphens takes first two parts", "8000-8002-9000", 0, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			lo, hi, ok := parseNFTRange(tt.s)
			if lo != tt.wantLo || hi != tt.wantHi || ok != tt.wantOK {
				t.Errorf("parseNFTRange(%q) = (%d,%d,%v), want (%d,%d,%v)", tt.s, lo, hi, ok, tt.wantLo, tt.wantHi, tt.wantOK)
			}
		})
	}
}

func TestExpandNFTPortElem(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		s    string
		want []int
	}{
		{"single port", "80", []int{80}},
		{"small range", "8000-8002", []int{8000, 8001, 8002}},
		{"not a number or range yields nil", "notaport", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := expandNFTPortElem(tt.s)
			if len(got) != len(tt.want) {
				t.Fatalf("expandNFTPortElem(%q) = %v, want %v", tt.s, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("expandNFTPortElem(%q)[%d] = %d, want %d", tt.s, i, got[i], tt.want[i])
				}
			}
		})
	}
}

// ── parsePortRange / iptAcceptedDports ──────────────────────────────────────

func TestParsePortRange(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		s      string
		wantLo int
		wantHi int
		wantOK bool
	}{
		{"valid range", "8000:8002", 8000, 8002, true},
		{"bare number is not a range", "80", 0, 0, false},
		{"reversed range invalid", "100:50", 0, 0, false},
		{"non-numeric invalid", "a:b", 0, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			lo, hi, ok := parsePortRange(tt.s)
			if lo != tt.wantLo || hi != tt.wantHi || ok != tt.wantOK {
				t.Errorf("parsePortRange(%q) = (%d,%d,%v), want (%d,%d,%v)", tt.s, lo, hi, ok, tt.wantLo, tt.wantHi, tt.wantOK)
			}
		})
	}
}

// TestIptAcceptedDports_MultiportRangeAndLiteral guards the "dports" branch's
// mixed list handling: a colon-range element must expand to every port in the
// range, while a plain literal element in the same list is parsed directly —
// this is the one sub-branch of iptAcceptedDports not exercised by the
// existing single-literal-multiport fixtures elsewhere in this package.
func TestIptAcceptedDports_MultiportRangeAndLiteral(t *testing.T) {
	t.Parallel()
	got := iptAcceptedDports("multiport dports 8000:8002,443")
	want := []int{8000, 8001, 8002, 443}
	if len(got) != len(want) {
		t.Fatalf("iptAcceptedDports = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("iptAcceptedDports[%d] = %d, want %d", i, got[i], want[i])
		}
	}
}
