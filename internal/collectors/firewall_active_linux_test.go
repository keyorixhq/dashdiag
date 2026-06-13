//go:build linux

package collectors

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// realNFTRuleset is a real `nft list ruleset` dump (alpine nftables, default-drop
// input chain with two rules), captured from the actual tool.
const realNFTRuleset = `table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		tcp dport 22 accept
	}
}
`

// TestParseNFTRulesetActive pins the firewall "active" verdict: a real ruleset with
// rules is active; an EMPTY `nft list ruleset` (nftables installed, no rules — common
// on minimal servers) is NOT active. Previously the nftables path set Active=true
// unconditionally — a latent false-OK where an unprotected host read as "firewall
// active". Now it matches the iptables path (Active requires actual rules).
func TestParseNFTRulesetActive(t *testing.T) {
	var real models.FirewallInfo
	parseNFTRuleset(realNFTRuleset, &real)
	if !real.Active || real.TotalRules == 0 {
		t.Errorf("real ruleset: Active=%v TotalRules=%d, want active with rules", real.Active, real.TotalRules)
	}
	if real.Backend != "nftables" || !real.Available {
		t.Errorf("real ruleset: Backend=%q Available=%v", real.Backend, real.Available)
	}

	var empty models.FirewallInfo
	parseNFTRuleset("", &empty) // empty `nft list ruleset` == no firewall rules
	if empty.Active {
		t.Error("empty nft ruleset must NOT be Active (no rules = no firewall); false-OK regression")
	}
	if !empty.Available || empty.Backend != "nftables" {
		t.Errorf("empty ruleset still detected as the backend: Available=%v Backend=%q", empty.Available, empty.Backend)
	}
}

// TestNFTAndIPTablesActiveAgree pins that the two backends decide "active" the same
// way (the sibling-divergence this fixed): empty -> inactive, rules -> active.
func TestNFTAndIPTablesActiveAgree(t *testing.T) {
	iptEmpty := "Chain INPUT (policy ACCEPT)\ntarget     prot opt source               destination\n"
	iptRules := iptEmpty + "1    ACCEPT     tcp  --  0.0.0.0/0  0.0.0.0/0  tcp dpt:22\n"
	var e, r models.FirewallInfo
	parseIPTList(iptEmpty, &e)
	parseIPTList(iptRules, &r)
	if e.Active {
		t.Error("iptables with no rules must not be Active")
	}
	if !r.Active {
		t.Error("iptables with a rule must be Active")
	}
}
