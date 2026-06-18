package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Firewall "couldn't read → silent OK" closures (FALSE_OK_SWEEP #15/#16).
func TestFirewallNotVerified(t *testing.T) {
	// Query failed (non-root EPERM) → INFO, not silent.
	q := models.FirewallInfo{Available: false, StatusReason: "could not read nftables ruleset (run as root?): exit 1"}
	if got := checkFirewall(q); !hasInsightMsg(got, "INFO", "not verified") {
		t.Errorf("query-failed firewall must INFO, got %+v", got)
	}
	// No tooling → INFO.
	none := models.FirewallInfo{Available: false, Status: "unverified", StatusReason: "no firewall tooling (nft/iptables) found — firewall state not verified"}
	if got := checkFirewall(none); !hasInsightMsg(got, "INFO", "not verified") {
		t.Errorf("no-tooling firewall must INFO, got %+v", got)
	}
	// PVE-managed but base ruleset unread → PVE INFO.
	pve := models.FirewallInfo{Available: false, PVEFirewallActive: true, StatusReason: "could not read nftables ruleset"}
	if got := checkFirewall(pve); !hasInsightMsg(got, "INFO", "pve-firewall") {
		t.Errorf("PVE-managed unread firewall must note pve-firewall, got %+v", got)
	}
	// Genuinely absent with no reason (legacy) → still silent (no regression).
	if got := checkFirewall(models.FirewallInfo{Available: false}); len(got) != 0 {
		t.Errorf("no reason → stay silent, got %+v", got)
	}
	// Available + rules → no not-verified INFO.
	ok := models.FirewallInfo{Available: true, Active: true, TotalRules: 5, Backend: "nftables", DefaultDrop: true}
	if got := checkFirewall(ok); hasInsightMsg(got, "INFO", "not verified") {
		t.Errorf("verified active firewall must not say not-verified, got %+v", got)
	}
}
