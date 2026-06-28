package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Services bound to all interfaces but dropped by the INPUT policy → WARN naming
// the ports (the "service up but unreachable" footgun). An active ruleset with no
// blocked listeners stays quiet.
func TestCheckFirewallBlockedListeners(t *testing.T) {
	f := models.FirewallInfo{
		Available: true, Active: true, TotalRules: 3, Backend: "iptables",
		DefaultDrop: true, BlockedListeners: []int{8080, 9090},
	}
	got := checkFirewall(f)
	if len(got) != 1 || got[0].Level != "WARN" {
		t.Fatalf("want 1 WARN, got %+v", got)
	}
	if !strings.Contains(got[0].Message, "8080") || !strings.Contains(got[0].Message, "9090") {
		t.Errorf("WARN should name the blocked ports: %q", got[0].Message)
	}
}

func TestCheckFirewallNoBlockedListenersQuiet(t *testing.T) {
	f := models.FirewallInfo{
		Available: true, Active: true, TotalRules: 3, Backend: "iptables", DefaultDrop: true,
	}
	if got := checkFirewall(f); len(got) != 0 {
		t.Errorf("active firewall with no blocked listeners must be quiet, got %+v", got)
	}
}
