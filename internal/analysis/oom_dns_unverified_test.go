package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// OOM / DNS "source unreadable → silent OK" closures (FALSE_OK_SWEEP #44/#17).

func TestOOMNotVerified(t *testing.T) {
	// kernel log unreadable → INFO, not silent.
	if got := checkOOM(models.OOMInfo{Available: true, StatusReason: "kernel log unreadable (journalctl -k and dmesg both failed)"}); !hasInsightMsg(got, "INFO", "not verified") {
		t.Errorf("unreadable kernel log must INFO, got %+v", got)
	}
	// verified, zero events → clean.
	if got := checkOOM(models.OOMInfo{Available: true, EventsLast24h: 0}); len(got) != 0 {
		t.Errorf("verified 0 events must be clean, got %+v", got)
	}
}

func TestDNSNoNameserversFailing(t *testing.T) {
	// no nameservers + resolution failing + Manager none → CRIT (was silent).
	d := models.DNSResolverInfo{Available: true, ExternalResolvesOK: false, InternalResolvesOK: false, Manager: "none", ResolvTestError: "lookup failed"}
	if got := checkDNS(d); !hasInsightMsg(got, "CRIT", "no nameservers") {
		t.Errorf("no-nameserver failing DNS must CRIT, got %+v", got)
	}
	// /etc/hosts-only host (internal resolves) → not the misconfigured CRIT.
	d2 := models.DNSResolverInfo{Available: true, ExternalResolvesOK: false, InternalResolvesOK: true, Manager: "none"}
	if got := checkDNS(d2); hasInsightMsg(got, "CRIT", "no nameservers") {
		t.Errorf("/etc/hosts host must not get the misconfigured CRIT, got %+v", got)
	}
}
