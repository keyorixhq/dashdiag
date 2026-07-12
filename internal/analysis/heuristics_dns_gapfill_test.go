package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Fills branch gaps in checkDNS: the air-gapped-with-error-detail message, the
// both-internal-and-external-failing CRIT (with and without ResolvTestError), and
// the slow-latency WARN branch.

func TestCheckDNS_AirGappedWithResolvTestError(t *testing.T) {
	t.Parallel()
	d := models.DNSResolverInfo{
		Available: true, Manager: "systemd-resolved",
		ExternalResolvesOK: false, InternalResolvesOK: true,
		Nameservers:     []string{"10.0.0.1"},
		ResolvTestError: "timeout",
	}
	out := checkDNS(d)
	if !hasInsightMsg(out, "WARN", "expected on air-gapped / internal-only networks (timeout)") {
		t.Errorf("air-gapped host with a resolv test error must include the error detail, got %+v", out)
	}
}

func TestCheckDNS_BothFailingWithError(t *testing.T) {
	t.Parallel()
	d := models.DNSResolverInfo{
		Available: true, Manager: "systemd-resolved",
		ExternalResolvesOK: false, InternalResolvesOK: false,
		Nameservers:     []string{"10.0.0.1"}, // non-empty, so the earlier "no nameservers" branch is skipped
		ResolvTestError: "connection refused",
	}
	out := checkDNS(d)
	if !hasInsightMsg(out, "CRIT", "cannot resolve external or internal hostnames: connection refused") {
		t.Errorf("both-failing DNS with an error detail must CRIT with that detail, got %+v", out)
	}
}

func TestCheckDNS_BothFailingNoError(t *testing.T) {
	t.Parallel()
	d := models.DNSResolverInfo{
		Available: true, Manager: "systemd-resolved",
		ExternalResolvesOK: false, InternalResolvesOK: false,
		Nameservers: []string{"10.0.0.1"},
	}
	out := checkDNS(d)
	if !hasInsightMsg(out, "CRIT", "cannot resolve external or internal hostnames") {
		t.Errorf("both-failing DNS with no error detail must still CRIT, got %+v", out)
	}
}

func TestCheckDNS_SlowLatencyWarn(t *testing.T) {
	t.Parallel()
	d := models.DNSResolverInfo{
		Available: true, ExternalResolvesOK: true, ExternalLatencyMs: 600,
		Nameservers: []string{"8.8.8.8"},
	}
	out := checkDNS(d)
	if !hasInsightMsg(out, "WARN", "DNS resolution is slow (600ms)") {
		t.Errorf("latency above 500ms must WARN, got %+v", out)
	}
}
