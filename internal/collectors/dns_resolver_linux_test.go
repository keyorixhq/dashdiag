//go:build linux

package collectors

import (
	"context"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestResolvConfMode(t *testing.T) {
	t.Parallel()
	cases := []struct {
		target    string
		isSymlink bool
		want      string
	}{
		{"/run/systemd/resolve/stub-resolv.conf", true, "stub"},
		{"/run/systemd/resolve/resolv.conf", true, "uplink"},
		{"/etc/some/other.conf", true, "custom"},
		{"", false, "custom"},
	}
	for _, c := range cases {
		if got := resolvConfMode(c.target, c.isSymlink); got != c.want {
			t.Errorf("resolvConfMode(%q,%v) = %q, want %q", c.target, c.isSymlink, got, c.want)
		}
	}
}

const sampleStatusDegraded = `Global
       Protocols: -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
resolv.conf mode: stub
       DNS Servers: 1.2.3.4

Link 2 (eth0)
    Current Scopes: DNS
         Protocols: +DefaultRoute -DNSOverTLS DNSSEC=no/unsupported
Current DNS Server: 1.2.3.4
       DNS Servers: 1.2.3.4
        DNS Domain: ~.
`

func TestParseResolvectlStatus(t *testing.T) {
	t.Parallel()
	info := &models.ResolverAuditInfo{}
	parseResolvectlStatus(sampleStatusDegraded, info)

	if info.DNSSECActive != "no/unsupported" {
		t.Errorf("global DNSSEC active = %q, want no/unsupported", info.DNSSECActive)
	}
	if info.DoTStatus != "no" {
		t.Errorf("DoT = %q, want no", info.DoTStatus)
	}
	var eth0 *models.ResolverLinkDNS
	for i := range info.LinkDNS {
		if info.LinkDNS[i].Link == "eth0" {
			eth0 = &info.LinkDNS[i]
		}
	}
	if eth0 == nil {
		t.Fatal("eth0 link not parsed")
	}
	if len(eth0.Servers) != 1 || eth0.Servers[0] != "1.2.3.4" {
		t.Errorf("eth0 servers = %v, want [1.2.3.4]", eth0.Servers)
	}
}

// TestParseResolvectlStatus_NoGlobalFallsBackToFirstLink guards the older-
// resolvectl fallback: when there is no "Global" section at all (so
// DNSSECActive is never set from it), the first real link with a non-empty
// DNSSEC value must supply DNSSECActive instead of leaving it empty.
func TestParseResolvectlStatus_NoGlobalFallsBackToFirstLink(t *testing.T) {
	t.Parallel()
	const noGlobalStatus = `Link 3 (wlan0)
    Current Scopes: DNS
         Protocols: -DNSOverTLS DNSSEC=no
       DNS Servers: 8.8.8.8

Link 2 (eth0)
    Current Scopes: DNS
         Protocols: +DNSOverTLS DNSSEC=yes
       DNS Servers: 1.1.1.1
`
	info := &models.ResolverAuditInfo{}
	parseResolvectlStatus(noGlobalStatus, info)
	if info.DNSSECActive != "no" {
		t.Errorf("DNSSECActive = %q, want %q (the first real link's DNSSEC value)", info.DNSSECActive, "no")
	}
}

func TestParseProtocolsDoT(t *testing.T) {
	t.Parallel()
	cases := []struct {
		line       string
		wantDNSSEC string
		wantDoT    string
	}{
		{"Protocols: +DefaultRoute +DNSOverTLS DNSSEC=yes", "yes", "yes"},
		{"Protocols: -DNSOverTLS DNSSEC=no/unsupported", "no/unsupported", "no"},
		{"Protocols: DNSOverTLS=opportunistic DNSSEC=allow-downgrade", "allow-downgrade", "opportunistic"},
	}
	for _, c := range cases {
		d, dot := parseProtocols(c.line)
		if d != c.wantDNSSEC || dot != c.wantDoT {
			t.Errorf("parseProtocols(%q) = (%q,%q), want (%q,%q)", c.line, d, dot, c.wantDNSSEC, c.wantDoT)
		}
	}
}

func TestParseResolvedConfDNSSEC(t *testing.T) {
	t.Parallel()
	in := `# resolved.conf
[Resolve]
#DNSSEC=allow-downgrade
DNSSEC=yes
DNSOverTLS=opportunistic
`
	if got, err := parseResolvedConfDNSSEC(strings.NewReader(in)); err != nil || got != "yes" {
		t.Errorf("DNSSEC = %q, err = %v, want yes, nil", got, err)
	}
	if got, err := parseResolvedConfDNSSEC(strings.NewReader("[Resolve]\n")); err != nil || got != "" {
		t.Errorf("DNSSEC = %q, err = %v, want empty (unset), nil", got, err)
	}
	// A single line exceeding bufio.Scanner's default 64KB token limit must
	// surface as a wrapped scan error, not silently succeed with a partial val.
	huge := strings.Repeat("x", 100*1024)
	if _, err := parseResolvedConfDNSSEC(strings.NewReader(huge)); err == nil {
		t.Error("expected a scan error for an oversized line")
	}
}

func TestComputeDNSSECDegrade(t *testing.T) {
	t.Parallel()

	// Configured yes, effective no/unsupported on eth0 → degraded with reason.
	info := &models.ResolverAuditInfo{
		DNSSECConfigured: "yes",
		DNSSECActive:     "no/unsupported",
		LinkDNS: []models.ResolverLinkDNS{
			{Link: "global", DNSSEC: "no/unsupported"},
			{Link: "eth0", DNSSEC: "no/unsupported", Servers: []string{"1.2.3.4"}},
		},
	}
	computeDNSSECDegrade(info)
	if !info.DNSSECDegraded {
		t.Fatal("expected DNSSECDegraded=true")
	}
	if !strings.Contains(info.DNSSECDegradedReason, "1.2.3.4") || !strings.Contains(info.DNSSECDegradedReason, "eth0") {
		t.Errorf("reason missing server/link: %q", info.DNSSECDegradedReason)
	}

	// Configured yes, effective yes → not degraded.
	ok := &models.ResolverAuditInfo{DNSSECConfigured: "yes", DNSSECActive: "yes"}
	computeDNSSECDegrade(ok)
	if ok.DNSSECDegraded {
		t.Error("expected not degraded when active=yes")
	}

	// allow-downgrade configured → a downgrade is expected, not a fault.
	ad := &models.ResolverAuditInfo{DNSSECConfigured: "allow-downgrade", DNSSECActive: "no/unsupported"}
	computeDNSSECDegrade(ad)
	if ad.DNSSECDegraded {
		t.Error("expected not degraded when configured=allow-downgrade")
	}

	// Configured yes, effective "no" (NOT containing "unsupported") → the
	// generic "resolved reports DNSSEC=%s" reason branch, distinct from the
	// "upstream does not support" reason above.
	plain := &models.ResolverAuditInfo{
		DNSSECConfigured: "yes",
		DNSSECActive:     "no",
		LinkDNS: []models.ResolverLinkDNS{
			{Link: "eth0", DNSSEC: "no"},
		},
	}
	computeDNSSECDegrade(plain)
	if !plain.DNSSECDegraded {
		t.Fatal("expected DNSSECDegraded=true")
	}
	if !strings.Contains(plain.DNSSECDegradedReason, "resolved reports DNSSEC=no") {
		t.Errorf("reason = %q, want the generic 'resolved reports DNSSEC=no' branch", plain.DNSSECDegradedReason)
	}
}

func TestParseDNSSECTestResult(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		out        string
		wantPassed bool
		wantSub    string
	}{
		{"validated", "sigok...: 1.2.3.4\n-- Data is authenticated: yes\n", true, ""},
		{"servfail", "sigok...: resolve call failed: SERVFAIL\n", false, "SERVFAIL"},
		{"timeout", "sigok...: Connection timed out\n", false, "timeout"},
		{"not-auth", "sigok...: 1.2.3.4\n-- Data is authenticated: no\n", false, "not DNSSEC-authenticated"},
	}
	for _, c := range cases {
		passed, errStr := parseDNSSECTestResult(c.out, nil, nil)
		if passed != c.wantPassed {
			t.Errorf("%s: passed = %v, want %v", c.name, passed, c.wantPassed)
		}
		if c.wantSub != "" && !strings.Contains(errStr, c.wantSub) {
			t.Errorf("%s: errStr = %q, want substring %q", c.name, errStr, c.wantSub)
		}
	}

	// Context error (deadline) is always treated as timeout, never SERVFAIL.
	if passed, errStr := parseDNSSECTestResult("", context.DeadlineExceeded, context.DeadlineExceeded); passed ||
		!strings.Contains(errStr, "timeout") {
		t.Errorf("ctx deadline: got (%v,%q), want graceful timeout", passed, errStr)
	}

	// No recognizable keyword AND err==nil AND ctxErr==nil — the final
	// unconditional fallback, distinct from the err!=nil generic-error branch
	// covered elsewhere (TestParseDNSSECTestResult_GenericErrFallback).
	if passed, errStr := parseDNSSECTestResult("some unrelated resolvectl output\n", nil, nil); passed ||
		errStr != "no DNSSEC authentication reported" {
		t.Errorf("got (%v,%q), want (false, 'no DNSSEC authentication reported')", passed, errStr)
	}
}

func TestIsVPNInterfaceName(t *testing.T) {
	t.Parallel()
	vpn := []string{"tun0", "wg0", "wg-home", "nordlynx", "proton0"}
	notVPN := []string{"eth0", "wlan0", "enp3s0", "lo", "docker0", "br0"}
	for _, n := range vpn {
		if !isVPNInterfaceName(n) {
			t.Errorf("%q should be detected as VPN", n)
		}
	}
	for _, n := range notVPN {
		if isVPNInterfaceName(n) {
			t.Errorf("%q should NOT be detected as VPN", n)
		}
	}
}

func TestParseNmcliDNS(t *testing.T) {
	t.Parallel()
	in := `GENERAL.DEVICE: eth0
IP4.ADDRESS[1]: 192.168.1.50/24
IP4.DNS[1]: 192.168.1.1
IP4.DNS[2]: 9.9.9.9
GENERAL.DEVICE: lo
IP4.DNS[1]: 192.168.1.1
`
	got := parseNmcliDNS(in)
	if len(got) != 2 || got[0] != "192.168.1.1" || got[1] != "9.9.9.9" {
		t.Errorf("parseNmcliDNS = %v, want [192.168.1.1 9.9.9.9] (deduped)", got)
	}

	// A ".DNS"-containing line with no colon at all must be skipped, not panic
	// on line[idx+1:] with idx==-1.
	noColon := "IP4.DNS malformed no colon here\nIP4.DNS[1]: 1.2.3.4\n"
	if got := parseNmcliDNS(noColon); len(got) != 1 || got[0] != "1.2.3.4" {
		t.Errorf("parseNmcliDNS(malformed) = %v, want [1.2.3.4] (colon-less line skipped)", got)
	}
}

func TestCheckVPNDNS_NoFalsePositive(t *testing.T) {
	t.Parallel()
	// No VPN interface → VPNDNSIntegrated stays nil (no warning).
	info := &models.ResolverAuditInfo{VPNInterface: ""}
	checkVPNDNS(info)
	if info.VPNDNSIntegrated != nil {
		t.Errorf("expected nil VPNDNSIntegrated with no VPN, got %v", *info.VPNDNSIntegrated)
	}
}

func TestDNSResolverCollector_ReturnsResult(t *testing.T) {
	t.Parallel()
	c := NewDNSResolverCollector()
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info, ok := res.(*models.ResolverAuditInfo)
	if !ok || info == nil {
		t.Fatalf("expected *models.ResolverAuditInfo, got %T", res)
	}
	if !info.Detected {
		t.Error("Detected should be true on Linux")
	}
	if info.ResolverType == "" {
		t.Error("ResolverType should be set")
	}
}
