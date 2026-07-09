//go:build linux

package collectors

import (
	"context"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

// Fixture-backed tests for DNSResolverCollector. These touch SetSource via
// withFixtureSource/withCombinedFixture, so per repo convention none of these
// (or their ancestor funcs) may use t.Parallel().

func TestDNSResolverCollectorIdentity_Fixtures(t *testing.T) {
	c := NewDNSResolverCollector()
	if c.Name() != "DNS resolver" {
		t.Errorf("Name() = %q, want %q", c.Name(), "DNS resolver")
	}
	if c.Timeout() != 9e9 {
		t.Errorf("Timeout() = %v, want 9s", c.Timeout())
	}
}

// TestDetectResolver_SystemdResolvedActive guards the primary detection
// branch: systemd-resolved reporting active must win outright.
func TestDetectResolver_SystemdResolvedActive(t *testing.T) {
	withCombinedFixture(t, nil, nil, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "systemd-resolved"}, "active\n", 0)
	})
	info := &models.ResolverAuditInfo{}
	detectResolver(context.Background(), info)
	if info.ResolverType != "systemd-resolved" || !info.ResolverActive {
		t.Errorf("got ResolverType=%q ResolverActive=%v, want systemd-resolved/true", info.ResolverType, info.ResolverActive)
	}
}

// TestDetectResolver_FallbackToNetworkManager guards the loop through
// NetworkManager/dnsmasq/unbound when systemd-resolved is inactive.
func TestDetectResolver_FallbackToNetworkManager(t *testing.T) {
	withCombinedFixture(t, nil, nil, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "systemd-resolved"}, "inactive\n", 3)
		b.PutCmd("systemctl", []string{"is-active", "NetworkManager"}, "active\n", 0)
	})
	info := &models.ResolverAuditInfo{}
	detectResolver(context.Background(), info)
	if info.ResolverType != "NetworkManager" || !info.ResolverActive {
		t.Errorf("got ResolverType=%q ResolverActive=%v, want NetworkManager/true", info.ResolverType, info.ResolverActive)
	}
}

// TestDetectResolver_StaticFallback guards the final fallback when nothing is
// active at all.
func TestDetectResolver_StaticFallback(t *testing.T) {
	withCombinedFixture(t, nil, nil, func(b *source.Bundle) {
		b.PutCmdNotFound("systemctl", []string{"is-active", "systemd-resolved"})
		b.PutCmdNotFound("systemctl", []string{"is-active", "NetworkManager"})
		b.PutCmdNotFound("systemctl", []string{"is-active", "dnsmasq"})
		b.PutCmdNotFound("systemctl", []string{"is-active", "unbound"})
	})
	info := &models.ResolverAuditInfo{}
	detectResolver(context.Background(), info)
	if info.ResolverType != "static" || info.ResolverActive {
		t.Errorf("got ResolverType=%q ResolverActive=%v, want static/false", info.ResolverType, info.ResolverActive)
	}
}

// TestRunResolvectl guards the exec-wrapper: stdout+stderr are combined
// (SERVFAIL/timeout diagnostics land on stderr).
func TestRunResolvectl(t *testing.T) {
	withCombinedFixture(t, nil, nil, func(b *source.Bundle) {
		b.PutCmd("resolvectl", []string{"status"}, "Global\n  Protocols: DNSSEC=yes\n", 0)
	})
	out, err := runResolvectl(context.Background(), "status")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "DNSSEC=yes") {
		t.Errorf("out = %q, want to contain DNSSEC=yes", out)
	}
}

// TestRunDNSSECTest guards the live-probe wrapper: parses `resolvectl query`
// output through parseDNSSECTestResult and always sets DNSSECTestRan.
func TestRunDNSSECTest(t *testing.T) {
	withCombinedFixture(t, nil, nil, func(b *source.Bundle) {
		b.PutCmd("resolvectl", []string{"query", sigokDomain},
			sigokDomain+": 194.150.168.168\n-- Data is authenticated: yes\n", 0)
	})
	info := &models.ResolverAuditInfo{}
	runDNSSECTest(context.Background(), info)
	if !info.DNSSECTestRan {
		t.Error("expected DNSSECTestRan=true")
	}
	if !info.DNSSECTestPassed {
		t.Errorf("expected DNSSECTestPassed=true, error=%q", info.DNSSECTestError)
	}
}

// TestRunDNSSECTest_Failure guards the SERVFAIL branch end to end through the
// exec wrapper.
func TestRunDNSSECTest_Failure(t *testing.T) {
	withCombinedFixture(t, nil, nil, func(b *source.Bundle) {
		b.PutCmd("resolvectl", []string{"query", sigokDomain},
			sigokDomain+": resolve call failed: SERVFAIL\n", 1)
	})
	info := &models.ResolverAuditInfo{}
	runDNSSECTest(context.Background(), info)
	if info.DNSSECTestPassed {
		t.Error("expected DNSSECTestPassed=false on SERVFAIL")
	}
	if !strings.Contains(info.DNSSECTestError, "SERVFAIL") {
		t.Errorf("DNSSECTestError = %q, want to contain SERVFAIL", info.DNSSECTestError)
	}
}

// TestVpnInterfaceUp guards the operstate classification: explicit "down" is
// inactive, everything else (including "unknown", the WireGuard case) is up,
// and a missing operstate file (readFile error) also defaults to up.
func TestVpnInterfaceUp(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/sys/class/net/tun0/operstate", []byte("up\n"))
		b.PutFile("/sys/class/net/wg0/operstate", []byte("unknown\n"))
		b.PutFile("/sys/class/net/eth0/operstate", []byte("down\n"))
	})
	if !vpnInterfaceUp("tun0") {
		t.Error("tun0 (up) should report up")
	}
	if !vpnInterfaceUp("wg0") {
		t.Error("wg0 (unknown — WireGuard) should report up")
	}
	if vpnInterfaceUp("eth0") {
		t.Error("eth0 (down) should report down")
	}
	if !vpnInterfaceUp("ghost0") {
		t.Error("a missing operstate file should default to up (assume active tun device)")
	}
}

// TestDetectVPNInterface guards the full sysfs-scan pipeline: only a VPN-named,
// up interface is returned; non-VPN and down VPN interfaces are skipped.
func TestDetectVPNInterface(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/sys/class/net", []string{"eth0", "lo", "wg0"})
		b.PutFile("/sys/class/net/wg0/operstate", []byte("unknown\n"))
	})
	if got := detectVPNInterface(); got != "wg0" {
		t.Errorf("detectVPNInterface() = %q, want wg0", got)
	}

	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/sys/class/net", []string{"eth0", "lo", "tun0"})
		b.PutFile("/sys/class/net/tun0/operstate", []byte("down\n"))
	})
	if got := detectVPNInterface(); got != "" {
		t.Errorf("detectVPNInterface() = %q, want empty (only VPN iface is down)", got)
	}

	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/sys/class/net", []string{"eth0", "lo"})
	})
	if got := detectVPNInterface(); got != "" {
		t.Errorf("detectVPNInterface() = %q, want empty (no VPN interfaces at all)", got)
	}
}

// TestCheckVPNDNS_Integrated guards the positive VPN-DNS-routing path: a VPN
// interface present in LinkDNS with servers must set VPNDNSIntegrated=true.
func TestCheckVPNDNS_Integrated(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/sys/class/net", []string{"eth0", "wg0"})
		b.PutFile("/sys/class/net/wg0/operstate", []byte("unknown\n"))
	})
	info := &models.ResolverAuditInfo{
		LinkDNS: []models.ResolverLinkDNS{
			{Link: "wg0", Servers: []string{"10.2.0.1"}},
		},
	}
	checkVPNDNS(info)
	if info.VPNInterface != "wg0" {
		t.Fatalf("VPNInterface = %q, want wg0", info.VPNInterface)
	}
	if info.VPNDNSIntegrated == nil || !*info.VPNDNSIntegrated {
		t.Error("expected VPNDNSIntegrated=true — wg0 has DNS servers routed")
	}
}

// TestCheckVPNDNS_NotIntegrated guards the negative case: VPN interface
// present but absent from LinkDNS (or with no servers) — DNS not routed
// through the VPN, a real misconfiguration finding.
func TestCheckVPNDNS_NotIntegrated(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/sys/class/net", []string{"eth0", "wg0"})
		b.PutFile("/sys/class/net/wg0/operstate", []byte("unknown\n"))
	})
	info := &models.ResolverAuditInfo{
		LinkDNS: []models.ResolverLinkDNS{
			{Link: "eth0", Servers: []string{"192.168.1.1"}},
		},
	}
	checkVPNDNS(info)
	if info.VPNDNSIntegrated == nil || *info.VPNDNSIntegrated {
		t.Error("expected VPNDNSIntegrated=false — wg0 has no entry with servers in LinkDNS")
	}
}

// TestCheckVPNDNS_NoLinkDNSData guards the "can't verify" branch: a VPN
// interface is present but LinkDNS is empty (resolver isn't systemd-resolved)
// — must stay nil, not false (false would be a false-positive misconfig claim).
func TestCheckVPNDNS_NoLinkDNSData(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutDir("/sys/class/net", []string{"tun0"})
		b.PutFile("/sys/class/net/tun0/operstate", []byte("up\n"))
	})
	info := &models.ResolverAuditInfo{}
	checkVPNDNS(info)
	if info.VPNInterface != "tun0" {
		t.Fatalf("VPNInterface = %q, want tun0", info.VPNInterface)
	}
	if info.VPNDNSIntegrated != nil {
		t.Errorf("expected VPNDNSIntegrated=nil when LinkDNS is empty, got %v", *info.VPNDNSIntegrated)
	}
}

// TestResolvConfNameservers guards the direct-file-read fallback used both by
// nmDNSFallback and the sudo-skip branch.
func TestResolvConfNameservers(t *testing.T) {
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/resolv.conf", []byte("# generated\nnameserver 1.1.1.1\nnameserver 8.8.8.8\nsearch example.com\n"))
	})
	got := resolvConfNameservers()
	if len(got) != 2 || got[0] != "1.1.1.1" || got[1] != "8.8.8.8" {
		t.Errorf("resolvConfNameservers() = %v, want [1.1.1.1 8.8.8.8]", got)
	}

	withFixtureSource(t, func(_ *source.Bundle) {})
	if got := resolvConfNameservers(); got != nil {
		t.Errorf("expected nil for a missing resolv.conf, got %v", got)
	}
}

// TestNmDNSFallback_NmcliSucceeds guards the primary nmcli path when not
// running under sudo.
func TestNmDNSFallback_NmcliSucceeds(t *testing.T) {
	t.Setenv("SUDO_USER", "")
	withCombinedFixture(t, nil, nil, func(b *source.Bundle) {
		b.PutCmd("nmcli", []string{"dev", "show"}, "GENERAL.DEVICE: eth0\nIP4.DNS[1]: 192.168.1.1\n", 0)
	})
	info := &models.ResolverAuditInfo{ResolverType: "NetworkManager"}
	nmDNSFallback(context.Background(), info)
	if len(info.NMNameservers) != 1 || info.NMNameservers[0] != "192.168.1.1" {
		t.Errorf("NMNameservers = %v, want [192.168.1.1]", info.NMNameservers)
	}
	if !strings.Contains(info.FallbackNote, "NetworkManager") {
		t.Errorf("FallbackNote = %q, want mention of NetworkManager", info.FallbackNote)
	}
}

// TestNmDNSFallback_SudoSkipsNmcli guards the documented sudo-skip: nmcli
// depends on a D-Bus session bus and fails silently under sudo, so the
// fallback must read resolv.conf directly instead and note it.
func TestNmDNSFallback_SudoSkipsNmcli(t *testing.T) {
	t.Setenv("SUDO_USER", "root")
	withFixtureSource(t, func(b *source.Bundle) {
		b.PutFile("/etc/resolv.conf", []byte("nameserver 9.9.9.9\n"))
	})
	info := &models.ResolverAuditInfo{ResolverType: "NetworkManager"}
	nmDNSFallback(context.Background(), info)
	if len(info.NMNameservers) != 1 || info.NMNameservers[0] != "9.9.9.9" {
		t.Errorf("NMNameservers = %v, want [9.9.9.9]", info.NMNameservers)
	}
	if !strings.Contains(info.FallbackNote, "nmcli skipped under sudo") {
		t.Errorf("FallbackNote = %q, want to mention nmcli skipped under sudo", info.FallbackNote)
	}
}

// TestNmDNSFallback_NmcliFails guards the nmcli-error fallback: nmcli exits
// non-zero (or command absent) → fall back to resolv.conf.
func TestNmDNSFallback_NmcliFails(t *testing.T) {
	t.Setenv("SUDO_USER", "")
	withCombinedFixture(t, nil, nil, func(b *source.Bundle) {
		b.PutCmdNotFound("nmcli", []string{"dev", "show"})
		b.PutFile("/etc/resolv.conf", []byte("nameserver 4.4.4.4\n"))
	})
	info := &models.ResolverAuditInfo{ResolverType: "NetworkManager"}
	nmDNSFallback(context.Background(), info)
	if len(info.NMNameservers) != 1 || info.NMNameservers[0] != "4.4.4.4" {
		t.Errorf("NMNameservers = %v, want [4.4.4.4]", info.NMNameservers)
	}
}

// TestNmDNSFallback_StaticNote guards the FallbackNote wording for the
// "static"/"none" resolver-type branch (no managing daemon at all).
func TestNmDNSFallback_StaticNote(t *testing.T) {
	t.Setenv("SUDO_USER", "")
	withCombinedFixture(t, nil, nil, func(b *source.Bundle) {
		b.PutCmdNotFound("nmcli", []string{"dev", "show"})
	})
	info := &models.ResolverAuditInfo{ResolverType: "static"}
	nmDNSFallback(context.Background(), info)
	if !strings.Contains(info.FallbackNote, "no systemd-resolved") {
		t.Errorf("FallbackNote = %q, want the static-specific wording", info.FallbackNote)
	}
}

// TestDNSResolverCollector_Collect_SystemdResolvedPath exercises Collect end
// to end down the systemd-resolved branch: resolvectl status/query both
// fixture-seeded, resolved.conf DNSSEC setting read, VPN check run.
func TestDNSResolverCollector_Collect_SystemdResolvedPath(t *testing.T) {
	withCombinedFixture(t, nil, nil, func(b *source.Bundle) {
		b.PutCmd("systemctl", []string{"is-active", "systemd-resolved"}, "active\n", 0)
		b.PutCmd("resolvectl", []string{"status"},
			"Global\n  Protocols: -DNSOverTLS DNSSEC=yes\nresolv.conf mode: stub\n  DNS Servers: 1.1.1.1\n\nLink 2 (eth0)\n  Protocols: -DNSOverTLS DNSSEC=yes\n  DNS Servers: 1.1.1.1\n", 0)
		b.PutFile("/etc/systemd/resolved.conf", []byte("[Resolve]\nDNSSEC=yes\n"))
		b.PutCmd("resolvectl", []string{"query", sigokDomain}, sigokDomain+": 1.2.3.4\n-- Data is authenticated: yes\n", 0)
		b.PutDir("/sys/class/net", []string{"eth0"})
	})
	c := NewDNSResolverCollector()
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := res.(*models.ResolverAuditInfo)
	if info.ResolverType != "systemd-resolved" {
		t.Errorf("ResolverType = %q, want systemd-resolved", info.ResolverType)
	}
	if info.DNSSECConfigured != "yes" {
		t.Errorf("DNSSECConfigured = %q, want yes", info.DNSSECConfigured)
	}
	if !info.DNSSECTestRan || !info.DNSSECTestPassed {
		t.Errorf("expected DNSSEC test to have run and passed, got ran=%v passed=%v err=%q", info.DNSSECTestRan, info.DNSSECTestPassed, info.DNSSECTestError)
	}
}

// TestLinkName_NoParens guards the fallback branch for older resolvectl
// output that doesn't wrap the interface name in parens.
func TestLinkName_NoParens(t *testing.T) {
	if got := linkName("Link 3"); got != "3" {
		t.Errorf("linkName(no parens) = %q, want %q", got, "3")
	}
}

// TestParseDNSSECTestResult_GenericErrFallback guards the final err!=nil
// branch: resolvectl exits non-zero with no recognizable keyword in stdout —
// the raw output (or error text) becomes the reported error string.
func TestParseDNSSECTestResult_GenericErrFallback(t *testing.T) {
	passed, errStr := parseDNSSECTestResult("", &cmdError{name: "resolvectl", code: 1}, nil)
	if passed {
		t.Error("expected passed=false")
	}
	if !strings.Contains(errStr, "resolvectl") {
		t.Errorf("errStr = %q, want to contain the underlying error text", errStr)
	}
}

// TestDNSResolverCollector_Collect_NonSystemdResolvedPath exercises the
// nmDNSFallback branch of Collect (systemd-resolved inactive).
func TestDNSResolverCollector_Collect_NonSystemdResolvedPath(t *testing.T) {
	t.Setenv("SUDO_USER", "")
	withCombinedFixture(t, nil, nil, func(b *source.Bundle) {
		b.PutCmdNotFound("systemctl", []string{"is-active", "systemd-resolved"})
		b.PutCmd("systemctl", []string{"is-active", "NetworkManager"}, "active\n", 0)
		b.PutCmd("nmcli", []string{"dev", "show"}, "GENERAL.DEVICE: eth0\nIP4.DNS[1]: 192.168.1.1\n", 0)
	})
	c := NewDNSResolverCollector()
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	info := res.(*models.ResolverAuditInfo)
	if info.ResolverType != "NetworkManager" {
		t.Errorf("ResolverType = %q, want NetworkManager", info.ResolverType)
	}
	if len(info.NMNameservers) != 1 || info.NMNameservers[0] != "192.168.1.1" {
		t.Errorf("NMNameservers = %v, want [192.168.1.1]", info.NMNameservers)
	}
}
