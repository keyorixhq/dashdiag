//go:build linux

package collectors

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// DNSResolverCollector audits the resolver feature set for `dsd net deep`:
// systemd-resolved vs NetworkManager, resolv.conf mode (stub/uplink/custom),
// DNSSEC configuration vs effective state, DNS-over-TLS, a live DNSSEC
// validation test, and VPN DNS routing. Linux-only — resolvectl and
// systemd-resolved do not exist on other platforms.
//
// This is additive to the existing /etc/resolv.conf audit (DNSCollector).
type DNSResolverCollector struct{}

func NewDNSResolverCollector() *DNSResolverCollector   { return &DNSResolverCollector{} }
func (c *DNSResolverCollector) Name() string           { return "DNS resolver" }
func (c *DNSResolverCollector) Timeout() time.Duration { return 9 * time.Second }

// sigokDomain is a known-good DNSSEC-signed domain used to verify validation.
const sigokDomain = "sigok.verteiltesysteme.net"

func (c *DNSResolverCollector) Collect(ctx context.Context) (interface{}, error) {
	info := &models.ResolverAuditInfo{Detected: true}

	detectResolver(ctx, info)

	if info.ResolverType == "systemd-resolved" && info.ResolverActive {
		if status, err := runResolvectl(ctx, "status"); err == nil {
			parseResolvectlStatus(status, info)
		}
		if f, err := os.Open("/etc/systemd/resolved.conf"); err == nil {
			info.DNSSECConfigured = parseResolvedConfDNSSEC(f)
			f.Close() //nolint:errcheck
		}
		if info.DNSSECConfigured == "" {
			info.DNSSECConfigured = "allow-downgrade" // systemd default when unset
		}
		computeDNSSECDegrade(info)
		runDNSSECTest(ctx, info)
	} else {
		nmDNSFallback(ctx, info)
	}

	checkVPNDNS(info)
	return info, nil
}

// ── resolver + resolv.conf detection ────────────────────────────────────────

func detectResolver(ctx context.Context, info *models.ResolverAuditInfo) {
	target, err := os.Readlink("/etc/resolv.conf")
	if err == nil {
		info.ResolvConfTarget = target
	}
	info.ResolvConfMode = resolvConfMode(target, err == nil)

	if out, e := runCmd(ctx, "systemctl", "is-active", "systemd-resolved"); e == nil &&
		strings.TrimSpace(out) == "active" {
		info.ResolverType = "systemd-resolved"
		info.ResolverActive = true
		return
	}

	// systemd-resolved inactive — find what else manages DNS.
	for _, svc := range []string{"NetworkManager", "dnsmasq", "unbound"} {
		if out, e := runCmd(ctx, "systemctl", "is-active", svc); e == nil &&
			strings.TrimSpace(out) == "active" {
			info.ResolverType = svc
			info.ResolverActive = true
			return
		}
	}
	info.ResolverType = "static" // plain /etc/resolv.conf, no managing daemon
}

// resolvConfMode classifies /etc/resolv.conf by its symlink target.
//   - stub:   /run/systemd/resolve/stub-resolv.conf (DNSSEC-aware, correct default)
//   - uplink: /run/systemd/resolve/resolv.conf      (bypasses stub, loses split-DNS)
//   - custom: a plain file or any other symlink target (resolved won't manage it)
func resolvConfMode(target string, isSymlink bool) string {
	if !isSymlink {
		return "custom" // plain file — edited directly or distro default
	}
	switch {
	case strings.Contains(target, "stub-resolv.conf"):
		return "stub"
	case strings.Contains(target, "systemd/resolve/resolv.conf"):
		return "uplink"
	default:
		return "custom"
	}
}

// ── resolvectl status parsing ───────────────────────────────────────────────

// parseResolvectlStatus parses `resolvectl status` output into per-link DNS
// data plus the effective global DNSSEC and DNS-over-TLS settings.
//
// Sample:
//
//	Global
//	       Protocols: -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
//	resolv.conf mode: stub
//	     DNS Servers: 192.168.1.1
//	Link 2 (eth0)
//	   Current Scopes: DNS
//	        Protocols: +DefaultRoute -DNSOverTLS DNSSEC=no/unsupported
//	      DNS Servers: 192.168.1.1
func parseResolvectlStatus(status string, info *models.ResolverAuditInfo) {
	var cur *models.ResolverLinkDNS
	flush := func() {
		if cur != nil {
			info.LinkDNS = append(info.LinkDNS, *cur)
			cur = nil
		}
	}

	sc := bufio.NewScanner(strings.NewReader(status))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "Global"):
			flush()
			cur = &models.ResolverLinkDNS{Link: "global"}
		case strings.HasPrefix(line, "Link "):
			flush()
			cur = &models.ResolverLinkDNS{Link: linkName(line)}
		case strings.HasPrefix(line, "DNS Servers:"):
			if cur != nil {
				cur.Servers = strings.Fields(strings.TrimPrefix(line, "DNS Servers:"))
			}
		case strings.HasPrefix(line, "Protocols:"):
			dnssec, dot := parseProtocols(line)
			if cur != nil {
				cur.DNSSEC = dnssec
			}
			if cur != nil && cur.Link == "global" {
				info.DNSSECActive = dnssec
				info.DoTStatus = dot
			}
		}
	}
	flush()

	// Fall back to the first real link's effective settings if there was no
	// Global section (older resolvectl) so degrade detection still works.
	if info.DNSSECActive == "" {
		for _, l := range info.LinkDNS {
			if l.Link != "global" && l.DNSSEC != "" {
				info.DNSSECActive = l.DNSSEC
				break
			}
		}
	}
}

// linkName extracts "eth0" from "Link 2 (eth0)".
func linkName(line string) string {
	open := strings.Index(line, "(")
	closeParen := strings.LastIndex(line, ")")
	if open >= 0 && closeParen > open {
		return line[open+1 : closeParen]
	}
	return strings.TrimSpace(strings.TrimPrefix(line, "Link"))
}

// parseProtocols extracts the DNSSEC and DNS-over-TLS state from a Protocols line.
// DNSSEC token looks like "DNSSEC=no/unsupported" → returns ("no", reason kept by
// caller via the raw token). DoT is "+DNSOverTLS"/"-DNSOverTLS" or
// "DNSOverTLS=opportunistic".
func parseProtocols(line string) (dnssec, dot string) {
	for _, tok := range strings.Fields(line) {
		switch {
		case strings.HasPrefix(tok, "DNSSEC="):
			dnssec = strings.TrimPrefix(tok, "DNSSEC=") // may be "no/unsupported"
		case strings.HasPrefix(tok, "DNSOverTLS="):
			dot = strings.TrimPrefix(tok, "DNSOverTLS=")
		case tok == "+DNSOverTLS":
			dot = "yes"
		case tok == "-DNSOverTLS":
			if dot == "" {
				dot = "no"
			}
		}
	}
	return dnssec, dot
}

// ── resolved.conf DNSSEC setting ────────────────────────────────────────────

// parseResolvedConfDNSSEC reads the last uncommented DNSSEC= line from
// resolved.conf. Returns "" if unset so the caller can apply the default.
func parseResolvedConfDNSSEC(r io.Reader) string {
	val := ""
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "DNSSEC=") {
			val = strings.TrimSpace(strings.TrimPrefix(line, "DNSSEC="))
		}
	}
	return val
}

// computeDNSSECDegrade flags the case where DNSSEC is configured "yes" but the
// effective state on a link is not "yes" (systemd downgraded it because an
// upstream resolver does not support validation).
func computeDNSSECDegrade(info *models.ResolverAuditInfo) {
	if !strings.EqualFold(info.DNSSECConfigured, "yes") {
		return // not configured strict — a downgrade is expected, not a fault
	}
	active := dnssecState(info.DNSSECActive)
	if active == "yes" {
		return
	}

	// Find the offending link to name it and its upstream server in the reason.
	link, server := "", ""
	for _, l := range info.LinkDNS {
		if l.Link == "global" {
			continue
		}
		if dnssecState(l.DNSSEC) != "yes" {
			link = l.Link
			if len(l.Servers) > 0 {
				server = l.Servers[0]
			}
			break
		}
	}

	info.DNSSECDegraded = true
	reason := "upstream DNS does not support DNSSEC validation"
	if strings.Contains(info.DNSSECActive, "unsupported") {
		if server != "" {
			reason = fmt.Sprintf("upstream DNS %s does not support DNSSEC validation", server)
		}
	} else if info.DNSSECActive != "" {
		reason = fmt.Sprintf("resolved reports DNSSEC=%s", info.DNSSECActive)
	}
	if link != "" {
		reason += " (on " + link + ")"
	}
	info.DNSSECDegradedReason = reason
}

// dnssecState normalises "no/unsupported" → "no", "yes/..." → "yes".
func dnssecState(v string) string {
	if i := strings.Index(v, "/"); i >= 0 {
		return v[:i]
	}
	return v
}

// ── DNSSEC validation test ──────────────────────────────────────────────────

func runDNSSECTest(ctx context.Context, info *models.ResolverAuditInfo) {
	info.DNSSECTestRan = true
	out, err := runResolvectl(ctx, "query", sigokDomain)
	passed, errStr := parseDNSSECTestResult(out, err, ctx.Err())
	info.DNSSECTestPassed = passed
	info.DNSSECTestError = errStr
}

// parseDNSSECTestResult interprets `resolvectl query` output. It distinguishes
// a real DNSSEC failure (SERVFAIL) from no-internet (timeout) so a clean box
// passes and an offline box fails gracefully rather than crying DNSSEC-broken.
func parseDNSSECTestResult(out string, err, ctxErr error) (passed bool, errStr string) {
	low := strings.ToLower(out)
	if strings.Contains(low, "authenticated: yes") {
		return true, ""
	}
	if ctxErr != nil || strings.Contains(low, "timeout") || strings.Contains(low, "timed out") {
		return false, "timeout — no internet (not a DNSSEC failure)"
	}
	if strings.Contains(low, "servfail") {
		return false, "SERVFAIL — DNSSEC validation failed (upstream returned broken signatures)"
	}
	if strings.Contains(low, "authenticated: no") {
		return false, "resolved but not DNSSEC-authenticated"
	}
	if err != nil {
		msg := strings.TrimSpace(out)
		if msg == "" {
			msg = err.Error()
		}
		return false, msg
	}
	return false, "no DNSSEC authentication reported"
}

// ── NetworkManager fallback (RHEL with systemd-resolved disabled) ───────────

// nmDNSFallback reads NetworkManager's per-device DNS via `nmcli dev show`.
// nmcli is NOT invoked under sudo: it depends on a D-Bus session bus and fails
// silently when run via sudo (documented in CLAUDE.md). In that case we read
// the nameservers straight from /etc/resolv.conf instead.
func nmDNSFallback(ctx context.Context, info *models.ResolverAuditInfo) {
	if info.ResolverType == "static" || info.ResolverType == "none" {
		info.FallbackNote = "no systemd-resolved — plain resolv.conf in use"
	} else {
		info.FallbackNote = "systemd-resolved inactive — DNS managed by " + info.ResolverType
	}

	if os.Getenv("SUDO_USER") != "" {
		info.NMNameservers = resolvConfNameservers()
		info.FallbackNote += " (nmcli skipped under sudo — read from resolv.conf)"
		return
	}

	out, err := runCmd(ctx, "nmcli", "dev", "show")
	if err != nil {
		info.NMNameservers = resolvConfNameservers()
		return
	}
	info.NMNameservers = parseNmcliDNS(out)
	if len(info.NMNameservers) == 0 {
		info.NMNameservers = resolvConfNameservers()
	}
}

// parseNmcliDNS extracts DNS server addresses from `nmcli dev show` output.
// Lines look like "IP4.DNS[1]: 192.168.1.1".
func parseNmcliDNS(out string) []string {
	var servers []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.Contains(line, ".DNS") {
			continue
		}
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		val := strings.TrimSpace(line[idx+1:])
		if val != "" && !seen[val] {
			seen[val] = true
			servers = append(servers, val)
		}
	}
	return servers
}

// resolvConfNameservers reads nameserver lines directly from /etc/resolv.conf.
func resolvConfNameservers() []string {
	data, err := os.ReadFile("/etc/resolv.conf") // #nosec G304 -- hardcoded system file
	if err != nil {
		return nil
	}
	var ns []string
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == "nameserver" {
			ns = append(ns, fields[1])
		}
	}
	return ns
}

// ── VPN DNS integration ─────────────────────────────────────────────────────

// checkVPNDNS detects an active VPN interface and verifies its DNS is routed
// through the VPN. Leaves VPNDNSIntegrated nil when no VPN is present so a
// VPN-free host produces no warning (and no false positive).
func checkVPNDNS(info *models.ResolverAuditInfo) {
	iface := detectVPNInterface()
	if iface == "" {
		return // VPNDNSIntegrated stays nil — not applicable
	}
	info.VPNInterface = iface

	// We can only confirm DNS routing when resolvectl gave us per-link data.
	if len(info.LinkDNS) == 0 {
		return // resolver isn't systemd-resolved — can't verify, stay nil
	}
	integrated := false
	for _, l := range info.LinkDNS {
		if l.Link == iface && len(l.Servers) > 0 {
			integrated = true
			break
		}
	}
	info.VPNDNSIntegrated = &integrated
}

// detectVPNInterface returns the first up VPN interface, or "" if none.
func detectVPNInterface() string {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return ""
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	for _, name := range names {
		if !isVPNInterfaceName(name) {
			continue
		}
		if vpnInterfaceUp(name) {
			return name
		}
	}
	return ""
}

// isVPNInterfaceName matches common VPN interface naming conventions.
func isVPNInterfaceName(name string) bool {
	for _, p := range []string{"tun", "wg", "nordlynx", "proton"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// vpnInterfaceUp treats a VPN link as up unless operstate is explicitly "down".
// WireGuard links report "unknown" while fully functional, so only "down" is
// treated as inactive.
func vpnInterfaceUp(name string) bool {
	data, err := os.ReadFile("/sys/class/net/" + name + "/operstate") // #nosec G304 -- iface name from sysfs listing
	if err != nil {
		return true // exists but no operstate — assume up (tun devices)
	}
	return strings.TrimSpace(string(data)) != "down"
}

// ── resolvectl exec helper ──────────────────────────────────────────────────

// runResolvectl runs resolvectl with a 5s sub-timeout, capturing stdout+stderr
// (SERVFAIL and timeout messages go to stderr). resolvectl has no file API, so
// shelling out is the only option.
func runResolvectl(ctx context.Context, args ...string) (string, error) {
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := localeSafeCmd(c, "resolvectl", args...)
	cmd.WaitDelay = 100 * time.Millisecond
	out, err := cmd.CombinedOutput()
	return string(out), err
}
