package analysis

import (
	"fmt"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// ── DNS resolver heuristics (Spec 15) ────────────────────────────────────────

func checkDNS(d models.DNSResolverInfo) []models.Insight {
	var out []models.Insight

	// Not available on this platform (the non-Linux stub) — every field below is
	// the zero value, which the first branch would otherwise misread as "no
	// nameservers configured and resolution failing" and fire a false CRIT. Linux
	// always sets Available:true, so this never suppresses a real broken host.
	if !d.Available {
		return nil
	}

	if d.ProbeSkipped {
		// internal-collectors-09-01: the live resolution probe never ran
		// (DSD_OFFLINE) — ExternalResolvesOK/InternalResolvesOK stay at their
		// zero value, which every branch below would otherwise misread as
		// "resolution is failing" and fire a false CRIT/WARN. Disclose
		// unmeasured and only report the config-shape issues that don't
		// depend on the live probe result.
		out = append(out, unverifiedInsight("INFO", "DNS",
			"DNS resolution probe was skipped (DSD_OFFLINE) — external/internal resolution not verified",
			[]string{"to verify manually: dig google.com"}))
		out = append(out, checkDNSConfigOnly(d)...)
		return out
	}

	// No nameservers at all AND resolution failing: the resolver is unconfigured and
	// broken. The Manager!="none" guard below would otherwise suppress this entirely,
	// so a host with an empty /etc/resolv.conf whose live probe failed produced ZERO
	// DNS insight. (Requiring !InternalResolvesOK protects /etc/hosts-only hosts.)
	if !d.ExternalResolvesOK && !d.InternalResolvesOK && len(d.Nameservers) == 0 {
		msg := "DNS misconfigured — no nameservers in /etc/resolv.conf and resolution is failing"
		if d.ResolvTestError != "" {
			msg += " (" + d.ResolvTestError + ")"
		}
		out = append(out, insight("CRIT", "DNS", msg,
			[]string{
				"to inspect: cat /etc/resolv.conf",
				"to fix: add a 'nameserver <ip>' line, or enable systemd-resolved / NetworkManager",
			},
		))
		return out
	}

	if !d.ExternalResolvesOK && d.Manager != "none" {
		// Internal names resolve but external don't → an intentional internal-only
		// / air-gapped / split-horizon network, not a broken resolver. Downgrade to
		// WARN with accurate wording instead of a false "DNS is failing" CRIT.
		if d.InternalResolvesOK {
			msg := "external DNS resolution unavailable, but internal names resolve — expected on air-gapped / internal-only networks"
			if d.ResolvTestError != "" {
				msg += " (" + d.ResolvTestError + ")"
			}
			out = append(out, insight("WARN", "DNS", msg,
				[]string{
					"to inspect: dig google.com   (expected to fail on an isolated network)",
					"note: if external resolution IS expected, check the upstream forwarder / firewall",
				},
			))
			out = append(out, checkDNSQuality(d)...)
			return out
		}
		msg := "DNS resolution failing — cannot resolve external or internal hostnames"
		if d.ResolvTestError != "" {
			msg += ": " + d.ResolvTestError
		}
		out = append(out, insight("CRIT", "DNS", msg,
			[]string{
				"to inspect: cat /etc/resolv.conf",
				"to inspect: dig google.com",
				"to inspect: systemctl status NetworkManager systemd-resolved",
			},
		))
		return out
	}

	out = append(out, checkDNSQuality(d)...)

	if d.ExternalResolvesOK && d.ExternalLatencyMs > 500 {
		out = append(out, insight("WARN", "DNS",
			fmt.Sprintf("DNS resolution is slow (%dms) — may affect application startup and health checks",
				d.ExternalLatencyMs),
			[]string{
				"to inspect: dig +stats google.com",
				"to fix: consider a local caching resolver (systemd-resolved, unbound)",
				fmt.Sprintf("current nameservers: %s", strings.Join(d.Nameservers, ", ")),
			},
		))
	} else if d.ExternalResolvesOK && d.ExternalLatencyMs > 200 {
		out = append(out, insight("INFO", "DNS",
			fmt.Sprintf("DNS latency %dms — acceptable but consider local caching", d.ExternalLatencyMs),
			[]string{"to inspect: dig +stats google.com"},
		))
	}

	if d.PublicFallback {
		out = append(out, insight("INFO", "DNS",
			"public DNS resolver (8.8.8.8/1.1.1.1) configured — DNS queries leave your network",
			[]string{
				"note: on servers this may expose internal hostname lookups to public resolvers",
				"to fix: use your organisation's internal DNS resolver instead",
			},
		))
	}

	return out
}

func checkDNSQuality(d models.DNSResolverInfo) []models.Insight {
	out := checkDNSConfigOnly(d)
	// HasLoopback fires for ANY loopback nameserver that isn't the systemd-resolved
	// stub (127.0.0.53) — including a perfectly healthy local caching resolver
	// (dnsmasq, unbound, pdns-recursor, Pi-hole) that detectDNSManager doesn't know
	// how to name. Gate on resolution actually failing: a config-shape WARN that
	// contradicts a successful live probe is a false alarm, not a diagnosis. Not
	// probe-independent, so this stays out of checkDNSConfigOnly (also called from
	// the ProbeSkipped short-circuit above, where !ExternalResolvesOK is unmeasured
	// rather than a real failure).
	if d.HasLoopback && !d.ExternalResolvesOK {
		out = append(out, insight("WARN", "DNS",
			"loopback nameserver (127.x.x.x) in /etc/resolv.conf but systemd-resolved is not active — DNS may fail",
			[]string{
				"to fix: sudo systemctl enable --now systemd-resolved",
				"to fix: or replace 127.0.0.1 with a real nameserver IP",
			},
		))
	}
	return out
}

// checkDNSConfigOnly reports config-shape DNS issues that don't depend on the
// live resolution probe's result — safe to run even when the probe was
// skipped (DSD_OFFLINE).
func checkDNSConfigOnly(d models.DNSResolverInfo) []models.Insight {
	var out []models.Insight

	if d.TooManyNameservers {
		out = append(out, insight("WARN", "DNS",
			fmt.Sprintf("/etc/resolv.conf has %d nameservers — libc silently ignores all beyond 3",
				len(d.Nameservers)),
			[]string{
				"to fix: remove extra nameservers from /etc/resolv.conf",
				"note: if managed by NetworkManager, adjust connection DNS settings",
			},
		))
	}
	if d.NdotsHigh > 3 {
		out = append(out, insight("WARN", "DNS",
			fmt.Sprintf("ndots:%d set — every short hostname is tried as FQDN first, causing %d extra DNS lookups per query",
				d.NdotsHigh, d.NdotsHigh),
			[]string{
				"note: ndots >3 is set by Kubernetes (ndots:5) and may leak internal hostnames",
				"to inspect: grep ndots /etc/resolv.conf",
				"to fix: reduce to ndots:2 unless Kubernetes service discovery requires it",
			},
		))
	}
	if d.IPv6Only {
		out = append(out, insight("WARN", "DNS",
			"all configured nameservers are IPv6 — applications without IPv6 support may fail to resolve",
			[]string{
				"to fix: add at least one IPv4 nameserver to /etc/resolv.conf",
				fmt.Sprintf("current: %s", strings.Join(d.Nameservers, ", ")),
			},
		))
	}
	if len(d.DuplicateNameserver) > 0 {
		out = append(out, insight("INFO", "DNS",
			fmt.Sprintf("duplicate nameserver entries: %s", strings.Join(d.DuplicateNameserver, ", ")),
			[]string{"to fix: remove duplicate entries from /etc/resolv.conf"},
		))
	}
	return out
}
