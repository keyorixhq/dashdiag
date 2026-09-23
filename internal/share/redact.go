package share

// redact.go implements the redaction pass behind `dsd share` (docs/SHARE_DESIGN.md's
// "Local share (shipped)" section): before a rendered report leaves the machine, strip
// secrets (reusing internal/source's capture-sanitizer rules) plus report-specific
// identifiers — hostnames, IPv4/IPv6, MACs, usernames-in-paths, serial numbers, cloud
// instance IDs, and email addresses. This is BEST-EFFORT, the same standing caveat
// internal/source/sanitize.go makes about its own rules: free-text log lines quoted
// inside a finding's Message/Hints can still carry something these patterns miss — see
// docs/THREAT_MODEL.md's "Local share" section. Callers must still expect a human
// review before sharing broadly.

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/keyorixhq/dashdiag/internal/source"
)

// RedactOptions controls a RedactText/RedactJSONBytes pass.
type RedactOptions struct {
	// Disabled turns off the entire pass (== --no-redact). Secrets are never
	// redacted either when this is set — an explicit, visible opt-out, not a
	// silent downgrade (the caller is expected to print a warning).
	Disabled bool
	// KeepHostnames skips the hostname substitution only; secrets and every
	// other identifier class are still redacted.
	KeepHostnames bool
	// KeepIPs skips the IPv4/IPv6 substitution only.
	KeepIPs bool
}

// Counts tallies redactions by class ("secrets", "hostnames", "ips", "macs",
// "usernames", "serials", "cloud_ids", "emails"). A zero/empty Counts means
// nothing in that class was found — never a sign the pass didn't run.
type Counts map[string]int

// Total returns the sum of every class's count.
func (c Counts) Total() int {
	n := 0
	for _, v := range c {
		n += v
	}
	return n
}

// Summary renders a one-line, deterministically-ordered redaction summary for
// the operator, e.g. "3 secrets, 2 ips, 1 hostname". Returns "none" when c is
// empty (redaction ran but found nothing to redact — distinct from a
// --no-redact pass, which the caller reports separately).
func (c Counts) Summary() string {
	if len(c) == 0 {
		return "none"
	}
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%d %s", c[k], k))
	}
	return strings.Join(parts, ", ")
}

var (
	// reIPv4 matches a dotted-quad. Loopback (127.0.0.1) and unspecified
	// (0.0.0.0) are excluded at the call site — they identify nothing.
	reIPv4 = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
	// reIPv6 covers the full 8-group form and the common "::"-compressed
	// forms starting with at least one hex group. Best-effort, like every
	// other rule here — see internal/source/sanitize.go's own documented
	// IPv6 gap, which this closes for share output specifically. Leading
	// "::" (e.g. "::1") is deliberately not matched — that's the loopback
	// form, which carries no identifying information.
	reIPv6 = regexp.MustCompile(
		`\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b` +
			`|\b(?:[0-9A-Fa-f]{1,4}:){1,7}:(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6})?`,
	)
	reMAC     = regexp.MustCompile(`\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b`)
	reEmail   = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)
	reHomeDir = regexp.MustCompile(`(/home/|/Users/)([A-Za-z0-9_.-]+)`)
	// reSerial matches a labeled serial number ("Serial Number: XYZ", "S/N=XYZ")
	// and keeps the label, redacting only the value — the same "keep the key,
	// drop the value" shape internal/source's secretRules use.
	reSerial = regexp.MustCompile(`(?i)(serial(?:\s*number)?|s/n)(\s*[:=]\s*)(\S+)`)
	// reCloudID matches AWS EC2-family resource IDs (instance/volume/network
	// interface). Azure/GCP instance identifiers are free-form (a GUID or a
	// plain hostname-derived string respectively) and are not distinguishable
	// from ordinary text by pattern alone, so they're not covered here.
	reCloudID = regexp.MustCompile(`\b(?:i|vol|eni|snap)-[0-9a-f]{8,17}\b`)
)

// RedactText redacts secrets and identifiers from a rendered, non-JSON report
// (markdown/HTML/text). hostname is the report's own hostname, redacted as a
// whole-word, case-insensitive match in addition to the generic identifier
// patterns below.
func RedactText(text, hostname string, opts RedactOptions) (string, Counts) {
	if opts.Disabled {
		return text, Counts{}
	}
	out, n := source.RedactSecretsText([]byte(text))
	result, counts := redactIdentifiers(string(out), hostname, opts)
	if n > 0 {
		counts["secrets"] = n
	}
	return result, counts
}

// RedactJSONBytes redacts secrets and identifiers from a JSON payload (used
// by `dsd share --format blob`, which encodes `dsd health --json`). Secrets
// go through the JSON-structural pass (source.RedactJSONSecretsCounted) —
// never the line-scan text rules, which can corrupt JSON syntax (see
// internal/source/sanitize.go's redactSecretsAndJSON doc comment). The
// identifier patterns below are safe to run directly against the resulting
// JSON bytes: each only matches a bounded token (an IP, a MAC, ...) and its
// replacement is a plain, quote-free string, so there is no risk of the match
// swallowing adjacent JSON syntax the way the greedy key=value secret rule
// can.
func RedactJSONBytes(data []byte, hostname string, opts RedactOptions) ([]byte, Counts, error) {
	if opts.Disabled {
		return data, Counts{}, nil
	}
	red, n, err := source.RedactJSONSecretsCounted(data)
	if err != nil {
		return nil, Counts{}, fmt.Errorf("share: redacting secrets: %w", err)
	}
	result, counts := redactIdentifiers(string(red), hostname, opts)
	if n > 0 {
		counts["secrets"] = n
	}
	return []byte(result), counts, nil
}

// redactIdentifiers applies every identifier-class pattern (hostname, home
// directory username, serial number, cloud instance ID, email, MAC, then
// IPv4/IPv6) to text and returns the result plus a per-class count. Order
// matters only where patterns could otherwise double-count the same bytes
// (e.g. a MAC-like substring inside an already-redacted token); each pattern
// here targets a disjoint shape, so the order chosen is for readability, not
// correctness.
func redactIdentifiers(text, hostname string, opts RedactOptions) (string, Counts) {
	counts := Counts{}
	out := text

	if !opts.KeepHostnames && hostname != "" && hostname != "host" {
		hostRe := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(hostname) + `\b`)
		if m := hostRe.FindAllString(out, -1); len(m) > 0 {
			counts["hostnames"] = len(m)
			out = hostRe.ReplaceAllString(out, "<host>")
		}
	}

	out = reHomeDir.ReplaceAllStringFunc(out, func(m string) string {
		sub := reHomeDir.FindStringSubmatch(m)
		counts["usernames"]++
		return sub[1] + "<user>"
	})

	out = reSerial.ReplaceAllStringFunc(out, func(m string) string {
		sub := reSerial.FindStringSubmatch(m)
		counts["serials"]++
		return sub[1] + sub[2] + "<serial>"
	})

	out = reCloudID.ReplaceAllStringFunc(out, func(string) string {
		counts["cloud_ids"]++
		return "<instance-id>"
	})

	out = reEmail.ReplaceAllStringFunc(out, func(string) string {
		counts["emails"]++
		return "<email>"
	})

	out = reMAC.ReplaceAllStringFunc(out, func(string) string {
		counts["macs"]++
		return "<mac>"
	})

	if !opts.KeepIPs {
		out = reIPv6.ReplaceAllStringFunc(out, func(string) string {
			counts["ips"]++
			return "<ip>"
		})
		out = reIPv4.ReplaceAllStringFunc(out, func(m string) string {
			if isNonRedactableIP(m) {
				return m
			}
			counts["ips"]++
			return "<ip>"
		})
	}

	return out, counts
}

// isNonRedactableIP reports whether a matched IPv4 literal identifies
// nothing worth redacting (loopback or unspecified).
func isNonRedactableIP(s string) bool {
	return s == "127.0.0.1" || s == "0.0.0.0"
}
