package source

import (
	"fmt"
	"hash/fnv"
	"net"
	"regexp"
)

// Sanitization is BEST-EFFORT redaction of common credential patterns from a raw
// capture bundle, so it can be shared for offline `dsd replay` / `dsd diff` without
// leaking secrets. It is NOT a guarantee: callers must still review a bundle before
// sharing it. It deliberately redacts only high-confidence SECRETS (keys, passwords,
// tokens) and leaves identifiers (hostnames, IPs, serials) intact so replay stays
// byte-stable and the verdicts are unchanged — those are a separate opt-in concern.

const redactedMark = "[REDACTED]"

// secretRule is a pattern plus its replacement. Where the rule keeps a label/key,
// the replacement uses submatch refs ($1) so "password=hunter2" → "password=[REDACTED]"
// rather than losing the key (which would make a sanitized config unreadable).
type secretRule struct {
	re   *regexp.Regexp
	repl string
}

var secretRules = []secretRule{
	// PEM private key blocks (SSH/TLS). (?s) so . spans newlines.
	{regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`),
		"[REDACTED PRIVATE KEY]"},
	// key = value / key: value secret assignments — keep the key, redact the value.
	// Group 1 is the key + separator; group 2 (the value) is dropped. The
	// [A-Za-z0-9_-]* after the keyword allows a SUFFIXED identifier —
	// SECRET_KEY_BASE=, DJANGO_SECRET_KEY=, STRIPE_API_KEY= — not just the bare
	// keyword immediately before the operator; a PREFIXED identifier
	// (MY_SECRET=) already matched without this, since the keyword alternation
	// has no leading \b anchor.
	{regexp.MustCompile(`(?i)((?:pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key|auth_?token|credentials?)[A-Za-z0-9_-]*\s*[=:]\s*)("[^"]*"|'[^']*'|\S+)`),
		"${1}" + redactedMark},
	// AWS access key IDs.
	{regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), "[REDACTED-AWS-KEY]"},
	// HTTP bearer tokens.
	{regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._\-]+`), "Bearer " + redactedMark},
	// /etc/shadow password hashes: "user:$6$salt$hash:..." → redact the hash field.
	{regexp.MustCompile(`(?m)^([^:\s]+:)(\$[0-9a-z]+\$[^:]*)(:)`), "${1}" + redactedMark + "${3}"},
	// Bare JWTs (a header.payload.signature triple) logged without a "Bearer "/
	// "token=" prefix — e.g. an app's stack trace printing a raw access token.
	// The header segment is base64url of `{"` and is virtually always "eyJ" in
	// practice, keeping the false-positive rate on ordinary dotted text low.
	{regexp.MustCompile(`\beyJ[\w-]+\.[\w-]+\.[\w-]+\b`), "[REDACTED JWT]"},
	// Credentials embedded in a URL: "scheme://user:password@host" — common in
	// database connection strings that show up verbatim in error logs. Keep the
	// scheme and username (structure/context), redact only the password.
	{regexp.MustCompile(`\b([a-zA-Z][a-zA-Z0-9+.-]*://[^\s/@:]+:)([^\s@]+)(@)`), "${1}" + redactedMark + "${3}"},
}

// sensitiveCacheKeys are Source.Cached() keys whose value is a live credential
// (not a config/log line), so it never carries a "token=" or "password="
// label for the generic patterns above to key on — e.g. a raw IMDSv2 session
// token, cached verbatim so replay can reuse it as the metadata-GET header.
// Sanitize force-redacts these by KEY (path), not by content pattern, since
// the value itself has no reliable lexical marker.
var sensitiveCacheKeys = []string{
	"imds-aws-token", // AWS IMDSv2 session token (cloudmeta_linux.go/aws_linux.go)
}

// isSensitiveCacheKey reports whether path is the bundle file path a Cached()
// key maps to (see cacheKey) for one of sensitiveCacheKeys.
func isSensitiveCacheKey(path string) bool {
	for _, k := range sensitiveCacheKeys {
		if path == cacheKey(k) {
			return true
		}
	}
	return false
}

// redactSecrets applies every rule to data and returns the redacted bytes plus the
// number of redactions made. It is deterministic: identical input → identical output.
func redactSecrets(data []byte) ([]byte, int) {
	if len(data) == 0 {
		return data, 0
	}
	n := 0
	out := data
	for _, r := range secretRules {
		matches := r.re.FindAll(out, -1)
		if len(matches) == 0 {
			continue
		}
		n += len(matches)
		out = r.re.ReplaceAll(out, []byte(r.repl))
	}
	return out, n
}

// SanitizeReport summarises what a Sanitize pass redacted.
type SanitizeReport struct {
	FilesRedacted    int // recorded files that had ≥1 redaction
	CommandsRedacted int // recorded command outputs that had ≥1 redaction
	TotalRedactions  int // total pattern matches replaced
}

// SanitizeOptions controls how aggressive a Sanitize pass is.
type SanitizeOptions struct {
	// Identifiers, when true, ALSO redacts IPv4 addresses, MAC addresses, and the
	// host's own hostname (in addition to secrets). Replacements are deterministic
	// stable-hash placeholders, so the bundle stays byte-stable AND the same value
	// maps to the same token everywhere (correlation is preserved) — replay verdicts
	// are unchanged, only the displayed identifiers differ. Loopback/unspecified
	// addresses are kept. IPv6 is not yet handled.
	Identifiers bool
}

// Sanitize redacts secrets (always) and, if opts.Identifiers, identifiers from
// every recorded file blob and command output in the bundle, in place.
// Best-effort (see the package note).
func (b *Bundle) Sanitize(opts SanitizeOptions) SanitizeReport {
	b.mu.Lock()
	defer b.mu.Unlock()

	host := b.Manifest.Host
	redact := func(data []byte) ([]byte, int) {
		out, n := redactSecrets(data)
		if opts.Identifiers {
			out, k := redactIdentifiers(out, host)
			return out, n + k
		}
		return out, n
	}

	var rep SanitizeReport
	for path, fr := range b.files {
		if len(fr.data) == 0 {
			continue
		}
		if isSensitiveCacheKey(path) {
			fr.data = []byte(redactedMark)
			b.files[path] = fr
			rep.FilesRedacted++
			rep.TotalRedactions++
			continue
		}
		if red, n := redact(fr.data); n > 0 {
			fr.data = red
			b.files[path] = fr
			rep.FilesRedacted++
			rep.TotalRedactions += n
		}
	}
	for key, cr := range b.cmds {
		var n int
		if red, k := redact(cr.res.Stdout); k > 0 {
			cr.res.Stdout = red
			n += k
		}
		if red, k := redact(cr.res.Stderr); k > 0 {
			cr.res.Stderr = red
			n += k
		}
		if n > 0 {
			b.cmds[key] = cr
			rep.CommandsRedacted++
			rep.TotalRedactions += n
		}
	}
	// The host's own hostname also lives in the manifest metadata.
	if opts.Identifiers && host != "" && host != "host" {
		b.Manifest.Host = hostPlaceholder
	}
	return rep
}

const hostPlaceholder = "[HOST]"

var (
	reMAC  = regexp.MustCompile(`\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b`)
	reIPv4 = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
)

// idPlaceholder is a deterministic placeholder for an identifier value: the same
// value always maps to the same token (so correlation survives) and it never
// varies across runs (so the bundle stays byte-stable for replay).
func idPlaceholder(prefix, val string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(val))
	return fmt.Sprintf("[%s-%08x]", prefix, h.Sum32())
}

// redactIdentifiers replaces MACs, real IPv4 addresses, and the host's own
// hostname with stable placeholders. MACs are redacted before IPs. Loopback and
// unspecified addresses are kept (they identify nothing and collectors may key on
// them). A candidate is only redacted if net.ParseIP confirms it is a real address,
// so version strings like "1.2.3.999" are left alone.
func redactIdentifiers(data []byte, hostname string) ([]byte, int) {
	if len(data) == 0 {
		return data, 0
	}
	n := 0
	out := reMAC.ReplaceAllFunc(data, func(m []byte) []byte {
		n++
		return []byte(idPlaceholder("MAC", string(m)))
	})
	out = reIPv4.ReplaceAllFunc(out, func(m []byte) []byte {
		if !isRedactableIP(string(m)) {
			return m
		}
		n++
		return []byte(idPlaceholder("IP", string(m)))
	})
	if hostname != "" && hostname != "host" && len(hostname) >= 2 {
		hostRe := regexp.MustCompile(`\b` + regexp.QuoteMeta(hostname) + `\b`)
		if matches := hostRe.FindAll(out, -1); len(matches) > 0 {
			n += len(matches)
			out = hostRe.ReplaceAll(out, []byte(hostPlaceholder))
		}
	}
	return out, n
}

// isRedactableIP reports whether s is a real IP worth redacting — a valid address
// that is not loopback (127.x / ::1) or unspecified (0.0.0.0 / ::).
func isRedactableIP(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && !ip.IsLoopback() && !ip.IsUnspecified()
}
