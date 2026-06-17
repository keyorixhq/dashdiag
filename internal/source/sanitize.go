package source

import "regexp"

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
	// Group 1 is the key + separator; group 2 (the value) is dropped.
	{regexp.MustCompile(`(?i)((?:pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key|auth_?token|credentials?)\s*[=:]\s*)("[^"]*"|'[^']*'|\S+)`),
		"${1}" + redactedMark},
	// AWS access key IDs.
	{regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), "[REDACTED-AWS-KEY]"},
	// HTTP bearer tokens.
	{regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._\-]+`), "Bearer " + redactedMark},
	// /etc/shadow password hashes: "user:$6$salt$hash:..." → redact the hash field.
	{regexp.MustCompile(`(?m)^([^:\s]+:)(\$[0-9a-z]+\$[^:]*)(:)`), "${1}" + redactedMark + "${3}"},
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

// Sanitize redacts common credential patterns from every recorded file blob and
// command output in the bundle, in place. Best-effort (see the package note).
func (b *Bundle) Sanitize() SanitizeReport {
	b.mu.Lock()
	defer b.mu.Unlock()

	var rep SanitizeReport
	for path, fr := range b.files {
		if len(fr.data) == 0 {
			continue
		}
		if red, n := redactSecrets(fr.data); n > 0 {
			fr.data = red
			b.files[path] = fr
			rep.FilesRedacted++
			rep.TotalRedactions += n
		}
	}
	for key, cr := range b.cmds {
		var n int
		if red, k := redactSecrets(cr.res.Stdout); k > 0 {
			cr.res.Stdout = red
			n += k
		}
		if red, k := redactSecrets(cr.res.Stderr); k > 0 {
			cr.res.Stderr = red
			n += k
		}
		if n > 0 {
			b.cmds[key] = cr
			rep.CommandsRedacted++
			rep.TotalRedactions += n
		}
	}
	return rep
}
