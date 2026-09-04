package source

import (
	"bytes"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net"
	"regexp"
	"strings"
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

// secretKeyPattern is the bare (no separator, no anchors) alternation of
// credential-shaped identifier names, shared by secretRules[1] (line-scan
// "key=value"/"key: value" text) and secretKeyNameRe (JSON object-key
// matching in redactJSONValue) so the two stay in lockstep — one list of
// "what counts as a secret key name" for the whole package. The trailing
// [A-Za-z0-9_-]* allows a SUFFIXED identifier — SECRET_KEY_BASE,
// DJANGO_SECRET_KEY, STRIPE_API_KEY — not just the bare keyword; a PREFIXED
// identifier (MY_SECRET) already matches without an explicit prefix wildcard
// wherever this pattern is used unanchored, since the alternation has no
// leading \b anchor.
const secretKeyPattern = `(?:pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key|auth_?token|credentials?)[A-Za-z0-9_-]*` //nolint:gosec // detector pattern for secret-shaped key NAMES, not a credential itself

// secretKeyNameRe matches secretKeyPattern anywhere within a bare identifier
// (e.g. a JSON object key like "SecretAccessKey" or "db_password") — used by
// redactJSONValue to force-redact a string value whose key looks like a
// credential, independent of the value's own content (see the JSON-vs-regex
// discussion on RedactJSONSecrets).
var secretKeyNameRe = regexp.MustCompile(`(?i)` + secretKeyPattern)

var secretRules = []secretRule{
	// PEM private key blocks (SSH/TLS). (?s) so . spans newlines.
	{regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`),
		"[REDACTED PRIVATE KEY]"},
	// key = value / key: value secret assignments — keep the key, redact the value.
	// Group 1 is the key + separator; group 2 (the value) is dropped.
	// Deliberately requires the separator to follow the key directly (mod
	// whitespace only, NOT an intervening quote): a JSON-quoted key like
	// `"password":"hunter2"` is intentionally left unmatched by this rule —
	// see TestRedactSecretsMissesJSONQuotedKey — because redacting it here
	// would mean dropping group 2's quoting to splice in the bare
	// [REDACTED] marker, corrupting the document into invalid JSON. JSON
	// content is instead handled structurally, by redactSecretsAndJSON
	// calling into redactJSONValue/RedactJSONSecrets, which decode-rewrite-
	// remarshal so the result is always valid JSON. The unquoted-value
	// alternative matches through end-of-line ([^\r\n]*, not \S+) so a value
	// containing spaces (e.g. `password = hunter two words` in a plain
	// config/log line) is redacted in full rather than stopping at the first
	// word; data here is a whole file/command-output blob (no per-line
	// splitting upstream), so [^\r\n]* — not a bare greedy `.*` — is required
	// to stay line-scoped and not swallow subsequent lines.
	{regexp.MustCompile(`(?i)(` + secretKeyPattern + `\s*[=:]\s*)("[^"]*"|'[^']*'|[^\r\n]*)`),
		"${1}" + redactedMark},
	// AWS access key IDs. AKIA = long-lived IAM user key; ASIA = temporary/STS
	// credentials (AssumeRole, EC2 instance profiles, EKS IRSA, Lambda execution
	// roles — the AWS-recommended, now-dominant shape); ABIA/ACCA are rarer
	// service/context-specific bearer forms. All four share the same 16
	// trailing alnum chars.
	{regexp.MustCompile(`\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b`), "[REDACTED-AWS-KEY]"},
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
	// netrc-style credential lines: "login USER password PASS" (one line, ~/.netrc
	// and /etc/apt/auth.conf.d/*.conf's grammar, read verbatim by
	// internal/collectors/pve_linux.go) or the same pair split across two lines.
	// The keyword rule above requires an "="/":" separator and cannot see this —
	// netrc/auth.conf use a bare space, so "password CANARY_SECRET" sailed through
	// unredacted (found via a canary-file sweep of dsd capture --raw --sanitize).
	// Anchored to whole lines (optionally "machine HOST " prefixed) rather than a
	// bare "login\s+\S+\s+password\s+\S+" scan, so ordinary prose that happens to
	// contain both words — "the login and password steps are separate" — cannot
	// satisfy it: that sentence doesn't start at BOL with "login"/"machine", and
	// once anchored, "and"/"steps" fail to complete the required single-token
	// login-value / password-value shape as literal line content. Keeps the login
	// line and the "password" keyword; drops only the password value.
	{regexp.MustCompile(`(?mi)^([ \t]*(?:machine\s+\S+[ \t]+)?login\s+\S+)([ \t]+|[ \t]*\r?\n[ \t]*)(pass(?:word|wd)?\s+)(\S+)[ \t]*$`),
		"${1}${2}${3}" + redactedMark},
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

// envCacheKeyPrefix is the Cached() key prefix collectors/fsaccess.go's
// getenv() uses: Cached("env/"+name, ...).
const envCacheKeyPrefix = "env/"

// sensitiveEnvNamePatterns are case-insensitive substrings matched against an
// env var NAME (not its value) cached via getenv()'s "env/<NAME>" key. Mirrors
// internal/collectors/docker.go's detectPlaintextSecrets pattern list (kept as
// an independent copy here, not imported — collectors already depends on
// source, so the reverse import would cycle).
var sensitiveEnvNamePatterns = []string{
	"PASSWORD", "PASSWD", "SECRET", "TOKEN", "APIKEY", "API_KEY",
	"PRIVATE_KEY", "SIGNING_KEY", "ENCRYPTION_KEY", "CREDENTIALS",
	"ACCESS_KEY", "AUTH_TOKEN",
}

// isSensitiveEnvCacheKey reports whether path is the bundle file path a
// Cached("env/"+name, ...) call maps to for a name that looks like a
// credential. getenv() caches the bare env value with no "name=value" label
// for the generic secretRules regex to key on, so any future collector that
// reads a genuinely sensitive env var (a cloud credential used as a
// provider-detection signal, say) needs to be force-redacted by NAME the same
// way sensitiveCacheKeys handles known live-credential keys — not just the
// one hardcoded "imds-aws-token" entry.
func isSensitiveEnvCacheKey(path string) bool {
	prefixed := cacheKey(envCacheKeyPrefix)
	name, ok := strings.CutPrefix(path, prefixed)
	if !ok {
		return false
	}
	name = strings.ToUpper(name)
	for _, pat := range sensitiveEnvNamePatterns {
		if strings.Contains(name, pat) {
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

// looksLikeJSON cheaply sniffs whether data appears to be a JSON document (an
// object or array), by checking the first non-whitespace byte — a full parse
// happens only if this passes (see redactSecretsAndJSON), so a false positive
// here just costs one wasted json.Unmarshal, and a false negative just skips
// the JSON-structural pass (the byte-level secretRules scan still ran).
func looksLikeJSON(data []byte) bool {
	t := bytes.TrimSpace(data)
	return len(t) > 0 && (t[0] == '{' || t[0] == '[')
}

// redactSecretsAndJSON is redactSecrets extended with a JSON-structural pass
// for content that looks like a JSON document. It exists because
// secretRules[1] (the "key=value"/"key: value" line-scan rule) cannot see a
// JSON-quoted key: in `"password":"hunter2"`, the closing quote after the key
// sits between the keyword and the `:` separator, so the key/value
// RELATIONSHIP is invisible to a text pattern once the key is quoted — only a
// structural walk of the decoded document sees it. Extending the regex to
// also swallow a trailing quote on the KEY side is possible (and secretRules[1]
// does that much, for keys directly followed by the separator with no
// intervening space), but redacting the VALUE side would require dropping its
// surrounding quotes to insert the bare [REDACTED] marker, corrupting the
// document into invalid JSON — a real problem here, since sanitized capture
// bundles are replayed and JSON-formatted captures/command output get
// json.Unmarshal'd back by collectors. RedactJSONSecrets/redactJSONValue
// decode-rewrite-remarshal instead, so the result is always valid JSON and
// generalizes correctly to nested objects/arrays, unlike a regex.
//
// The JSON-structural pass is tried FIRST, on the untouched input, and its
// result is used exclusively when the document parses — the regex pass never
// runs on top of syntactically valid JSON. This is load-bearing, not
// stylistic: secretRules[1]'s value-match is `[^\r\n]*` (line-scoped, not
// JSON-string-scoped), so on a single-line JSON array element like
// `"POSTGRES_PASSWORD=hunter2"` it doesn't stop at the value's closing quote —
// it consumes the quote, the closing `]`/`}`, and everything else through
// end-of-line, replacing all of it with the bare [REDACTED] marker and
// leaving invalid JSON behind. redactJSONValue's leaf-string case already
// runs this SAME regex pass on each decoded string in isolation (no
// surrounding JSON syntax to swallow), so nothing is lost by skipping the
// whole-document regex pass when the structural walk can run — this was
// caught by TestSanitizeReplayEquivalence (cmd package) replaying a captured
// `docker inspect`-shaped bundle whose Env array contained a
// credential-shaped entry: the container silently vanished from the
// collector's parsed result on the sanitized replay, because the value-side
// corruption broke json.Unmarshal downstream.
func redactSecretsAndJSON(data []byte) ([]byte, int) {
	if looksLikeJSON(data) {
		if red, k, err := redactJSONSecretsCounted(data); err == nil {
			return red, k
		}
		// Sniffed as JSON-shaped but didn't actually parse (e.g. a shell
		// script or log line that happens to start with '{') — fall through
		// to the line-scan regex pass below.
	}
	out, n := redactSecrets(data)
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
// every recorded file blob, command output, symlink target, directory listing,
// glob match, and recorded error string in the bundle, in place. Best-effort
// (see the package note).
func (b *Bundle) Sanitize(opts SanitizeOptions) SanitizeReport {
	b.mu.Lock()
	defer b.mu.Unlock()

	host := b.Manifest.Host
	redact := func(data []byte) ([]byte, int) {
		out, n := redactSecretsAndJSON(data)
		if opts.Identifiers {
			out, k := redactIdentifiers(out, host)
			return out, n + k
		}
		return out, n
	}
	// redactStr is the string-in/string-out convenience form of redact, for the
	// many recorded fields (errText, symlink targets, dir/glob entries) that are
	// plain strings rather than []byte blobs.
	redactStr := func(s string) (string, int) {
		if s == "" {
			return s, 0
		}
		red, n := redact([]byte(s))
		if n == 0 {
			return s, 0
		}
		return string(red), n
	}
	// redactSlice runs redactStr over every element of a []string (a dirs.json /
	// globs.json entry list), returning a fresh slice only when something changed
	// so untouched entries never get needlessly reallocated.
	redactSlice := func(items []string) ([]string, int) {
		var total int
		var out []string
		for i, s := range items {
			red, n := redactStr(s)
			if n == 0 {
				continue
			}
			if out == nil {
				out = append([]string(nil), items...)
			}
			out[i] = red
			total += n
		}
		if out == nil {
			return items, 0
		}
		return out, total
	}

	var rep SanitizeReport
	b.sanitizeFiles(redact, redactStr, &rep)
	b.sanitizeCmds(redact, redactStr, &rep)
	b.sanitizeLinks(redactStr, &rep)
	b.sanitizeStatErrs(redactStr, &rep)
	b.sanitizeDirsGlobs(redactSlice, &rep)

	// The host's own hostname also lives in the manifest metadata.
	if opts.Identifiers && host != "" && host != "host" {
		b.Manifest.Host = hostPlaceholder
	}
	return rep
}

// sanitizeFiles rewrites every recorded file blob and its error text in
// place, force-redacting known live-credential and sensitive-env cache keys
// by path (they carry no lexical marker for the generic content patterns).
func (b *Bundle) sanitizeFiles(redact func([]byte) ([]byte, int), redactStr func(string) (string, int), rep *SanitizeReport) {
	for path, fr := range b.files {
		var n int
		if len(fr.data) > 0 {
			if isSensitiveCacheKey(path) || isSensitiveEnvCacheKey(path) {
				fr.data = []byte(redactedMark)
				n++
			} else if red, k := redact(fr.data); k > 0 {
				fr.data = red
				n += k
			}
		}
		if red, k := redactStr(fr.errText); k > 0 {
			fr.errText = red
			n += k
		}
		if n > 0 {
			b.files[path] = fr
			rep.FilesRedacted++
			rep.TotalRedactions += n
		}
	}
}

// sanitizeCmds rewrites every recorded command's stdout/stderr, error text,
// and argv in place. persist.go's Save() writes argv verbatim into
// commands/index.json as cmdIndexEntry.Argv, so a secret passed as a CLI
// argument (e.g. a diagnostic tool invoked with a token flag) must be
// redacted the same way stdout/stderr already are. Argv lives in the map
// KEY (see cmdKey), so a redacted argv means a new key — rebuild the map
// rather than mutate mid-range. Argv redaction is secrets-only (not
// identifiers): the command index is also a replay LOOKUP key (getCmd
// matches on the live argv), and the identifiers-in-argv tradeoff
// (probe-target IPs surviving as lookup keys) is already a documented,
// accepted caveat — this only closes the secrets gap, which was
// undocumented and unmitigated.
func (b *Bundle) sanitizeCmds(redact func([]byte) ([]byte, int), redactStr func(string) (string, int), rep *SanitizeReport) {
	newCmds := make(map[string]cmdRec, len(b.cmds))
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
		if red, k := redactStr(cr.errText); k > 0 {
			cr.errText = red
			n += k
		}
		newKey, argN := redactCmdArgvKey(key)
		n += argN
		if n > 0 {
			rep.CommandsRedacted++
			rep.TotalRedactions += n
		}
		newCmds[newKey] = cr
	}
	b.cmds = newCmds
}

// sanitizeLinks rewrites every recorded symlink target and error text in place.
func (b *Bundle) sanitizeLinks(redactStr func(string) (string, int), rep *SanitizeReport) {
	for path, rec := range b.links {
		var n int
		if red, k := redactStr(rec.target); k > 0 {
			rec.target = red
			n += k
		}
		if red, k := redactStr(rec.errText); k > 0 {
			rec.errText = red
			n += k
		}
		if n > 0 {
			b.links[path] = rec
			rep.TotalRedactions += n
		}
	}
}

// sanitizeStatErrs rewrites the recorded error text on every stat/statfs
// entry — the only field on either that can carry a leaked secret (e.g. a
// path containing a token, echoed back in an ENOENT error string).
func (b *Bundle) sanitizeStatErrs(redactStr func(string) (string, int), rep *SanitizeReport) {
	for path, rec := range b.stats {
		if red, n := redactStr(rec.errText); n > 0 {
			rec.errText = red
			b.stats[path] = rec
			rep.TotalRedactions += n
		}
	}
	for path, rec := range b.statfss {
		if red, n := redactStr(rec.errText); n > 0 {
			rec.errText = red
			b.statfss[path] = rec
			rep.TotalRedactions += n
		}
	}
}

// sanitizeDirsGlobs rewrites every directory-listing and glob-match entry.
func (b *Bundle) sanitizeDirsGlobs(redactSlice func([]string) ([]string, int), rep *SanitizeReport) {
	for pattern, entries := range b.dirs {
		if red, n := redactSlice(entries); n > 0 {
			b.dirs[pattern] = red
			rep.TotalRedactions += n
		}
	}
	for pattern, entries := range b.globs {
		if red, n := redactSlice(entries); n > 0 {
			b.globs[pattern] = red
			rep.TotalRedactions += n
		}
	}
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
		// (?i): a captured log line can render the hostname in a different case
		// than os.Hostname() returned (e.g. an upcased syslog HOSTNAME field) —
		// that occurrence must still be recognized under --identifiers.
		hostRe := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(hostname) + `\b`)
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

// redactCmdArgvKey runs redactSecrets over each argv element of a b.cmds map
// key (built by cmdKey — name+args joined on NUL) and returns the key rebuilt
// from the redacted elements plus the total redaction count. Each element is
// redacted independently (matching persist.go's Save(), which persists argv
// as a []string, not a joined command line), so a single-element form like
// "--token=abc123" is caught by the same label-aware rule stdout/stderr use,
// while a secret split across two adjacent elements ("-p", "hunter2") is not —
// a known best-effort limit, same class as the rest of this package.
func redactCmdArgvKey(key string) (string, int) {
	parts := splitKey(key)
	total := 0
	changed := false
	for i, p := range parts {
		red, n := redactSecrets([]byte(p))
		if n == 0 {
			continue
		}
		parts[i] = string(red)
		total += n
		changed = true
	}
	if !changed {
		return key, 0
	}
	return cmdKey(parts[0], parts[1:]), total
}

// RedactJSONSecrets applies the same always-on secret redaction Bundle.Sanitize
// gives capture-bundle content to an arbitrary JSON document, by decoding it,
// rewriting every string leaf through redactSecrets, and re-marshalling.
//
// Rewriting is done on the DECODED value, never on the raw serialized bytes:
// running the byte-level secretRules patterns directly against
// already-serialized JSON is unsafe, because a match (e.g. the generic
// key=value rule's greedy \S+ value group) can swallow adjacent JSON syntax —
// a closing quote, comma, or brace — when there is no whitespace between JSON
// tokens (the normal case for compact/minified output), corrupting the
// document. Decoding first means only string VALUES are ever substituted, so
// the result is always valid JSON.
//
// Used by `dsd mcp`'s dsd_health/dsd_replay tools: their checks[].raw field is
// documented out-of-contract and may carry a collector's verbatim raw data, so
// it gets the same "secrets always redacted" treatment a capture bundle
// already gets before crossing an MCP boundary that commonly forwards straight
// into a cloud LLM's context. Returns data unchanged (with a non-nil error) if
// it isn't valid JSON.
func RedactJSONSecrets(data []byte) ([]byte, error) {
	out, _, err := redactJSONSecretsCounted(data)
	return out, err
}

// redactJSONSecretsCounted is the shared implementation behind
// RedactJSONSecrets; it additionally reports how many redactions were made,
// for SanitizeReport (RedactJSONSecrets keeps its existing 2-return public
// signature since it's already used across an MCP-facing call site).
func redactJSONSecretsCounted(data []byte) ([]byte, int, error) {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return data, 0, fmt.Errorf("source: redacting JSON: %w", err)
	}
	n := 0
	out, err := json.Marshal(redactJSONValue("", v, &n))
	if err != nil {
		return data, 0, fmt.Errorf("source: re-marshalling redacted JSON: %w", err)
	}
	return out, n, nil
}

// redactJSONValue recursively rewrites a decoded JSON value (as produced by
// json.Unmarshal into `any`): every string leaf is run through redactSecrets
// (catching content-pattern secrets — AWS keys, JWTs, PEM blocks — regardless
// of key name), and additionally, a string leaf whose OWN object key looks
// like a credential name (secretKeyNameRe — "password", "SecretAccessKey",
// "db_token", ...) is force-redacted outright, the same "redact by key, not
// content" rationale sensitiveCacheKeys/sensitiveEnvNamePatterns use — a bare
// value like "hunter2" carries no lexical marker for redactSecrets to key on
// once the key/value relationship only exists as JSON structure. key is the
// object key val was reached under ("" for array elements/the document
// root); n accumulates the total redaction count.
func redactJSONValue(key string, v any, n *int) any {
	switch t := v.(type) {
	case string:
		if key != "" && t != "" && secretKeyNameRe.MatchString(key) {
			*n++
			return redactedMark
		}
		red, k := redactSecrets([]byte(t))
		*n += k
		return string(red)
	case map[string]any:
		for k, val := range t {
			t[k] = redactJSONValue(k, val, n)
		}
		return t
	case []any:
		for i, val := range t {
			t[i] = redactJSONValue("", val, n)
		}
		return t
	default:
		return v
	}
}
