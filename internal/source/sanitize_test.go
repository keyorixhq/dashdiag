package source

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRedactSecrets(t *testing.T) {
	cases := []struct {
		name       string
		in         string
		mustRedact []string // substrings that must be GONE from the output
		mustKeep   []string // substrings that must REMAIN (keys, structure)
		wantN      int
	}{
		{
			name:       "password assignment keeps key, drops value",
			in:         "password=hunter2\nDB_HOST=db.local",
			mustRedact: []string{"hunter2"},
			mustKeep:   []string{"password=", "DB_HOST=db.local"},
			wantN:      1,
		},
		{
			name:       "token and api_key (colon + quotes)",
			in:         `api_key: "AKIAlikebutnot"` + "\n" + `token = 'abc.def.ghi'`,
			mustRedact: []string{"abc.def.ghi"},
			mustKeep:   []string{"api_key:", "token ="},
			wantN:      2,
		},
		{
			name:       "PEM private key block",
			in:         "before\n-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAsecretkeymaterial\n-----END OPENSSH PRIVATE KEY-----\nafter",
			mustRedact: []string{"secretkeymaterial", "BEGIN OPENSSH"},
			mustKeep:   []string{"before", "after"},
			wantN:      1,
		},
		{
			name:       "AWS access key id",
			in:         "aws_key AKIAIOSFODNN7EXAMPLE end",
			mustRedact: []string{"AKIAIOSFODNN7EXAMPLE"},
			mustKeep:   []string{"end"},
			wantN:      1,
		},
		{
			name:       "bearer token",
			in:         "Authorization: Bearer eyJhbGciOi.payload.sig",
			mustRedact: []string{"eyJhbGciOi.payload.sig"},
			mustKeep:   []string{"Authorization:"},
			wantN:      1,
		},
		{
			name:       "shadow hash",
			in:         "root:$6$saltsalt$bighashvalue:19000:0:99999:7:::",
			mustRedact: []string{"bighashvalue", "saltsalt"},
			mustKeep:   []string{"root:", "19000"},
			wantN:      1,
		},
		{
			name:       "no secrets is untouched",
			in:         "cpu MHz: 3600\nMemTotal: 16 kB\nhostname web01",
			mustRedact: nil,
			mustKeep:   []string{"cpu MHz: 3600", "web01"},
			wantN:      0,
		},
		{
			name:       "bare JWT with no Bearer/token prefix",
			in:         "dump: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PYb end", // gitleaks:allow -- synthetic test fixture, not a real token
			mustRedact: []string{"eyJhbGciOiJIUzI1NiJ9", "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PYb"},
			mustKeep:   []string{"dump:", "end"},
			wantN:      1,
		},
		{
			name:       "URL-embedded credentials keep scheme/user/host, drop password",
			in:         "connect to postgresql://admin:S3cretPW@db.internal:5432/mydb now",
			mustRedact: []string{"S3cretPW"},
			mustKeep:   []string{"postgresql://admin:", "@db.internal:5432/mydb"},
			wantN:      1,
		},
		{
			// The keyword regex previously required the operator immediately
			// after the bare keyword, so a suffixed env-var name never matched
			// — SECRET_KEY_BASE was written to a sanitized bundle in the clear.
			name:       "suffixed keyword env vars (SECRET_KEY_BASE, DJANGO_SECRET_KEY)",
			in:         "SECRET_KEY_BASE=abc123def456\nDJANGO_SECRET_KEY: 'topsecretvalue'\nDB_HOST=db.local",
			mustRedact: []string{"abc123def456", "topsecretvalue"},
			mustKeep:   []string{"SECRET_KEY_BASE=", "DJANGO_SECRET_KEY:", "DB_HOST=db.local"},
			wantN:      2,
		},
		{
			// sanitize-bundle-05: the unquoted-value alternative previously used a
			// greedy \S+ that stopped at the first whitespace, so only "hunter" was
			// redacted and "two words" leaked into the sanitized output.
			name:       "unquoted value spanning multiple words redacted in full",
			in:         "password = hunter two words\nnext_line=untouched",
			mustRedact: []string{"hunter two words", "hunter", "two words"},
			mustKeep:   []string{"password =", "next_line=untouched"},
			wantN:      1,
		},
		{
			// The end-of-line value match must stay line-scoped: it must not
			// swallow a following line's content into the (dropped) value group,
			// which would otherwise delete "next_line=untouched" instead of
			// leaving it as a separate, unredacted match.
			name:       "unquoted multi-word value does not swallow the next line",
			in:         "password = hunter two words\nsecret = another value here",
			mustRedact: []string{"hunter two words", "another value here"},
			mustKeep:   []string{"password =", "secret ="},
			wantN:      2,
		},
		{
			// Found via a canary-file sweep of `dsd capture --raw --sanitize`:
			// /etc/apt/auth.conf.d/*.conf (read verbatim by pve_linux.go) uses
			// netrc grammar — "login USER" / "password PASS" with a bare space,
			// no "="/":" — which the keyword rule above cannot see.
			name:       "netrc/apt auth.conf.d two-line login/password",
			in:         "machine enterprise.proxmox.com/debian/pve\nlogin canary-svc-account\npassword S3cretApt9f8e\n",
			mustRedact: []string{"S3cretApt9f8e"},
			mustKeep:   []string{"machine enterprise.proxmox.com/debian/pve", "login canary-svc-account", "password "},
			wantN:      1,
		},
		{
			name:       "netrc-style one-line machine/login/password",
			in:         "machine deb.example.com login myuser password mysecretpw",
			mustRedact: []string{"mysecretpw"},
			mustKeep:   []string{"machine deb.example.com", "login myuser", "password "},
			wantN:      1,
		},
		{
			// The netrc rule is line-anchored specifically so ordinary prose
			// containing both words never matches — it must not fire outside a
			// real credential-file line.
			name:       "prose containing both words is not mistaken for netrc credentials",
			in:         "Please login then enter your password immediately.\nThe login and password steps are separate from checkout.",
			mustRedact: nil,
			mustKeep:   []string{"Please login then enter your password immediately.", "login and password steps are separate"},
			wantN:      0,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, n := redactSecrets([]byte(c.in))
			got := string(out)
			if n != c.wantN {
				t.Errorf("redaction count = %d, want %d (out: %q)", n, c.wantN, got)
			}
			for _, s := range c.mustRedact {
				if strings.Contains(got, s) {
					t.Errorf("secret %q still present after redaction: %q", s, got)
				}
			}
			for _, s := range c.mustKeep {
				if !strings.Contains(got, s) {
					t.Errorf("expected %q to remain, got: %q", s, got)
				}
			}
			// Determinism: re-redacting the output must produce identical bytes
			// (stable for replay). The match count may be non-zero — the assignment
			// rule re-matches the "[REDACTED]" placeholder value — but the bytes
			// must not change, which is the property replay depends on.
			if out2, _ := redactSecrets(out); string(out2) != got {
				t.Errorf("not byte-stable on second pass: %q -> %q", got, string(out2))
			}
		})
	}

	if _, n := redactSecrets(nil); n != 0 {
		t.Errorf("nil input should yield 0 redactions, got %d", n)
	}
}

func TestBundleSanitize(t *testing.T) {
	b := NewBundle()
	b.PutFile("/etc/app/config", []byte("password=topsecret\nport=8080"))
	b.PutFile("/proc/cpuinfo", []byte("model name: Xeon\nMHz: 2400")) // no secret
	b.putCmd("env", nil, Result{Stdout: []byte("DB_TOKEN=abc123\nPATH=/usr/bin")}, nil)

	rep := b.Sanitize(SanitizeOptions{})
	if rep.FilesRedacted != 1 || rep.CommandsRedacted != 1 || rep.TotalRedactions != 2 {
		t.Fatalf("report = %+v, want files=1 cmds=1 total=2", rep)
	}

	if fr, _ := b.getFile("/etc/app/config"); strings.Contains(string(fr.data), "topsecret") {
		t.Errorf("secret left in config file: %q", fr.data)
	} else if !strings.Contains(string(fr.data), "port=8080") {
		t.Errorf("non-secret content dropped: %q", fr.data)
	}
	if fr, _ := b.getFile("/proc/cpuinfo"); string(fr.data) != "model name: Xeon\nMHz: 2400" {
		t.Errorf("non-secret file was modified: %q", fr.data)
	}
	if cr, _ := b.getCmd("env", nil); strings.Contains(string(cr.res.Stdout), "abc123") {
		t.Errorf("secret left in command output: %q", cr.res.Stdout)
	}
}

// TestBundleSanitizeSensitiveCacheKey guards the IMDSv2-token gap: the cached
// AWS session token carries no "token="/"password=" label for the generic
// secretRules to key on (it's a bare opaque string cached verbatim so replay
// can reuse it as the metadata-GET header), so it must be force-redacted by
// its known Cached() key instead of by content pattern.
func TestBundleSanitizeSensitiveCacheKey(t *testing.T) {
	b := NewBundle()
	tokenPath := cacheKey("imds-aws-token")
	b.PutFile(tokenPath, []byte("AQAEAB8O1u9wJlPtb3example-opaque-session-token"))
	b.PutFile("/proc/cpuinfo", []byte("model name: Xeon")) // untouched control

	rep := b.Sanitize(SanitizeOptions{})
	if rep.FilesRedacted != 1 || rep.TotalRedactions != 1 {
		t.Fatalf("report = %+v, want files=1 total=1", rep)
	}

	fr, ok := b.getFile(tokenPath)
	if !ok {
		t.Fatal("cached IMDS token file should still exist after sanitize")
	}
	if strings.Contains(string(fr.data), "example-opaque-session-token") {
		t.Errorf("IMDS token value survived sanitize: %q", fr.data)
	}
	if string(fr.data) != redactedMark {
		t.Errorf("expected the cached token to be fully replaced with %q, got %q", redactedMark, fr.data)
	}

	if fr2, _ := b.getFile("/proc/cpuinfo"); string(fr2.data) != "model name: Xeon" {
		t.Errorf("unrelated file should be untouched, got %q", fr2.data)
	}
}

// TestBundleSanitizeSkipsEmptyFiles verifies Sanitize skips zero-length
// recorded files entirely (nothing to redact, no report increment) rather
// than running the regex passes over empty data.
func TestBundleSanitizeSkipsEmptyFiles(t *testing.T) {
	t.Parallel()

	b := NewBundle()
	b.PutFile("/etc/empty", []byte(""))
	b.putFile("/etc/absent", nil, nil) // notExist-style record with nil data

	rep := b.Sanitize(SanitizeOptions{})
	if rep.FilesRedacted != 0 || rep.TotalRedactions != 0 {
		t.Fatalf("report = %+v, want no redactions for empty/absent files", rep)
	}
}

// TestBundleSanitizeStderrOnly verifies Sanitize redacts a secret that
// appears ONLY in a command's stderr (not stdout), exercising the stderr
// redaction branch independently of stdout.
func TestBundleSanitizeStderrOnly(t *testing.T) {
	t.Parallel()

	b := NewBundle()
	b.putCmd("curl", []string{"-v"}, Result{
		Stdout: []byte("200 OK"),
		Stderr: []byte("Authorization: Bearer eyJhbGciOi.payload.sig"),
	}, nil)

	rep := b.Sanitize(SanitizeOptions{})
	if rep.CommandsRedacted != 1 || rep.TotalRedactions != 1 {
		t.Fatalf("report = %+v, want cmds=1 total=1", rep)
	}
	cr, _ := b.getCmd("curl", []string{"-v"})
	if strings.Contains(string(cr.res.Stderr), "eyJhbGciOi.payload.sig") {
		t.Errorf("secret left in stderr: %q", cr.res.Stderr)
	}
	if string(cr.res.Stdout) != "200 OK" {
		t.Errorf("stdout should be untouched, got %q", cr.res.Stdout)
	}
}

// TestBundleSanitizeWithIdentifiers exercises Sanitize(SanitizeOptions{Identifiers:
// true}) end to end — the branch that also redacts IPs/MACs/hostname (not just
// secrets), including the manifest.Host replacement.
func TestBundleSanitizeWithIdentifiers(t *testing.T) {
	t.Parallel()
	b := NewBundle()
	b.Manifest.Host = "web01"
	b.PutFile("/etc/hosts", []byte("192.168.1.1 web01\npassword=hunter2"))
	b.putCmd("ip", []string{"addr"}, Result{Stdout: []byte("link/ether aa:bb:cc:dd:ee:ff")}, nil)

	rep := b.Sanitize(SanitizeOptions{Identifiers: true})
	if rep.FilesRedacted == 0 || rep.CommandsRedacted == 0 {
		t.Fatalf("report = %+v, want both files and commands redacted", rep)
	}

	fr, _ := b.getFile("/etc/hosts")
	got := string(fr.data)
	if strings.Contains(got, "192.168.1.1") {
		t.Errorf("IP survived Sanitize(Identifiers:true): %q", got)
	}
	if strings.Contains(got, "web01") {
		t.Errorf("hostname survived Sanitize(Identifiers:true): %q", got)
	}
	if strings.Contains(got, "hunter2") {
		t.Errorf("secret survived Sanitize(Identifiers:true): %q", got)
	}

	cr, _ := b.getCmd("ip", []string{"addr"})
	if strings.Contains(string(cr.res.Stdout), "aa:bb:cc:dd:ee:ff") {
		t.Errorf("MAC survived Sanitize(Identifiers:true): %q", cr.res.Stdout)
	}

	if b.Manifest.Host != hostPlaceholder {
		t.Errorf("manifest.Host = %q, want %q", b.Manifest.Host, hostPlaceholder)
	}
}

// TestBundleSanitizeIdentifiersHostGuard verifies Sanitize does NOT replace
// Manifest.Host when it is empty or the literal placeholder "host" — both are
// non-identifying sentinel values, not a real hostname to redact.
func TestBundleSanitizeIdentifiersHostGuard(t *testing.T) {
	t.Parallel()
	for _, host := range []string{"", "host"} {
		b := NewBundle()
		b.Manifest.Host = host
		b.PutFile("/etc/motd", []byte("welcome"))
		b.Sanitize(SanitizeOptions{Identifiers: true})
		if b.Manifest.Host != host {
			t.Errorf("Manifest.Host changed from %q to %q, want unchanged", host, b.Manifest.Host)
		}
	}
}

// TestRedactSecretsASIAPrefix guards sanitize-bundle-02: the AWS access-key-ID
// rule originally only matched the AKIA (long-lived IAM user key) prefix, so a
// temporary/STS access key ID (ASIA — the AWS-recommended, now-dominant shape
// from AssumeRole/EC2 instance profiles/EKS IRSA/Lambda) shipped in the clear.
// Deliberately BARE (no "key_id=" label): a labeled occurrence is already
// caught by the generic key=value rule regardless of prefix, so this isolates
// the AKIA-only bare-prefix gap specifically (e.g. an access key ID appearing
// unlabeled in a docker inspect Env array entry, a URL query param, or a JSON
// blob with a non-obvious field name).
func TestRedactSecretsASIAPrefix(t *testing.T) {
	t.Parallel()
	in := "container env dump: ASIAQWERTY1234ABCDEF end" // 20 chars: ASIA + 16 alnum
	out, n := redactSecrets([]byte(in))
	got := string(out)
	if n == 0 {
		t.Fatalf("expected ≥1 redaction, got 0: %q", got)
	}
	if strings.Contains(got, "ASIAQWERTY1234ABCDEF") {
		t.Errorf("bare ASIA-prefixed temporary AWS access key survived redaction: %q", got)
	}
	if !strings.Contains(got, "end") {
		t.Errorf("unrelated trailing content dropped: %q", got)
	}
}

// TestRedactIdentifiersCaseInsensitiveHostname guards redaction-primitives-06:
// hostRe had no (?i) flag, so a differently-cased rendering of the hostname
// (e.g. an upcased syslog HOSTNAME field) survived --identifiers untouched.
func TestRedactIdentifiersCaseInsensitiveHostname(t *testing.T) {
	t.Parallel()
	in := "syslog: HOSTNAME=WEB01 reboot detected"
	out, n := redactIdentifiers([]byte(in), "web01")
	got := string(out)
	if n == 0 {
		t.Fatalf("expected ≥1 redaction, got 0: %q", got)
	}
	if strings.Contains(got, "WEB01") {
		t.Errorf("differently-cased hostname survived redaction: %q", got)
	}
	if !strings.Contains(got, hostPlaceholder) {
		t.Errorf("expected hostname placeholder, got: %q", got)
	}
}

// TestBundleSanitizeSensitiveEnvCacheKey guards redaction-primitives-07:
// getenv()'s Cached("env/"+name, ...) blob has no "name=value" label for the
// generic secretRules to key on (it caches the bare value), and only the one
// hardcoded "imds-aws-token" cache key was ever force-redacted by key. A
// future collector reading a genuinely sensitive env var (e.g. as a
// cloud-provider detection signal) needs the same treatment for ANY
// credential-shaped env var name, not just that one entry.
func TestBundleSanitizeSensitiveEnvCacheKey(t *testing.T) {
	t.Parallel()
	b := NewBundle()
	envPath := cacheKey("env/AWS_SECRET_ACCESS_KEY")
	b.PutFile(envPath, []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"))
	b.PutFile("/proc/cpuinfo", []byte("model name: Xeon")) // untouched control

	rep := b.Sanitize(SanitizeOptions{})
	if rep.FilesRedacted != 1 || rep.TotalRedactions != 1 {
		t.Fatalf("report = %+v, want files=1 total=1", rep)
	}
	fr, ok := b.getFile(envPath)
	if !ok {
		t.Fatal("cached env file should still exist after sanitize")
	}
	if strings.Contains(string(fr.data), "wJalrXUtnFEMI") {
		t.Errorf("secret env value survived sanitize: %q", fr.data)
	}
	if fr2, _ := b.getFile("/proc/cpuinfo"); string(fr2.data) != "model name: Xeon" {
		t.Errorf("unrelated file should be untouched, got %q", fr2.data)
	}
}

// TestIsSensitiveEnvCacheKey_BenignName covers the "no pattern matched"
// return: an env/-prefixed cache key for a name that isn't credential-shaped
// must not be force-redacted.
func TestIsSensitiveEnvCacheKey_BenignName(t *testing.T) {
	t.Parallel()
	if isSensitiveEnvCacheKey(cacheKey("env/PATH")) {
		t.Error("isSensitiveEnvCacheKey(env/PATH) = true, want false for a benign env var name")
	}
}

// TestBundleSanitizeCmdArgvSecret guards redaction-primitives-02: Sanitize
// never touched a command's own argv, only its stdout/stderr — persist.go's
// Save() writes argv verbatim into commands/index.json, so a credential
// passed as a CLI argument (a diagnostic tool invoked with a token flag)
// shipped unredacted in an otherwise "sanitized" bundle.
func TestBundleSanitizeCmdArgvSecret(t *testing.T) {
	t.Parallel()
	b := NewBundle()
	b.putCmd("probe-tool", []string{"--token=abc123secretvalue", "--verbose"},
		Result{Stdout: []byte("200 OK")}, nil)

	rep := b.Sanitize(SanitizeOptions{})
	if rep.CommandsRedacted != 1 || rep.TotalRedactions != 1 {
		t.Fatalf("report = %+v, want cmds=1 total=1", rep)
	}

	// The secret must be gone from whatever key now backs this command AND must
	// not be reachable via the original (unredacted) argv lookup.
	if _, ok := b.getCmd("probe-tool", []string{"--token=abc123secretvalue", "--verbose"}); ok {
		t.Fatal("command should no longer be reachable by its original, unredacted argv")
	}
	found := false
	for key := range b.cmds {
		if strings.Contains(key, "abc123secretvalue") {
			t.Errorf("secret argv value survived in bundle key: %q", key)
		}
		if strings.Contains(key, "probe-tool") {
			found = true
			if !strings.Contains(key, "--verbose") {
				t.Errorf("non-secret argv element dropped from key: %q", key)
			}
		}
	}
	if !found {
		t.Fatal("expected the probe-tool command to still be present under a redacted key")
	}
}

// TestSaveCmdArgvSecretRedacted is the persisted-index-level regression for
// redaction-primitives-02: after Sanitize(), the on-disk
// commands/index.json (what an operator actually hands to a vendor) must not
// contain the raw secret in its argv field.
func TestSaveCmdArgvSecretRedacted(t *testing.T) {
	t.Parallel()
	b := NewBundle()
	b.putCmd("probe-tool", []string{"--token=abc123secretvalue"}, Result{Stdout: []byte("ok")}, nil)
	b.Sanitize(SanitizeOptions{})

	dir := t.TempDir()
	if err := b.Save(dir); err != nil {
		t.Fatalf("Save: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "commands", "index.json"))
	if err != nil {
		t.Fatalf("reading commands/index.json: %v", err)
	}
	if strings.Contains(string(raw), "abc123secretvalue") {
		t.Errorf("secret argv value persisted to commands/index.json: %s", raw)
	}
	if !strings.Contains(string(raw), "probe-tool") {
		t.Errorf("command name should still be present: %s", raw)
	}
}

// TestBundleSanitizeErrTextSecret guards redaction-primitives-03 /
// sanitize-bundle-04: Sanitize only ever iterated b.files' data and b.cmds'
// stdout/stderr — a file read's recorded error TEXT (fileRec.errText,
// persisted as fileIndexEntry.Err) was never passed through redactSecrets at
// all, even when the OS error text happened to embed sensitive content (a
// path with a credential in it, or a wrapped lower-level error carrying one).
func TestBundleSanitizeErrTextSecret(t *testing.T) {
	t.Parallel()
	b := NewBundle()
	b.files["/etc/secret.d/creds"] = fileRec{
		errText: "open /etc/secret.d/creds: dial failed: password=hunter2secret",
	}
	rep := b.Sanitize(SanitizeOptions{})
	if rep.FilesRedacted != 1 || rep.TotalRedactions != 1 {
		t.Fatalf("report = %+v, want files=1 total=1", rep)
	}
	fr, _ := b.getFile("/etc/secret.d/creds")
	if strings.Contains(fr.errText, "hunter2secret") {
		t.Errorf("secret survived in file errText: %q", fr.errText)
	}
	if !strings.Contains(fr.errText, "dial failed") {
		t.Errorf("non-secret error context dropped: %q", fr.errText)
	}
}

// TestBundleSanitizeLinkTarget guards the links.json half of
// redaction-primitives-03 / sanitize-bundle-04: a symlink target is recorded
// verbatim from the live filesystem and was never passed through Sanitize.
func TestBundleSanitizeLinkTarget(t *testing.T) {
	t.Parallel()
	b := NewBundle()
	b.putLink("/etc/app/current-config", "/mnt/secrets/token=abc123secretvalue/config", nil)

	rep := b.Sanitize(SanitizeOptions{})
	if rep.TotalRedactions == 0 {
		t.Fatalf("report = %+v, want ≥1 redaction", rep)
	}
	rec, _ := b.getLink("/etc/app/current-config")
	if strings.Contains(rec.target, "abc123secretvalue") {
		t.Errorf("secret survived in symlink target: %q", rec.target)
	}
}

// TestBundleSanitizeDirEntrySecret guards the dirs.json half of
// redaction-primitives-03 / sanitize-bundle-04: directory listing entries
// were never passed through Sanitize at all.
func TestBundleSanitizeDirEntrySecret(t *testing.T) {
	t.Parallel()
	b := NewBundle()
	b.putDir("/mnt/secrets", []string{"readme.txt", "token=abc123secretvalue.txt"})

	rep := b.Sanitize(SanitizeOptions{})
	if rep.TotalRedactions == 0 {
		t.Fatalf("report = %+v, want ≥1 redaction", rep)
	}
	entries, _ := b.getDir("/mnt/secrets")
	for _, e := range entries {
		if strings.Contains(e, "abc123secretvalue") {
			t.Errorf("secret survived in dir listing entry: %q", e)
		}
	}
	found := false
	for _, e := range entries {
		if e == "readme.txt" {
			found = true
		}
	}
	if !found {
		t.Errorf("non-secret dir entry dropped, got: %v", entries)
	}
}

// TestRedactJSONSecrets guards sanitize-bundle-01: `dsd mcp`'s dsd_health /
// dsd_replay tools returned checks[].raw verbatim over MCP with no redaction
// path at all. Exercises the JSON-safe leaf-walking approach on COMPACT
// (no-whitespace) JSON, the shape where a naive byte-level regex pass against
// already-serialized JSON would corrupt structure.
func TestRedactJSONSecrets(t *testing.T) {
	t.Parallel()
	in := `{"checks":[{"name":"env","raw":{"line":"token=abc123secretvalue","port":8080}}],"status":"OK"}`
	out, err := RedactJSONSecrets([]byte(in))
	if err != nil {
		t.Fatalf("RedactJSONSecrets: %v", err)
	}
	if strings.Contains(string(out), "abc123secretvalue") {
		t.Errorf("secret survived RedactJSONSecrets: %s", out)
	}
	var v map[string]any
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatalf("RedactJSONSecrets produced invalid JSON: %v\noutput: %s", err, out)
	}
	if v["status"] != "OK" {
		t.Errorf("non-secret field corrupted: %+v", v)
	}
	checks, _ := v["checks"].([]any)
	if len(checks) != 1 {
		t.Fatalf("expected 1 check to survive, got: %+v", v)
	}
	raw, _ := checks[0].(map[string]any)["raw"].(map[string]any)
	if raw["port"] != float64(8080) {
		t.Errorf("non-secret nested field corrupted: %+v", raw)
	}
}

// TestRedactSecretsMissesJSONQuotedKey documents internal-source-02-01's exact
// failure mode: secretRules[1] requires a bare key literal immediately
// followed (mod whitespace) by "="/":" with no intervening quote, so a
// JSON-quoted key like "password":"hunter2" is invisible to it — the closing
// quote after the key breaks the pattern. This is why redaction of JSON
// content is NOT handled by extending this regex (see redactSecretsAndJSON's
// doc), but by the structural JSON pass in RedactJSONSecrets/redactJSONValue.
func TestRedactSecretsMissesJSONQuotedKey(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		`"password":"hunter2"`,
		`"SecretAccessKey" : "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`,
	} {
		out, n := redactSecrets([]byte(in))
		if n != 0 || string(out) != in {
			t.Errorf("redactSecrets(%q) = %q (n=%d); expected the JSON-quoted-key line scan to NOT catch this (that's redactSecretsAndJSON's job)", in, out, n)
		}
	}
}

// TestRedactSecretsAndJSON covers internal-source-02-01: a JSON-formatted
// capture file (or command output, e.g. `docker inspect`/`kubectl -o json`)
// with a quoted key immediately followed by its value — "password":"hunter2"
// — must be redacted even though secretRules[1]'s line-scan regex can't see
// it (TestRedactSecretsMissesJSONQuotedKey). redactSecretsAndJSON is what
// Bundle.Sanitize's redact closure now calls instead of bare redactSecrets.
func TestRedactSecretsAndJSON(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		in         string
		mustRedact []string
		mustKeep   []string
	}{
		{
			name:       "compact JSON quoted key:value",
			in:         `{"password":"hunter2","port":8080}`,
			mustRedact: []string{"hunter2"},
			mustKeep:   []string{`"password"`, `"port":8080`},
		},
		{
			name:       "spaced JSON quoted key : value (AWS-shaped key)",
			in:         `{"SecretAccessKey" : "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "Region":"us-east-1"}`,
			mustRedact: []string{"wJalrXUtnFEMI"},
			mustKeep:   []string{`"SecretAccessKey"`, `"Region":"us-east-1"`},
		},
		{
			name:       "nested object: only the secret-named leaf is redacted",
			in:         `{"credentials":{"user":"alice","token":"abc123xyz"},"ok":true}`,
			mustRedact: []string{"abc123xyz"},
			mustKeep:   []string{`"user":"alice"`, `"ok":true`},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			out, n := redactSecretsAndJSON([]byte(c.in))
			if n == 0 {
				t.Errorf("expected ≥1 redaction, got 0 (out: %q)", out)
			}
			if !json.Valid(out) {
				t.Errorf("redactSecretsAndJSON produced invalid JSON: %s", out)
			}
			got := string(out)
			for _, s := range c.mustRedact {
				if strings.Contains(got, s) {
					t.Errorf("secret %q still present after redaction: %q", s, got)
				}
			}
			for _, s := range c.mustKeep {
				if !strings.Contains(got, s) {
					t.Errorf("expected %q to remain, got: %q", s, got)
				}
			}
		})
	}

	// Non-JSON content (the common case) must still go through the plain
	// regex path unchanged.
	out, n := redactSecretsAndJSON([]byte("password=hunter2"))
	if n != 1 || strings.Contains(string(out), "hunter2") {
		t.Errorf("plain key=value text should still be redacted by the regex path, got %q (n=%d)", out, n)
	}

	// Something that merely starts with '{' but isn't valid JSON (e.g. a shell
	// snippet) must fall back to the regex-only result rather than erroring.
	notJSON := "{ not json, password=hunter2 }"
	out, n = redactSecretsAndJSON([]byte(notJSON))
	if strings.Contains(string(out), "hunter2") {
		t.Errorf("non-JSON content starting with '{' should still get the regex pass: %q (n=%d)", out, n)
	}
}

// TestBundleSanitizeJSONFile is the end-to-end path for internal-source-02-01:
// a captured JSON file (e.g. a recorded `docker inspect`/API response) with a
// JSON-quoted secret key must come out redacted AND still be valid JSON after
// Bundle.Sanitize, since sanitized capture bundles are replayed and
// JSON-formatted captures get json.Unmarshal'd back by collectors.
func TestBundleSanitizeJSONFile(t *testing.T) {
	b := NewBundle()
	b.PutFile("/var/lib/docker/containers/x/config.json",
		[]byte(`{"Env":["PATH=/usr/bin"],"password":"hunter2","SecretAccessKey":"wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"}`))

	rep := b.Sanitize(SanitizeOptions{})
	if rep.FilesRedacted != 1 {
		t.Fatalf("report = %+v, want files=1", rep)
	}

	fr, _ := b.getFile("/var/lib/docker/containers/x/config.json")
	if !json.Valid(fr.data) {
		t.Fatalf("sanitized JSON file is no longer valid JSON: %s", fr.data)
	}
	got := string(fr.data)
	for _, s := range []string{"hunter2", "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"} {
		if strings.Contains(got, s) {
			t.Errorf("secret survived Bundle.Sanitize on a JSON file: %q", got)
		}
	}
	if !strings.Contains(got, `"PATH=/usr/bin"`) {
		t.Errorf("non-secret content dropped: %q", got)
	}
}

func TestRedactIdentifiers(t *testing.T) {
	in := "gw 192.168.1.1 mac aa:bb:cc:dd:ee:ff host web01\n" +
		"loopback 127.0.0.1 unspec 0.0.0.0 version 1.2.3.999\n" +
		"again 192.168.1.1"
	out, n := redactIdentifiers([]byte(in), "web01")
	got := string(out)

	// Sensitive identifiers gone.
	for _, s := range []string{"192.168.1.1", "aa:bb:cc:dd:ee:ff", "web01"} {
		if strings.Contains(got, s) {
			t.Errorf("identifier %q not redacted: %q", s, got)
		}
	}
	// Preserved: loopback, unspecified, and a non-IP version string.
	for _, s := range []string{"127.0.0.1", "0.0.0.0", "1.2.3.999"} {
		if !strings.Contains(got, s) {
			t.Errorf("expected %q to be preserved, got: %q", s, got)
		}
	}
	if !strings.Contains(got, hostPlaceholder) {
		t.Errorf("hostname should map to %s, got: %q", hostPlaceholder, got)
	}
	// Stable mapping: the IP appears twice and must redact to the SAME token both
	// times (correlation preserved) — count its occurrences in the output.
	tok := idPlaceholder("IP", "192.168.1.1")
	if strings.Count(got, tok) != 2 {
		t.Errorf("expected the repeated IP to map to the same token twice, got: %q", got)
	}
	if n == 0 {
		t.Errorf("expected redactions, got 0")
	}

	// Determinism: same input → identical output bytes.
	if out2, _ := redactIdentifiers([]byte(in), "web01"); string(out2) != got {
		t.Errorf("redactIdentifiers not deterministic")
	}
}
