package source

import (
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
