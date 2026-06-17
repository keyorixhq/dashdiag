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

	rep := b.Sanitize()
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
