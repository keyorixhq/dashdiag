package cis

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// ── result-helper constructors ───────────────────────────────────────────────

func TestResultHelpers(t *testing.T) {
	r := Rule{ID: "X.1", Framework: "BOTH", Level: 2, Section: "SSH", Description: "desc"}

	if got := pass(r); got.Status != models.CISPass || got.ID != "X.1" ||
		got.Framework != "BOTH" || got.Level != 2 || got.Section != "SSH" || got.Description != "desc" {
		t.Errorf("pass() = %+v, fields not copied from rule", got)
	}

	f := failr(r, "the finding", "the fix")
	if f.Status != models.CISFail || f.Finding != "the finding" || f.Remediation != "the fix" {
		t.Errorf("failr() = %+v, want FAIL with finding+remediation", f)
	}

	s := skipr(r, "why skipped")
	if s.Status != models.CISSkipped || s.Finding != "why skipped" {
		t.Errorf("skipr() = %+v, want SKIP with reason in Finding", s)
	}
}

// ── parseMaxStartups ─────────────────────────────────────────────────────────

func TestParseMaxStartups(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		in        string
		wantStart int
		wantFull  int
		wantOK    bool
	}{
		{"bare value has no throttling, full==start", "10", 10, 10, true},
		{"full triplet parses both ends", "10:30:60", 10, 60, true},
		{"whitespace is trimmed", "  10:30:60  ", 10, 60, true},
		{"non-numeric start fails to parse", "abc:30:60", 0, 0, false},
		{"non-numeric full fails to parse", "10:30:xyz", 0, 0, false},
		{"empty string fails to parse", "", 0, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			start, full, ok := parseMaxStartups(tc.in)
			if start != tc.wantStart || full != tc.wantFull || ok != tc.wantOK {
				t.Errorf("parseMaxStartups(%q) = (%d, %d, %v), want (%d, %d, %v)",
					tc.in, start, full, ok, tc.wantStart, tc.wantFull, tc.wantOK)
			}
		})
	}
}

// ── checkSysctl ──────────────────────────────────────────────────────────────

func TestCheckSysctl(t *testing.T) {
	r := Rule{ID: "3.1.1", Framework: "BOTH"}

	write := func(t *testing.T, content string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "knob")
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Run("matches wanted value", func(t *testing.T) {
		got := checkSysctl(r, write(t, "0\n"), "0", "finding", "fix")
		if got.Status != models.CISPass {
			t.Errorf("want PASS, got %s (%s)", got.Status, got.Finding)
		}
	})
	t.Run("differs from wanted value", func(t *testing.T) {
		got := checkSysctl(r, write(t, "1"), "0", "ip_forward on", "fix")
		if got.Status != models.CISFail || got.Finding != "ip_forward on" {
			t.Errorf("want FAIL with finding, got %s (%s)", got.Status, got.Finding)
		}
	})
	t.Run("missing path skips", func(t *testing.T) {
		got := checkSysctl(r, filepath.Join(t.TempDir(), "nope"), "0", "finding", "fix")
		if got.Status != models.CISSkipped {
			t.Errorf("want SKIP for missing path, got %s", got.Status)
		}
	})
}

// ── checkFilePerm ────────────────────────────────────────────────────────────

func TestCheckFilePerm(t *testing.T) {
	r := Rule{ID: "6.1.1", Framework: "BOTH"}

	withMode := func(t *testing.T, mode os.FileMode) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "f")
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Run("stricter than max passes", func(t *testing.T) {
		got := checkFilePerm(r, withMode(t, 0o600), 0o644, "fix")
		if got.Status != models.CISPass {
			t.Errorf("0600 <= 0644 should PASS, got %s (%s)", got.Status, got.Finding)
		}
	})
	t.Run("equal to max passes", func(t *testing.T) {
		got := checkFilePerm(r, withMode(t, 0o644), 0o644, "fix")
		if got.Status != models.CISPass {
			t.Errorf("0644 == 0644 should PASS, got %s", got.Status)
		}
	})
	t.Run("looser than max fails", func(t *testing.T) {
		got := checkFilePerm(r, withMode(t, 0o666), 0o644, "chmod 644")
		if got.Status != models.CISFail || got.Remediation != "chmod 644" {
			t.Errorf("0666 > 0644 should FAIL with remediation, got %s (%s)", got.Status, got.Remediation)
		}
	})
	t.Run("missing path skips", func(t *testing.T) {
		got := checkFilePerm(r, filepath.Join(t.TempDir(), "nope"), 0o644, "fix")
		if got.Status != models.CISSkipped {
			t.Errorf("want SKIP for missing path, got %s", got.Status)
		}
	})
	// Regression: these modes are numerically SMALLER than maxMode but add a
	// forbidden bit. A magnitude compare (perm > maxMode) wrongly passed them.
	t.Run("world-readable shadow fails despite lower numeric value", func(t *testing.T) {
		// 0o604 (=388) < 0o640 (=416) but world-read is forbidden on /etc/shadow.
		got := checkFilePerm(r, withMode(t, 0o604), 0o640, "chmod 640")
		if got.Status != models.CISFail {
			t.Errorf("0604 has world-read beyond 0640 — must FAIL, got %s", got.Status)
		}
	})
	t.Run("group-writable passwd fails despite lower numeric value", func(t *testing.T) {
		// 0o620 (=400) < 0o644 (=420) but group-write is forbidden on /etc/passwd.
		got := checkFilePerm(r, withMode(t, 0o620), 0o644, "chmod 644")
		if got.Status != models.CISFail {
			t.Errorf("0620 has group-write beyond 0644 — must FAIL, got %s", got.Status)
		}
	})
}

// ── checkLoginDefsField ──────────────────────────────────────────────────────

func TestCheckLoginDefsField(t *testing.T) {
	t.Parallel()
	r := Rule{ID: "5.4.1", Framework: "BOTH"}

	write := func(t *testing.T, content string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "login.defs")
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	failsOver365 := func(days int) bool { return days > 365 || days == 0 }

	t.Run("compliant value passes", func(t *testing.T) {
		t.Parallel()
		got := checkLoginDefsField(r, write(t, "PASS_MAX_DAYS\t90\n"), "PASS_MAX_DAYS", failsOver365,
			"PASS_MAX_DAYS is %d", "fix", "not set", "add it")
		if got.Status != models.CISPass {
			t.Errorf("90 days should PASS, got %s (%s)", got.Status, got.Finding)
		}
	})
	t.Run("value exceeding threshold fails", func(t *testing.T) {
		t.Parallel()
		got := checkLoginDefsField(r, write(t, "PASS_MAX_DAYS\t99999\n"), "PASS_MAX_DAYS", failsOver365,
			"PASS_MAX_DAYS is %d", "set PASS_MAX_DAYS 365", "not set", "add it")
		if got.Status != models.CISFail || got.Remediation != "set PASS_MAX_DAYS 365" {
			t.Errorf("99999 days should FAIL with remediation, got %s (%s)", got.Status, got.Remediation)
		}
		if got.Finding != "PASS_MAX_DAYS is 99999" {
			t.Errorf("finding = %q, want formatted value", got.Finding)
		}
	})
	t.Run("zero is treated as unbounded and fails", func(t *testing.T) {
		t.Parallel()
		got := checkLoginDefsField(r, write(t, "PASS_MAX_DAYS\t0\n"), "PASS_MAX_DAYS", failsOver365,
			"PASS_MAX_DAYS is %d", "fix", "not set", "add it")
		if got.Status != models.CISFail {
			t.Errorf("0 (no expiry) should FAIL, got %s", got.Status)
		}
	})
	t.Run("commented line is ignored, field then reported not set", func(t *testing.T) {
		t.Parallel()
		got := checkLoginDefsField(r, write(t, "# PASS_MAX_DAYS 90\n"), "PASS_MAX_DAYS", failsOver365,
			"PASS_MAX_DAYS is %d", "fix", "PASS_MAX_DAYS not set", "add PASS_MAX_DAYS")
		if got.Status != models.CISFail || got.Finding != "PASS_MAX_DAYS not set" {
			t.Errorf("commented-out field should read as not set, got %s (%s)", got.Status, got.Finding)
		}
	})
	t.Run("field entirely absent fails with notSet message", func(t *testing.T) {
		t.Parallel()
		got := checkLoginDefsField(r, write(t, "PASS_MIN_DAYS\t0\n"), "PASS_MAX_DAYS", failsOver365,
			"PASS_MAX_DAYS is %d", "fix", "PASS_MAX_DAYS not set", "add PASS_MAX_DAYS")
		if got.Status != models.CISFail || got.Finding != "PASS_MAX_DAYS not set" || got.Remediation != "add PASS_MAX_DAYS" {
			t.Errorf("absent field: got %+v", got)
		}
	})
	t.Run("unreadable file skips", func(t *testing.T) {
		t.Parallel()
		got := checkLoginDefsField(r, filepath.Join(t.TempDir(), "nope"), "PASS_MAX_DAYS", failsOver365,
			"PASS_MAX_DAYS is %d", "fix", "not set", "add it")
		if got.Status != models.CISSkipped {
			t.Errorf("want SKIP for missing file, got %s", got.Status)
		}
	})
	t.Run("field present with no value defers to pass", func(t *testing.T) {
		t.Parallel()
		// Line matches the prefix but has no second field — the predicate is
		// never evaluated and the rule falls through to pass, matching the
		// original inline implementation's behavior for a malformed line.
		got := checkLoginDefsField(r, write(t, "PASS_MAX_DAYS\n"), "PASS_MAX_DAYS", failsOver365,
			"PASS_MAX_DAYS is %d", "fix", "not set", "add it")
		if got.Status != models.CISPass {
			t.Errorf("malformed line (no value) should fall through to PASS, got %s", got.Status)
		}
	})
}

// ── password-aging rules wired through checkLoginDefsField via loginDefsPath ──
// These exercise the shipped 5.4.1 / V-238380 / V-238382 / V-238383 Check
// closures end-to-end by pointing the package-level loginDefsPath at a fixture
// file instead of the real host /etc/login.defs.

func TestPasswordAgingRules_LoginDefsFixture(t *testing.T) {
	saved := loginDefsPath
	t.Cleanup(func() { loginDefsPath = saved })

	writeDefs := func(t *testing.T, content string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "login.defs")
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	cases := []struct {
		name    string
		id      string
		content string
		want    models.CISStatus
	}{
		{"5.4.1 compliant 90 days passes", "5.4.1", "PASS_MAX_DAYS\t90\n", models.CISPass},
		{"5.4.1 default 99999 fails", "5.4.1", "PASS_MAX_DAYS\t99999\n", models.CISFail},
		{"5.4.1 missing file skips", "5.4.1", "", models.CISSkipped},

		{"V-238380 STIG stricter threshold: 90 days fails (>60)", "V-238380", "PASS_MAX_DAYS\t90\n", models.CISFail},
		{"V-238380 60 days passes", "V-238380", "PASS_MAX_DAYS\t60\n", models.CISPass},

		{"V-238382 min days 0 fails", "V-238382", "PASS_MIN_DAYS\t0\n", models.CISFail},
		{"V-238382 min days 1 passes", "V-238382", "PASS_MIN_DAYS\t1\n", models.CISPass},

		{"V-238383 warn age 3 fails", "V-238383", "PASS_WARN_AGE\t3\n", models.CISFail},
		{"V-238383 warn age 7 passes", "V-238383", "PASS_WARN_AGE\t7\n", models.CISPass},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.content == "" {
				loginDefsPath = filepath.Join(t.TempDir(), "nope-login.defs")
			} else {
				loginDefsPath = writeDefs(t, tc.content)
			}
			rule := ruleByID(tc.id)
			if rule.Check == nil {
				t.Fatalf("rule %s has no Check func", tc.id)
			}
			got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
			if got.Status != tc.want {
				t.Errorf("rule %s: got %s, want %s (finding=%q)", tc.id, got.Status, tc.want, got.Finding)
			}
		})
	}
}

// ── ruleByID ─────────────────────────────────────────────────────────────────

func TestRuleByID(t *testing.T) {
	// A known rule from the real registry.
	got := ruleByID("5.2.10")
	if got.ID != "5.2.10" || got.Section != "SSH" || got.Description == "" {
		t.Errorf("ruleByID(5.2.10) = %+v, want populated SSH rule", got)
	}

	// Unknown ID falls back to a CIS stub carrying the requested ID.
	fb := ruleByID("does.not.exist")
	if fb.ID != "does.not.exist" || fb.Framework != "CIS" {
		t.Errorf("ruleByID(unknown) = %+v, want CIS fallback stub", fb)
	}
}

// ── real struct-driven rule checks ───────────────────────────────────────────
// These exercise the shipped Check closures that read only the SecurityInfo /
// KernelSecurityInfo structs (no host filesystem), so they are deterministic on
// every platform including the dev Mac.

func TestStructDrivenRules(t *testing.T) {
	var ks models.KernelSecurityInfo
	cases := []struct {
		name string
		id   string
		sec  models.SecurityInfo
		want models.CISStatus
	}{
		// 5.2.2 SSH access limited
		{"5.2.2 no allow lists fails", "5.2.2", models.SecurityInfo{}, models.CISFail},
		{"5.2.2 AllowUsers set passes", "5.2.2", models.SecurityInfo{SSHAllowUsers: []string{"deploy"}}, models.CISPass},

		// 5.2.5 LogLevel
		{"5.2.5 empty defaults to INFO", "5.2.5", models.SecurityInfo{}, models.CISPass},
		{"5.2.5 VERBOSE ok", "5.2.5", models.SecurityInfo{SSHLogLevel: "VERBOSE"}, models.CISPass},
		{"5.2.5 DEBUG fails", "5.2.5", models.SecurityInfo{SSHLogLevel: "DEBUG"}, models.CISFail},

		// 5.2.6 X11 forwarding
		{"5.2.6 off passes", "5.2.6", models.SecurityInfo{}, models.CISPass},
		{"5.2.6 on fails", "5.2.6", models.SecurityInfo{SSHX11Forwarding: true}, models.CISFail},

		// 5.2.7 MaxAuthTries (default 6)
		{"5.2.7 default 6 fails", "5.2.7", models.SecurityInfo{}, models.CISFail},
		{"5.2.7 value 4 passes", "5.2.7", models.SecurityInfo{SSHMaxAuthTries: 4}, models.CISPass},

		// 5.2.8 IgnoreRhosts
		{"5.2.8 disabled fails", "5.2.8", models.SecurityInfo{}, models.CISFail},
		{"5.2.8 enabled passes", "5.2.8", models.SecurityInfo{SSHIgnoreRhosts: true}, models.CISPass},

		// 5.2.9 HostbasedAuth
		{"5.2.9 enabled fails", "5.2.9", models.SecurityInfo{SSHHostbasedAuth: true}, models.CISFail},
		{"5.2.9 disabled passes", "5.2.9", models.SecurityInfo{}, models.CISPass},

		// 5.2.10 root login
		{"5.2.10 permit root fails", "5.2.10", models.SecurityInfo{SSHPermitRoot: true}, models.CISFail},
		{"5.2.10 no root passes", "5.2.10", models.SecurityInfo{}, models.CISPass},

		// 5.2.11 empty passwords
		{"5.2.11 empty pw fails", "5.2.11", models.SecurityInfo{SSHPermitEmptyPwd: true}, models.CISFail},
		{"5.2.11 no empty pw passes", "5.2.11", models.SecurityInfo{}, models.CISPass},

		// 5.2.12 PermitUserEnvironment
		{"5.2.12 user env fails", "5.2.12", models.SecurityInfo{SSHPermitUserEnv: true}, models.CISFail},
		{"5.2.12 default passes", "5.2.12", models.SecurityInfo{}, models.CISPass},

		// 5.2.13 idle timeout
		{"5.2.13 no timeout fails", "5.2.13", models.SecurityInfo{}, models.CISFail},
		{"5.2.13 timeout set passes", "5.2.13", models.SecurityInfo{SSHClientAliveInterval: 300}, models.CISPass},

		// 5.2.14 LoginGraceTime (default 120)
		{"5.2.14 default 120 fails", "5.2.14", models.SecurityInfo{}, models.CISFail},
		{"5.2.14 value 60 passes", "5.2.14", models.SecurityInfo{SSHLoginGraceTime: 60}, models.CISPass},

		// 5.2.15 banner
		{"5.2.15 no banner fails", "5.2.15", models.SecurityInfo{}, models.CISFail},
		{"5.2.15 'none' banner fails", "5.2.15", models.SecurityInfo{SSHBanner: "none"}, models.CISFail},
		{"5.2.15 banner set passes", "5.2.15", models.SecurityInfo{SSHBanner: "/etc/issue.net"}, models.CISPass},

		// 5.2.17 TCP forwarding
		{"5.2.17 on fails", "5.2.17", models.SecurityInfo{SSHTCPForwarding: true}, models.CISFail},
		{"5.2.17 off passes", "5.2.17", models.SecurityInfo{}, models.CISPass},

		// 5.2.18 MaxStartups
		{"5.2.18 unset fails", "5.2.18", models.SecurityInfo{}, models.CISFail},
		{"5.2.18 set passes", "5.2.18", models.SecurityInfo{SSHMaxStartups: "10:30:60"}, models.CISPass},
		// `sshd -T` always emits the compiled default 10:30:100 — it must FAIL
		// (full 100 > 60), not pass on mere presence.
		{"5.2.18 openssh default 10:30:100 fails", "5.2.18", models.SecurityInfo{SSHMaxStartups: "10:30:100"}, models.CISFail},
		{"5.2.18 high start fails", "5.2.18", models.SecurityInfo{SSHMaxStartups: "20:30:60"}, models.CISFail},
		{"5.2.18 bare compliant value passes", "5.2.18", models.SecurityInfo{SSHMaxStartups: "10"}, models.CISPass},

		// 5.2.19 MaxSessions (default 10)
		{"5.2.19 default 10 passes", "5.2.19", models.SecurityInfo{}, models.CISPass},
		{"5.2.19 value 20 fails", "5.2.19", models.SecurityInfo{SSHMaxSessions: 20}, models.CISFail},

		// 4.1.1 auditd installed
		{"4.1.1 not installed fails", "4.1.1", models.SecurityInfo{AuditRules: -1}, models.CISFail},
		{"4.1.1 installed passes", "4.1.1", models.SecurityInfo{AuditRules: 42}, models.CISPass},

		// 4.1.2 auditd rules
		{"4.1.2 unavailable skips", "4.1.2", models.SecurityInfo{AuditRules: -1}, models.CISSkipped},
		{"4.1.2 zero rules fails", "4.1.2", models.SecurityInfo{AuditRules: 0}, models.CISFail},
		{"4.1.2 rules loaded passes", "4.1.2", models.SecurityInfo{AuditRules: 5}, models.CISPass},

		// 5.2.16 SSH idle timeout (ClientAliveInterval)
		{"5.2.16 not set fails", "5.2.16", models.SecurityInfo{SSHClientAliveInterval: 0}, models.CISFail},
		{"5.2.16 900s passes", "5.2.16", models.SecurityInfo{SSHClientAliveInterval: 900}, models.CISPass},
		{"5.2.16 300s passes", "5.2.16", models.SecurityInfo{SSHClientAliveInterval: 300}, models.CISPass},
		{"5.2.16 1800s fails", "5.2.16", models.SecurityInfo{SSHClientAliveInterval: 1800}, models.CISFail},

		// 1.1.22 sticky bit on world-writable dirs
		{"1.1.22 no bad dirs passes", "1.1.22", models.SecurityInfo{}, models.CISPass},
		{"1.1.22 missing sticky fails", "1.1.22", models.SecurityInfo{WorldWritableDirs: []string{"/tmp"}}, models.CISFail},

		// 6.2.1 empty password fields
		{"6.2.1 shadow unreadable skips", "6.2.1", models.SecurityInfo{ShadowUnreadable: true}, models.CISSkipped},
		{"6.2.1 empty password account fails", "6.2.1", models.SecurityInfo{EmptyPasswordAccounts: []string{"baduser"}}, models.CISFail},
		{"6.2.1 no empty passwords passes", "6.2.1", models.SecurityInfo{}, models.CISPass},

		// 6.2.3 only root is UID 0
		{"6.2.3 extra uid0 fails", "6.2.3", models.SecurityInfo{UID0Users: []string{"toor"}}, models.CISFail},
		{"6.2.3 none passes", "6.2.3", models.SecurityInfo{}, models.CISPass},

		// 6.2.4 no empty passwords
		{"6.2.4 no empty passes", "6.2.4", models.SecurityInfo{}, models.CISPass},
		{"6.2.4 empty account fails", "6.2.4", models.SecurityInfo{EmptyPasswordAccounts: []string{"ghost"}}, models.CISFail},
		{"6.2.4 shadow unreadable skips", "6.2.4", models.SecurityInfo{ShadowUnreadable: true}, models.CISSkipped},

		// V-238213 ciphers (STIG)
		{"V-238213 unset fails", "V-238213", models.SecurityInfo{}, models.CISFail},
		{"V-238213 weak 3des fails", "V-238213", models.SecurityInfo{SSHCiphers: "aes256-ctr,3des-cbc"}, models.CISFail},
		{"V-238213 strong passes", "V-238213", models.SecurityInfo{SSHCiphers: "aes256-ctr,aes256-gcm@openssh.com"}, models.CISPass},

		// V-238214 MACs (STIG)
		{"V-238214 unset fails", "V-238214", models.SecurityInfo{}, models.CISFail},
		{"V-238214 weak md5 fails", "V-238214", models.SecurityInfo{SSHMACs: "hmac-md5"}, models.CISFail},
		{"V-238214 strong passes", "V-238214", models.SecurityInfo{SSHMACs: "hmac-sha2-512"}, models.CISPass},

		// V-238215 KexAlgorithms (STIG)
		{"V-238215 unset fails", "V-238215", models.SecurityInfo{}, models.CISFail},
		{"V-238215 weak group1 fails", "V-238215", models.SecurityInfo{SSHKexAlgorithms: "diffie-hellman-group1-sha1"}, models.CISFail},
		{"V-238215 strong passes", "V-238215", models.SecurityInfo{SSHKexAlgorithms: "ecdh-sha2-nistp256"}, models.CISPass},

		// V-238226 StrictModes (STIG)
		{"V-238226 disabled fails", "V-238226", models.SecurityInfo{}, models.CISFail},
		{"V-238226 enabled passes", "V-238226", models.SecurityInfo{SSHStrictModes: true}, models.CISPass},

		// 1.3.1 AIDE installed
		{"1.3.1 not installed fails", "1.3.1", models.SecurityInfo{AIDEInstalled: false}, models.CISFail},
		{"1.3.1 installed passes", "1.3.1", models.SecurityInfo{AIDEInstalled: true}, models.CISPass},

		// 1.3.2 AIDE check ran recently
		{"1.3.2 aide absent skips", "1.3.2", models.SecurityInfo{AIDEInstalled: false}, models.CISSkipped},
		{"1.3.2 no db fails", "1.3.2", models.SecurityInfo{AIDEInstalled: true, AIDEDBExists: false}, models.CISFail},
		{"1.3.2 never run fails", "1.3.2", models.SecurityInfo{AIDEInstalled: true, AIDEDBExists: true, AIDELastRunDays: -1}, models.CISFail},
		{"1.3.2 stale 8 days fails", "1.3.2", models.SecurityInfo{AIDEInstalled: true, AIDEDBExists: true, AIDELastRunDays: 8}, models.CISFail},
		{"1.3.2 within 7 days passes", "1.3.2", models.SecurityInfo{AIDEInstalled: true, AIDEDBExists: true, AIDELastRunDays: 3}, models.CISPass},
		{"1.3.2 exactly 7 days passes", "1.3.2", models.SecurityInfo{AIDEInstalled: true, AIDEDBExists: true, AIDELastRunDays: 7}, models.CISPass},

		// 5.4.2 stale password accounts
		{"5.4.2 shadow unreadable skips", "5.4.2", models.SecurityInfo{ShadowUnreadable: true}, models.CISSkipped},
		{"5.4.2 no stale passes", "5.4.2", models.SecurityInfo{}, models.CISPass},
		{"5.4.2 stale account fails", "5.4.2", models.SecurityInfo{StalePasswordAccounts: []string{"alice"}}, models.CISFail},

		// 6.1.14 SUID executables
		{"6.1.14 no unexpected SUIDs passes", "6.1.14", models.SecurityInfo{}, models.CISPass},
		{"6.1.14 unexpected SUID fails", "6.1.14", models.SecurityInfo{SUIDBinaries: []string{"/usr/bin/weird"}}, models.CISFail},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := ruleByID(tc.id)
			if rule.Check == nil {
				t.Fatalf("rule %s has no Check func (id not found)", tc.id)
			}
			got := rule.Check(tc.sec, ks)
			if got.Status != tc.want {
				t.Errorf("rule %s: got %s, want %s (finding=%q)", tc.id, got.Status, tc.want, got.Finding)
			}
		})
	}
}

// V-238221 is a fixed MANUAL check regardless of input.
func TestManualRule(t *testing.T) {
	got := ruleByID("V-238221").Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
	if got.Status != models.CISManual {
		t.Errorf("V-238221 should be MANUAL, got %s", got.Status)
	}
}

// ── Evaluate: framework filtering, level gating, STIG swap, tallying ──────────
// Swaps the global rule registry for a controlled fixture so the assertions are
// deterministic and independent of host filesystem state. Restored on cleanup.

func TestEvaluate(t *testing.T) {
	saved := CISRules
	t.Cleanup(func() { CISRules = saved })

	// Fixture checks stamp their own ID + status, mirroring how the real
	// pass()/failr() helpers populate the result from the rule.
	mk := func(id string, status models.CISStatus) func(models.SecurityInfo, models.KernelSecurityInfo) models.CISResult {
		return func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
			return models.CISResult{ID: id, Status: status}
		}
	}

	CISRules = []Rule{
		{ID: "C1", Framework: "CIS", Level: 1, Section: "S", Description: "cis-l1", Check: mk("C1", models.CISPass)},
		{ID: "C2", Framework: "CIS", Level: 2, Section: "S", Description: "cis-l2", Check: mk("C2", models.CISPass)},
		{ID: "B1", StigID: "V-1", StigDescription: "stig desc", Framework: "BOTH", Level: 1,
			Section: "S", Description: "both-l1", Check: mk("B1", models.CISFail)},
		{ID: "S1", Framework: "STIG", Level: 1, Section: "S", Description: "stig-l1", Check: mk("S1", models.CISManual)},
	}

	sec := models.SecurityInfo{}
	ks := models.KernelSecurityInfo{}

	t.Run("CIS L1 excludes STIG-only and L2", func(t *testing.T) {
		rep := Evaluate(sec, ks, 1, false, "apt")
		if rep.Framework != "CIS" {
			t.Errorf("Framework = %q, want CIS", rep.Framework)
		}
		ids := resultIDs(rep)
		// C1 (CIS L1) + B1 (BOTH L1). C2 is L2; S1 is STIG-only.
		if len(rep.Results) != 2 || !ids["C1"] || !ids["B1"] {
			t.Errorf("results = %v, want exactly {C1,B1}", ids)
		}
		if rep.Pass != 1 || rep.Fail != 1 {
			t.Errorf("counts pass=%d fail=%d, want 1/1", rep.Pass, rep.Fail)
		}
		assertTally(t, rep)
	})

	t.Run("CIS L2 includes the L2 rule", func(t *testing.T) {
		rep := Evaluate(sec, ks, 2, false, "apt")
		ids := resultIDs(rep)
		if !ids["C2"] {
			t.Errorf("L2 run should include C2; got %v", ids)
		}
		assertTally(t, rep)
	})

	t.Run("STIG mode swaps IDs and excludes CIS-only", func(t *testing.T) {
		rep := Evaluate(sec, ks, 1, true, "apt")
		if rep.Framework != "STIG" {
			t.Errorf("Framework = %q, want STIG", rep.Framework)
		}
		ids := resultIDs(rep)
		// B1 (swapped to V-1) + S1. CIS-only C1/C2 excluded.
		if ids["C1"] || ids["C2"] {
			t.Errorf("STIG run must exclude CIS-only rules; got %v", ids)
		}
		if !ids["V-1"] {
			t.Errorf("BOTH rule should surface under its StigID V-1; got %v", ids)
		}
		// Confirm the description was swapped to the STIG variant.
		for _, r := range rep.Results {
			if r.ID == "V-1" && r.Description != "stig desc" {
				t.Errorf("StigDescription not applied: %q", r.Description)
			}
		}
		assertTally(t, rep)
	})
}

// When a dedicated STIG rule shares an ID with a BOTH rule's StigID (the real
// V-238380 case: CIS 365-day vs STIG 60-day password age), STIG mode must emit
// that ID once — from the dedicated STIG rule — not twice with contradictory
// verdicts.
func TestEvaluate_StigSupersedesBoth(t *testing.T) {
	saved := CISRules
	t.Cleanup(func() { CISRules = saved })
	mk := func(id string, status models.CISStatus) func(models.SecurityInfo, models.KernelSecurityInfo) models.CISResult {
		return func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
			return models.CISResult{ID: id, Status: status}
		}
	}
	CISRules = []Rule{
		{ID: "5.x", StigID: "V-9", Framework: "BOTH", Level: 1, Section: "S",
			Description: "both", Check: mk("V-9", models.CISPass)}, // lenient CIS verdict
		{ID: "V-9", Framework: "STIG", Level: 1, Section: "S",
			Description: "stig", Check: mk("V-9", models.CISFail)}, // strict STIG verdict
	}

	rep := Evaluate(models.SecurityInfo{}, models.KernelSecurityInfo{}, 1, true, "apt")
	count, status := 0, models.CISStatus("")
	for _, r := range rep.Results {
		if r.ID == "V-9" {
			count++
			status = r.Status
		}
	}
	if count != 1 {
		t.Errorf("STIG mode emitted V-9 %d times, want exactly 1", count)
	}
	if status != models.CISFail {
		t.Errorf("surviving V-9 status = %v, want the dedicated STIG verdict (FAIL)", status)
	}
	assertTally(t, rep)
}

// TestEvaluate_NotApplicableTally exercises the CISNotApplicable branch of the
// per-status tally switch in Evaluate. No shipped rule currently returns N/A,
// but the status is part of the models.CISStatus contract (models/cis.go) and
// Evaluate must tally it correctly if/when a rule does — same fixture-swap
// pattern as TestEvaluate/TestEvaluate_StigSupersedesBoth.
func TestEvaluate_NotApplicableTally(t *testing.T) {
	saved := CISRules
	t.Cleanup(func() { CISRules = saved })

	CISRules = []Rule{
		{ID: "N1", Framework: "CIS", Level: 1, Section: "S", Description: "na-rule",
			Check: func(_ models.SecurityInfo, _ models.KernelSecurityInfo) models.CISResult {
				return models.CISResult{ID: "N1", Status: models.CISNotApplicable}
			}},
	}

	rep := Evaluate(models.SecurityInfo{}, models.KernelSecurityInfo{}, 1, false, "apt")
	if rep.NA != 1 {
		t.Errorf("NA = %d, want 1", rep.NA)
	}
	if len(rep.Results) != 1 || rep.Results[0].Status != models.CISNotApplicable {
		t.Errorf("results = %+v, want single N/A result", rep.Results)
	}
	assertTally(t, rep)
}

// ── 5.2.1 sshd_config file-mode check ───────────────────────────────────────
// Rule 5.2.1 uses the package-level sshdConfigPath var (mirrors loginDefsPath)
// so tests can point it at a fixture rather than the real host file.

func TestRule5_2_1_SshdConfigNotFound(t *testing.T) {
	// No t.Parallel(): mutates the shared package-level sshdConfigPath var,
	// same reason TestPasswordAgingRules_LoginDefsFixture omits it for loginDefsPath.
	saved := sshdConfigPath
	t.Cleanup(func() { sshdConfigPath = saved })
	sshdConfigPath = filepath.Join(t.TempDir(), "sshd_config_does_not_exist")

	rule := ruleByID(cisRuleSSH52)
	if rule.Check == nil {
		t.Fatal("rule 5.2.1 has no Check func")
	}
	got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
	if got.Status != models.CISSkipped {
		t.Errorf("missing sshd_config: want Skipped, got %s (%s)", got.Status, got.Finding)
	}
}

func TestRule5_2_1_SshdConfigCompliantMode(t *testing.T) {
	// No t.Parallel(): mutates the shared package-level sshdConfigPath var.
	dir := t.TempDir()
	p := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(p, []byte("# sshd_config fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	saved := sshdConfigPath
	t.Cleanup(func() { sshdConfigPath = saved })
	sshdConfigPath = p

	rule := ruleByID(cisRuleSSH52)
	if rule.Check == nil {
		t.Fatal("rule 5.2.1 has no Check func")
	}
	got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
	if got.Status != models.CISPass {
		t.Errorf("sshd_config mode 0600: want Pass, got %s (%s)", got.Status, got.Finding)
	}
}

func TestRule5_2_1_SshdConfigNonCompliantMode(t *testing.T) {
	// No t.Parallel(): mutates the shared package-level sshdConfigPath var.
	dir := t.TempDir()
	p := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(p, []byte("# sshd_config fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	saved := sshdConfigPath
	t.Cleanup(func() { sshdConfigPath = saved })
	sshdConfigPath = p

	rule := ruleByID(cisRuleSSH52)
	if rule.Check == nil {
		t.Fatal("rule 5.2.1 has no Check func")
	}
	got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
	if got.Status != models.CISFail {
		t.Errorf("sshd_config mode 0644: want Fail, got %s (%s)", got.Status, got.Finding)
	}
}

// ── 6.2.2 legacy NIS '+' entry check ─────────────────────────────────────────
// Rule 6.2.2 uses the package-level legacyNISPaths var so tests can supply
// fixture files rather than the real /etc/passwd, /etc/shadow, /etc/group.

func TestRule6_2_2_NISEntryDetected(t *testing.T) {
	// No t.Parallel(): mutates the shared package-level legacyNISPaths var.
	dir := t.TempDir()
	passwd := filepath.Join(dir, "passwd")
	if err := os.WriteFile(passwd, []byte("root:x:0:0:root:/root:/bin/bash\n+::0:0:::\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	saved := legacyNISPaths
	t.Cleanup(func() { legacyNISPaths = saved })
	legacyNISPaths = []string{passwd}

	rule := ruleByID("6.2.2")
	if rule.Check == nil {
		t.Fatal("rule 6.2.2 has no Check func")
	}
	got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
	if got.Status != models.CISFail {
		t.Errorf("'+' entry in passwd: want Fail, got %s (%s)", got.Status, got.Finding)
	}
	if !strings.Contains(got.Finding, "legacy NIS") {
		t.Errorf("finding = %q, want NIS mention", got.Finding)
	}
}

func TestRule6_2_2_UnreadableFileSkipped(t *testing.T) {
	// No t.Parallel(): mutates the shared package-level legacyNISPaths var.
	dir := t.TempDir()
	missing := filepath.Join(dir, "shadow_does_not_exist")
	clean := filepath.Join(dir, "passwd")
	if err := os.WriteFile(clean, []byte("root:x:0:0:root:/root:/bin/bash\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	saved := legacyNISPaths
	t.Cleanup(func() { legacyNISPaths = saved })
	legacyNISPaths = []string{missing, clean}

	rule := ruleByID("6.2.2")
	if rule.Check == nil {
		t.Fatal("rule 6.2.2 has no Check func")
	}
	got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
	if got.Status != models.CISPass {
		t.Errorf("unreadable file + clean file: want Pass, got %s (%s)", got.Status, got.Finding)
	}
}

func TestRule6_2_2_CleanFilesPass(t *testing.T) {
	// No t.Parallel(): mutates the shared package-level legacyNISPaths var.
	dir := t.TempDir()
	passwd := filepath.Join(dir, "passwd")
	group := filepath.Join(dir, "group")
	if err := os.WriteFile(passwd, []byte("root:x:0:0:root:/root:/bin/bash\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(group, []byte("root:x:0:\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	saved := legacyNISPaths
	t.Cleanup(func() { legacyNISPaths = saved })
	legacyNISPaths = []string{passwd, group}

	rule := ruleByID("6.2.2")
	if rule.Check == nil {
		t.Fatal("rule 6.2.2 has no Check func")
	}
	got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
	if got.Status != models.CISPass {
		t.Errorf("clean files: want Pass, got %s (%s)", got.Status, got.Finding)
	}
}

func resultIDs(rep models.CISReport) map[string]bool {
	m := make(map[string]bool, len(rep.Results))
	for _, r := range rep.Results {
		m[r.ID] = true
	}
	return m
}

// assertTally checks the per-status counters sum to the number of results.
func assertTally(t *testing.T, rep models.CISReport) {
	t.Helper()
	sum := rep.Pass + rep.Fail + rep.Manual + rep.NA + rep.Skipped
	if sum != len(rep.Results) {
		t.Errorf("counter sum %d != len(Results) %d", sum, len(rep.Results))
	}
}

// ── smoke: the real registry evaluates without panicking on this host ────────

func TestEvaluateRealRegistry(t *testing.T) {
	rep := Evaluate(models.SecurityInfo{AuditRules: -1}, models.KernelSecurityInfo{}, 2, false, "apt")
	if len(rep.Results) == 0 {
		t.Fatal("real registry produced no results")
	}
	assertTally(t, rep)
}

// The auditd remediation hints (4.1.1 install, 4.1.2 sample-rules path) are
// Debian-shaped by default, but `dsd cis` runs cross-distro. On a dnf host the
// apt command and the /usr/share/doc/auditd Debian path don't exist — they must
// be rewritten to the dnf command and the RHEL /usr/share/audit/sample-rules path.
func TestEvaluate_AuditRemediationAdaptsToPackageManager(t *testing.T) {
	// AuditRules == -1 → 4.1.1 fails (install); AuditRules == 0 → 4.1.2 fails (rules).
	find := func(rep models.CISReport, id string) (models.CISResult, bool) {
		for _, r := range rep.Results {
			if r.ID == id {
				return r, true
			}
		}
		return models.CISResult{}, false
	}

	// dnf host: both auditd remediations must be RHEL-shaped.
	repInstall := Evaluate(models.SecurityInfo{AuditRules: -1}, models.KernelSecurityInfo{}, 1, false, "dnf")
	if r, ok := find(repInstall, "4.1.1"); !ok {
		t.Fatal("4.1.1 not present")
	} else if !strings.Contains(r.Remediation, "dnf install audit") {
		t.Errorf("4.1.1 remediation = %q, want dnf install", r.Remediation)
	}

	repRules := Evaluate(models.SecurityInfo{AuditRules: 0}, models.KernelSecurityInfo{}, 1, false, "dnf")
	if r, ok := find(repRules, "4.1.2"); !ok {
		t.Fatal("4.1.2 not present")
	} else {
		if !strings.Contains(r.Remediation, "/usr/share/audit/sample-rules/") {
			t.Errorf("4.1.2 remediation = %q, want RHEL sample-rules path", r.Remediation)
		}
		if strings.Contains(r.Remediation, "/usr/share/doc/auditd") {
			t.Errorf("4.1.2 remediation still has the Debian path: %q", r.Remediation)
		}
	}

	// apt host keeps the Debian forms.
	repApt := Evaluate(models.SecurityInfo{AuditRules: 0}, models.KernelSecurityInfo{}, 1, false, "apt")
	if r, ok := find(repApt, "4.1.2"); ok && !strings.Contains(r.Remediation, "/usr/share/doc/auditd") {
		t.Errorf("apt 4.1.2 remediation = %q, want Debian path", r.Remediation)
	}
}

// TestEvaluate_AuditUnreadableNotFailed is a regression guard: `auditctl -l` is
// root-only, so a non-root `dsd cis` run gets the SAME AuditRules==-1 sentinel
// whether auditd is genuinely absent OR installed-and-running-but-unreadable.
// Rule 4.1.1 ("auditd installed and running") must not FAIL a fully compliant
// host purely because dsd ran non-root — it must Skip, distinguishable from the
// real "not installed" FAIL.
func TestEvaluate_AuditUnreadableNotFailed(t *testing.T) {
	find := func(rep models.CISReport, id string) (models.CISResult, bool) {
		for _, r := range rep.Results {
			if r.ID == id {
				return r, true
			}
		}
		return models.CISResult{}, false
	}

	unreadable := Evaluate(models.SecurityInfo{AuditRules: -1, AuditRulesUnreadable: true}, models.KernelSecurityInfo{}, 1, false, "apt")
	r, ok := find(unreadable, "4.1.1")
	if !ok {
		t.Fatal("4.1.1 not present")
	}
	if r.Status != models.CISSkipped {
		t.Errorf("4.1.1 with AuditRulesUnreadable=true: status = %v, want Skipped", r.Status)
	}

	// Genuinely not installed (AuditRulesUnreadable=false) must still FAIL.
	notInstalled := Evaluate(models.SecurityInfo{AuditRules: -1, AuditRulesUnreadable: false}, models.KernelSecurityInfo{}, 1, false, "apt")
	r2, ok := find(notInstalled, "4.1.1")
	if !ok {
		t.Fatal("4.1.1 not present")
	}
	if r2.Status != models.CISFail {
		t.Errorf("4.1.1 with AuditRulesUnreadable=false: status = %v, want Fail", r2.Status)
	}
}

// ── 2.1.1 Time Sync Daemon Installed ─────────────────────────────────────────

func TestRule2_1_1_NoDaemonInstalled(t *testing.T) {
	// No t.Parallel(): mutates chronyCfgPaths, ntpCfgPath, timesyncdCfgPath.
	dir := t.TempDir()
	savedChrony := chronyCfgPaths
	savedNtp := ntpCfgPath
	savedTimesyncd := timesyncdCfgPath
	t.Cleanup(func() {
		chronyCfgPaths = savedChrony
		ntpCfgPath = savedNtp
		timesyncdCfgPath = savedTimesyncd
	})
	chronyCfgPaths = []string{filepath.Join(dir, "chrony.conf")}
	ntpCfgPath = filepath.Join(dir, "ntp.conf")
	timesyncdCfgPath = filepath.Join(dir, "timesyncd.conf")

	rule := ruleByID("2.1.1")
	got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
	if got.Status != models.CISFail {
		t.Errorf("no daemon config: want Fail, got %s (%s)", got.Status, got.Finding)
	}
}

func TestRule2_1_1_ChronyInstalled(t *testing.T) {
	// No t.Parallel(): mutates chronyCfgPaths.
	dir := t.TempDir()
	p := filepath.Join(dir, "chrony.conf")
	if err := os.WriteFile(p, []byte("# chrony fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	savedChrony := chronyCfgPaths
	savedNtp := ntpCfgPath
	savedTimesyncd := timesyncdCfgPath
	t.Cleanup(func() {
		chronyCfgPaths = savedChrony
		ntpCfgPath = savedNtp
		timesyncdCfgPath = savedTimesyncd
	})
	chronyCfgPaths = []string{p}
	ntpCfgPath = filepath.Join(dir, "ntp.conf")             // absent
	timesyncdCfgPath = filepath.Join(dir, "timesyncd.conf") // absent

	rule := ruleByID("2.1.1")
	got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
	if got.Status != models.CISPass {
		t.Errorf("chrony.conf present: want Pass, got %s (%s)", got.Status, got.Finding)
	}
}

func TestRule2_1_1_NtpInstalled(t *testing.T) {
	// No t.Parallel(): mutates ntpCfgPath, chronyCfgPaths (to force ntp path).
	dir := t.TempDir()
	p := filepath.Join(dir, "ntp.conf")
	if err := os.WriteFile(p, []byte("server 0.pool.ntp.org\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	savedChrony := chronyCfgPaths
	savedNtp := ntpCfgPath
	savedTimesyncd := timesyncdCfgPath
	t.Cleanup(func() {
		chronyCfgPaths = savedChrony
		ntpCfgPath = savedNtp
		timesyncdCfgPath = savedTimesyncd
	})
	chronyCfgPaths = []string{filepath.Join(dir, "chrony.conf")} // absent
	ntpCfgPath = p
	timesyncdCfgPath = filepath.Join(dir, "timesyncd.conf") // absent

	rule := ruleByID("2.1.1")
	got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
	if got.Status != models.CISPass {
		t.Errorf("ntp.conf present: want Pass, got %s (%s)", got.Status, got.Finding)
	}
}

func TestRule2_1_1_TimesyncdInstalled(t *testing.T) {
	// No t.Parallel(): mutates timesyncdCfgPath, chronyCfgPaths, ntpCfgPath.
	dir := t.TempDir()
	p := filepath.Join(dir, "timesyncd.conf")
	if err := os.WriteFile(p, []byte("[Time]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	savedChrony := chronyCfgPaths
	savedNtp := ntpCfgPath
	savedTimesyncd := timesyncdCfgPath
	t.Cleanup(func() {
		chronyCfgPaths = savedChrony
		ntpCfgPath = savedNtp
		timesyncdCfgPath = savedTimesyncd
	})
	chronyCfgPaths = []string{filepath.Join(dir, "chrony.conf")} // absent
	ntpCfgPath = filepath.Join(dir, "ntp.conf")                  // absent
	timesyncdCfgPath = p

	rule := ruleByID("2.1.1")
	got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
	if got.Status != models.CISPass {
		t.Errorf("timesyncd.conf present: want Pass, got %s (%s)", got.Status, got.Finding)
	}
}

// ── 2.1.2 Time Sync Daemon Configured ────────────────────────────────────────

func TestRule2_1_2_NoDaemon(t *testing.T) {
	// No t.Parallel(): mutates package-level path vars.
	dir := t.TempDir()
	savedChrony := chronyCfgPaths
	savedNtp := ntpCfgPath
	savedTimesyncd := timesyncdCfgPath
	t.Cleanup(func() {
		chronyCfgPaths = savedChrony
		ntpCfgPath = savedNtp
		timesyncdCfgPath = savedTimesyncd
	})
	chronyCfgPaths = []string{filepath.Join(dir, "chrony.conf")}
	ntpCfgPath = filepath.Join(dir, "ntp.conf")
	timesyncdCfgPath = filepath.Join(dir, "timesyncd.conf")

	rule := ruleByID("2.1.2")
	got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
	if got.Status != models.CISSkipped {
		t.Errorf("no config: want Skipped, got %s (%s)", got.Status, got.Finding)
	}
}

func TestRule2_1_2_ChronyWithPool(t *testing.T) {
	// No t.Parallel(): mutates chronyCfgPaths.
	dir := t.TempDir()
	p := filepath.Join(dir, "chrony.conf")
	if err := os.WriteFile(p, []byte("pool pool.ntp.org iburst\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	savedChrony := chronyCfgPaths
	savedNtp := ntpCfgPath
	savedTimesyncd := timesyncdCfgPath
	t.Cleanup(func() {
		chronyCfgPaths = savedChrony
		ntpCfgPath = savedNtp
		timesyncdCfgPath = savedTimesyncd
	})
	chronyCfgPaths = []string{p}
	ntpCfgPath = filepath.Join(dir, "ntp.conf")             // absent
	timesyncdCfgPath = filepath.Join(dir, "timesyncd.conf") // absent

	rule := ruleByID("2.1.2")
	got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
	if got.Status != models.CISPass {
		t.Errorf("chrony with pool: want Pass, got %s (%s)", got.Status, got.Finding)
	}
}

func TestRule2_1_2_ChronyWithServer(t *testing.T) {
	// No t.Parallel(): mutates chronyCfgPaths.
	dir := t.TempDir()
	p := filepath.Join(dir, "chrony.conf")
	if err := os.WriteFile(p, []byte("server 0.debian.pool.ntp.org iburst\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	savedChrony := chronyCfgPaths
	savedNtp := ntpCfgPath
	savedTimesyncd := timesyncdCfgPath
	t.Cleanup(func() {
		chronyCfgPaths = savedChrony
		ntpCfgPath = savedNtp
		timesyncdCfgPath = savedTimesyncd
	})
	chronyCfgPaths = []string{p}
	ntpCfgPath = filepath.Join(dir, "ntp.conf")             // absent
	timesyncdCfgPath = filepath.Join(dir, "timesyncd.conf") // absent

	rule := ruleByID("2.1.2")
	got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
	if got.Status != models.CISPass {
		t.Errorf("chrony with server: want Pass, got %s (%s)", got.Status, got.Finding)
	}
}

func TestRule2_1_2_ChronyNoServers(t *testing.T) {
	// No t.Parallel(): mutates chronyCfgPaths.
	dir := t.TempDir()
	p := filepath.Join(dir, "chrony.conf")
	if err := os.WriteFile(p, []byte("# chrony.conf — no server or pool set\nmaxdistance 1.5\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	savedChrony := chronyCfgPaths
	savedNtp := ntpCfgPath
	savedTimesyncd := timesyncdCfgPath
	t.Cleanup(func() {
		chronyCfgPaths = savedChrony
		ntpCfgPath = savedNtp
		timesyncdCfgPath = savedTimesyncd
	})
	chronyCfgPaths = []string{p}
	ntpCfgPath = filepath.Join(dir, "ntp.conf")             // absent
	timesyncdCfgPath = filepath.Join(dir, "timesyncd.conf") // absent

	rule := ruleByID("2.1.2")
	got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
	if got.Status != models.CISFail {
		t.Errorf("chrony no server/pool: want Fail, got %s (%s)", got.Status, got.Finding)
	}
}

func TestRule2_1_2_NtpWithServer(t *testing.T) {
	// No t.Parallel(): mutates ntpCfgPath and chronyCfgPaths (to skip chrony).
	dir := t.TempDir()
	p := filepath.Join(dir, "ntp.conf")
	if err := os.WriteFile(p, []byte("server 0.pool.ntp.org iburst\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	savedChrony := chronyCfgPaths
	savedNtp := ntpCfgPath
	savedTimesyncd := timesyncdCfgPath
	t.Cleanup(func() {
		chronyCfgPaths = savedChrony
		ntpCfgPath = savedNtp
		timesyncdCfgPath = savedTimesyncd
	})
	chronyCfgPaths = []string{filepath.Join(dir, "chrony.conf")} // absent
	ntpCfgPath = p
	timesyncdCfgPath = filepath.Join(dir, "timesyncd.conf") // absent

	rule := ruleByID("2.1.2")
	got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
	if got.Status != models.CISPass {
		t.Errorf("ntp with server: want Pass, got %s (%s)", got.Status, got.Finding)
	}
}

func TestRule2_1_2_TimesyncdPresent(t *testing.T) {
	// No t.Parallel(): mutates package-level path vars.
	dir := t.TempDir()
	p := filepath.Join(dir, "timesyncd.conf")
	if err := os.WriteFile(p, []byte("[Time]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	savedChrony := chronyCfgPaths
	savedNtp := ntpCfgPath
	savedTimesyncd := timesyncdCfgPath
	t.Cleanup(func() {
		chronyCfgPaths = savedChrony
		ntpCfgPath = savedNtp
		timesyncdCfgPath = savedTimesyncd
	})
	chronyCfgPaths = []string{filepath.Join(dir, "chrony.conf")} // absent
	ntpCfgPath = filepath.Join(dir, "ntp.conf")                  // absent
	timesyncdCfgPath = p

	rule := ruleByID("2.1.2")
	got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
	if got.Status != models.CISPass {
		t.Errorf("timesyncd present: want Pass, got %s (%s)", got.Status, got.Finding)
	}
}

// ── 5.3.4 Sudo Requires Password ─────────────────────────────────────────────

func TestRule5_3_4_NoNopasswd(t *testing.T) {
	t.Parallel()
	rule := ruleByID("5.3.4")
	got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
	if got.Status != models.CISPass {
		t.Errorf("empty SudoNopasswd: want Pass, got %s (%s)", got.Status, got.Finding)
	}
}

func TestRule5_3_4_SudoersUnreadable(t *testing.T) {
	t.Parallel()
	rule := ruleByID("5.3.4")
	got := rule.Check(models.SecurityInfo{SudoersUnreadable: true}, models.KernelSecurityInfo{})
	if got.Status != models.CISSkipped {
		t.Errorf("SudoersUnreadable=true: want Skipped, got %s (%s)", got.Status, got.Finding)
	}
}

func TestRule5_3_4_NopasswdEntries(t *testing.T) {
	t.Parallel()
	rule := ruleByID("5.3.4")
	sec := models.SecurityInfo{SudoNopasswd: []string{"alice", "bob"}}
	got := rule.Check(sec, models.KernelSecurityInfo{})
	if got.Status != models.CISFail {
		t.Errorf("SudoNopasswd=[alice,bob]: want Fail, got %s (%s)", got.Status, got.Finding)
	}
	if !strings.Contains(got.Finding, "alice") || !strings.Contains(got.Finding, "bob") {
		t.Errorf("finding should list users, got %q", got.Finding)
	}
}

// ── 3.3.1 / 3.3.2 MAC rules ─────────────────────────────────────────────────

// TestRule_331_MACInstalled covers the "no MAC present → FAIL" and "any MAC
// present → PASS" cases for rule 3.3.1. It also verifies RHEL and AppArmor
// hosts both pass.
func TestRule_331_MACInstalled(t *testing.T) {
	t.Parallel()
	find := func(rep models.CISReport) models.CISResult {
		t.Helper()
		for _, r := range rep.Results {
			if r.ID == "3.3.1" {
				return r
			}
		}
		t.Fatal("3.3.1 not present in report")
		return models.CISResult{}
	}
	cases := []struct {
		name   string
		ks     models.KernelSecurityInfo
		wantSt models.CISStatus
	}{
		{"no MAC → FAIL", models.KernelSecurityInfo{}, models.CISFail},
		{"AppArmor present → PASS", models.KernelSecurityInfo{AppArmorPresent: true}, models.CISPass},
		{"SELinux present → PASS (RHEL path)", models.KernelSecurityInfo{SELinuxPresent: true}, models.CISPass},
		{"both present → PASS", models.KernelSecurityInfo{AppArmorPresent: true, SELinuxPresent: true}, models.CISPass},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := find(Evaluate(models.SecurityInfo{}, tc.ks, 1, false, "apt"))
			if r.Status != tc.wantSt {
				t.Errorf("3.3.1 %s: status = %s, want %s (finding: %s)", tc.name, r.Status, tc.wantSt, r.Finding)
			}
		})
	}
}

// TestRule_332_MACEnforcing covers all SELinux/AppArmor mode transitions and
// the "no MAC" skip path for rule 3.3.2.
func TestRule_332_MACEnforcing(t *testing.T) {
	t.Parallel()
	find := func(rep models.CISReport) models.CISResult {
		t.Helper()
		for _, r := range rep.Results {
			if r.ID == "3.3.2" {
				return r
			}
		}
		t.Fatal("3.3.2 not present in report")
		return models.CISResult{}
	}
	cases := []struct {
		name   string
		ks     models.KernelSecurityInfo
		wantSt models.CISStatus
	}{
		// SELinux path (RHEL/Rocky — SELinux present wins over AppArmor check)
		{"SELinux enforcing → PASS",
			models.KernelSecurityInfo{SELinuxPresent: true, SELinuxMode: "enforcing"}, models.CISPass},
		{"SELinux permissive → FAIL",
			models.KernelSecurityInfo{SELinuxPresent: true, SELinuxMode: "permissive"}, models.CISFail},
		{"SELinux disabled → FAIL",
			models.KernelSecurityInfo{SELinuxPresent: true, SELinuxMode: "disabled"}, models.CISFail},
		// AppArmor path (Ubuntu/Debian — AppArmor present, no SELinux)
		{"AppArmor enforce → PASS",
			models.KernelSecurityInfo{AppArmorPresent: true, AppArmorMode: "enforce"}, models.CISPass},
		{"AppArmor complain → FAIL",
			models.KernelSecurityInfo{AppArmorPresent: true, AppArmorMode: "complain"}, models.CISFail},
		{"AppArmor unknown → SKIP (root required)",
			models.KernelSecurityInfo{AppArmorPresent: true, AppArmorMode: "unknown"}, models.CISSkipped},
		{"AppArmor disabled → FAIL",
			models.KernelSecurityInfo{AppArmorPresent: true, AppArmorMode: "disabled"}, models.CISFail},
		// No MAC framework at all
		{"no MAC → SKIP (see 3.3.1)",
			models.KernelSecurityInfo{}, models.CISSkipped},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := find(Evaluate(models.SecurityInfo{}, tc.ks, 1, false, "apt"))
			if r.Status != tc.wantSt {
				t.Errorf("3.3.2 %s: status = %s, want %s (finding: %s)", tc.name, r.Status, tc.wantSt, r.Finding)
			}
		})
	}
}

// ── 3.5.1 firewall rule ──────────────────────────────────────────────────────

// TestRule_351_FirewallActive covers the active/inactive/unreadable paths for
// rule 3.5.1. The false-OK guard here is: FirewallUnreadable=true must never
// produce a PASS (it would certify an unread firewall state as safe).
func TestRule_351_FirewallActive(t *testing.T) {
	t.Parallel()
	find := func(rep models.CISReport) models.CISResult {
		t.Helper()
		for _, r := range rep.Results {
			if r.ID == "3.5.1" {
				return r
			}
		}
		t.Fatal("3.5.1 not present in report")
		return models.CISResult{}
	}
	cases := []struct {
		name   string
		sec    models.SecurityInfo
		wantSt models.CISStatus
	}{
		{"active firewall → PASS",
			models.SecurityInfo{FirewallActive: true, FirewallToolingPresent: true}, models.CISPass},
		{"tooling present but inactive → FAIL",
			models.SecurityInfo{FirewallActive: false, FirewallToolingPresent: true}, models.CISFail},
		{"no tooling → FAIL",
			models.SecurityInfo{FirewallActive: false, FirewallToolingPresent: false}, models.CISFail},
		{"unreadable must SKIP — never PASS",
			models.SecurityInfo{FirewallUnreadable: true}, models.CISSkipped},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := find(Evaluate(tc.sec, models.KernelSecurityInfo{}, 1, false, "apt"))
			if r.Status != tc.wantSt {
				t.Errorf("3.5.1 %s: status = %s, want %s (finding: %s)", tc.name, r.Status, tc.wantSt, r.Finding)
			}
			if tc.sec.FirewallUnreadable && r.Status == models.CISPass {
				t.Error("3.5.1 must not PASS when FirewallUnreadable=true (false-OK guard)")
			}
		})
	}
}

// ── 5.3.1 sudo installed ──────────────────────────────────────────────────────

func TestRule5_3_1_SudoFound(t *testing.T) {
	// No t.Parallel(): modifies package-level sudoBinPaths.
	dir := t.TempDir()
	saved := sudoBinPaths
	t.Cleanup(func() { sudoBinPaths = saved })
	p := filepath.Join(dir, "sudo")
	if err := os.WriteFile(p, []byte(""), 0o755); err != nil {
		t.Fatal(err)
	}
	sudoBinPaths = []string{p}
	rule := ruleByID("5.3.1")
	got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
	if got.Status != models.CISPass {
		t.Errorf("sudo found: want Pass, got %s (%s)", got.Status, got.Finding)
	}
}

func TestRule5_3_1_SudoNotFound(t *testing.T) {
	// No t.Parallel(): modifies package-level sudoBinPaths.
	saved := sudoBinPaths
	t.Cleanup(func() { sudoBinPaths = saved })
	sudoBinPaths = []string{"/nonexistent/path/sudo"}
	rule := ruleByID("5.3.1")
	got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
	if got.Status != models.CISFail {
		t.Errorf("sudo absent: want Fail, got %s (%s)", got.Status, got.Finding)
	}
}

func TestRule5_3_1_RemediationAdaptsToPackageManager(t *testing.T) {
	saved := sudoBinPaths
	t.Cleanup(func() { sudoBinPaths = saved })
	sudoBinPaths = []string{"/nonexistent/path/sudo"}
	cases := []struct {
		pkgMgr  string
		wantCmd string
	}{
		{"apt", "apt install sudo"},
		{"dnf", "dnf install sudo"},
		{"zypper", "zypper install sudo"},
		{"pacman", "pacman -S sudo"},
	}
	for _, tc := range cases {
		t.Run(tc.pkgMgr, func(t *testing.T) {
			t.Parallel()
			report := Evaluate(models.SecurityInfo{}, models.KernelSecurityInfo{}, 1, false, tc.pkgMgr)
			var r models.CISResult
			for _, res := range report.Results {
				if res.ID == "5.3.1" {
					r = res
					break
				}
			}
			if r.Status != models.CISFail {
				t.Fatalf("5.3.1 should fail when sudo absent, got %s", r.Status)
			}
			if !strings.Contains(r.Remediation, tc.wantCmd) {
				t.Errorf("remediation = %q, want %q", r.Remediation, tc.wantCmd)
			}
		})
	}
}

// ── 5.4.3 ENCRYPT_METHOD ─────────────────────────────────────────────────────

func TestRule5_4_3_EncryptMethod(t *testing.T) {
	// No t.Parallel(): modifies package-level loginDefsPath.
	saved := loginDefsPath
	t.Cleanup(func() { loginDefsPath = saved })
	cases := []struct {
		name    string
		content string
		want    models.CISStatus
	}{
		{"SHA512 passes", "ENCRYPT_METHOD SHA512\n", models.CISPass},
		{"yescrypt passes", "ENCRYPT_METHOD yescrypt\n", models.CISPass},
		{"YESCRYPT upper passes", "ENCRYPT_METHOD YESCRYPT\n", models.CISPass},
		{"MD5 fails", "ENCRYPT_METHOD MD5\n", models.CISFail},
		{"missing field fails", "PASS_MAX_DAYS 90\n", models.CISFail},
		{"missing file skips", "", models.CISSkipped},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.content == "" {
				loginDefsPath = filepath.Join(t.TempDir(), "no-login.defs")
			} else {
				p := filepath.Join(t.TempDir(), "login.defs")
				if err := os.WriteFile(p, []byte(tc.content), 0o644); err != nil {
					t.Fatal(err)
				}
				loginDefsPath = p
			}
			rule := ruleByID("5.4.3")
			got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
			if got.Status != tc.want {
				t.Errorf("got %s, want %s (finding=%q)", got.Status, tc.want, got.Finding)
			}
		})
	}
}

// ── 5.4.4 PASS_MIN_DAYS ───────────────────────────────────────────────────────

func TestRule5_4_4_PassMinDays(t *testing.T) {
	// No t.Parallel(): modifies package-level loginDefsPath.
	saved := loginDefsPath
	t.Cleanup(func() { loginDefsPath = saved })
	cases := []struct {
		name    string
		content string
		want    models.CISStatus
	}{
		{"min days 1 passes", "PASS_MIN_DAYS 1\n", models.CISPass},
		{"min days 7 passes", "PASS_MIN_DAYS 7\n", models.CISPass},
		{"min days 0 fails", "PASS_MIN_DAYS 0\n", models.CISFail},
		{"missing field fails", "PASS_MAX_DAYS 90\n", models.CISFail},
		{"missing file skips", "", models.CISSkipped},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.content == "" {
				loginDefsPath = filepath.Join(t.TempDir(), "no-login.defs")
			} else {
				p := filepath.Join(t.TempDir(), "login.defs")
				if err := os.WriteFile(p, []byte(tc.content), 0o644); err != nil {
					t.Fatal(err)
				}
				loginDefsPath = p
			}
			rule := ruleByID("5.4.4")
			got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
			if got.Status != tc.want {
				t.Errorf("got %s, want %s (finding=%q)", got.Status, tc.want, got.Finding)
			}
		})
	}
}

// ── 5.4.5 useradd default GROUP ───────────────────────────────────────────────

func TestRule5_4_5_UseraddDefaultGroup(t *testing.T) {
	// No t.Parallel(): modifies package-level useraddDefaultPath.
	saved := useraddDefaultPath
	t.Cleanup(func() { useraddDefaultPath = saved })
	cases := []struct {
		name    string
		content string
		want    models.CISStatus
	}{
		{"GROUP=0 passes", "GROUP=0\n", models.CISPass},
		{"GROUP=root passes", "GROUP=root\n", models.CISPass},
		{"GROUP=100 fails", "GROUP=100\n", models.CISFail},
		{"no GROUP line fails", "SHELL=/bin/bash\n", models.CISFail},
		{"missing file skips", "", models.CISSkipped},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.content == "" {
				useraddDefaultPath = filepath.Join(t.TempDir(), "no-useradd")
			} else {
				p := filepath.Join(t.TempDir(), "useradd")
				if err := os.WriteFile(p, []byte(tc.content), 0o644); err != nil {
					t.Fatal(err)
				}
				useraddDefaultPath = p
			}
			rule := ruleByID("5.4.5")
			got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
			if got.Status != tc.want {
				t.Errorf("got %s, want %s (finding=%q)", got.Status, tc.want, got.Finding)
			}
		})
	}
}

// ── 6.1.4–6.1.8 backup file permissions ──────────────────────────────────────

func TestRule6_1_4_to_6_1_8_RegistryPresence(t *testing.T) {
	t.Parallel()
	ids := []string{"6.1.4", "6.1.5", "6.1.6", "6.1.7", "6.1.8"}
	for _, id := range ids {
		t.Run(id, func(t *testing.T) {
			t.Parallel()
			rule := ruleByID(id)
			if rule.Check == nil {
				t.Fatalf("rule %s not found in registry", id)
			}
			if rule.Description == "" {
				t.Errorf("rule %s has no description", id)
			}
		})
	}
}

func TestCheckFilePerm6_1_Variants(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cases := []struct {
		name    string
		mode    os.FileMode
		maxMode os.FileMode
		wantSt  models.CISStatus
	}{
		{"0600 vs max 0600 passes", 0o600, 0o600, models.CISPass},
		{"0644 vs max 0600 fails", 0o644, 0o600, models.CISFail},
		{"0640 vs max 0640 passes", 0o640, 0o640, models.CISPass},
		{"0644 vs max 0640 fails", 0o644, 0o640, models.CISFail},
		{"0644 vs max 0644 passes", 0o644, 0o644, models.CISPass},
		{"0664 vs max 0644 fails", 0o664, 0o644, models.CISFail},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "_"))
			if err := os.WriteFile(p, []byte(""), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(p, tc.mode); err != nil {
				t.Fatal(err)
			}
			r := ruleByID("6.1.4")
			got := checkFilePerm(r, p, tc.maxMode, "fix")
			if got.Status != tc.wantSt {
				t.Errorf("mode %04o maxMode %04o: got %s, want %s", tc.mode, tc.maxMode, got.Status, tc.wantSt)
			}
		})
	}
}

// ── 1.7 Warning Banners ──────────────────────────────────────────────────────

// TestCheckBannerContent tests the checkBannerContent helper directly.
// No t.Parallel(): modifies package-level motdPath.
func TestCheckBannerContent(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name    string
		content string
		wantSt  models.CISStatus
		wantHas string
	}{
		{"non-empty banner passes", "Authorized use only.", models.CISPass, ""},
		{"empty file fails", "", models.CISFail, "empty"},
		{`\s fingerprinting fails`, `Welcome to \s`, models.CISFail, `\s`},
		{`\m fingerprinting fails`, `Machine: \m`, models.CISFail, `\m`},
		{`\r fingerprinting fails`, `Release: \r`, models.CISFail, `\r`},
		{`\v fingerprinting fails`, `Version: \v`, models.CISFail, `\v`},
		{`\u fingerprinting fails`, `Users: \u`, models.CISFail, `\u`},
	}
	r := ruleByID("1.7.1")
	for _, tc := range cases {
		p := filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "_"))
		if err := os.WriteFile(p, []byte(tc.content), 0o644); err != nil {
			t.Fatal(err)
		}
		got := checkBannerContent(r, p, "fix")
		if got.Status != tc.wantSt {
			t.Errorf("%s: got %s, want %s", tc.name, got.Status, tc.wantSt)
		}
		if tc.wantHas != "" && !strings.Contains(got.Finding, tc.wantHas) {
			t.Errorf("%s: finding %q missing %q", tc.name, got.Finding, tc.wantHas)
		}
	}
}

// TestCheckBannerContent_MissingFile verifies that a missing file returns FAIL.
// No t.Parallel(): uses checkBannerContent helper directly (no package var mutation).
func TestCheckBannerContent_MissingFile(t *testing.T) {
	r := ruleByID("1.7.1")
	got := checkBannerContent(r, "/nonexistent/banner/file", "fix")
	if got.Status != models.CISFail {
		t.Errorf("got %s, want FAIL for missing file", got.Status)
	}
	if !strings.Contains(got.Finding, "not found") {
		t.Errorf("finding %q missing 'not found'", got.Finding)
	}
}

// TestRule1_7_4_5_6_BannerPermissions verifies rules 1.7.4-1.7.6 via checkFilePerm.
// No t.Parallel(): modifies package-level motdPath, issuePath, issueNetPath.
func TestRule1_7_4_5_6_BannerPermissions(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		id      string
		mode    os.FileMode
		wantSt  models.CISStatus
	}{
		{"1.7.4", 0o644, models.CISPass},
		{"1.7.4", 0o600, models.CISPass},
		{"1.7.4", 0o664, models.CISFail},
		{"1.7.5", 0o644, models.CISPass},
		{"1.7.5", 0o777, models.CISFail},
		{"1.7.6", 0o644, models.CISPass},
		{"1.7.6", 0o646, models.CISFail},
	}
	for _, tc := range cases {
		p := filepath.Join(dir, tc.id+"_"+tc.mode.String())
		if err := os.WriteFile(p, []byte(""), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, tc.mode); err != nil {
			t.Fatal(err)
		}
		r := ruleByID(tc.id)
		got := checkFilePerm(r, p, 0o644, "fix")
		if got.Status != tc.wantSt {
			t.Errorf("rule %s mode %04o: got %s, want %s", tc.id, tc.mode, got.Status, tc.wantSt)
		}
	}
}

// TestRule1_7_1_ViaPackageVar verifies rule 1.7.1 end-to-end via motdPath injection.
// No t.Parallel(): modifies package-level motdPath.
func TestRule1_7_1_ViaPackageVar(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "motd")
	if err := os.WriteFile(p, []byte("Authorized use only."), 0o644); err != nil {
		t.Fatal(err)
	}
	orig := motdPath
	motdPath = p
	t.Cleanup(func() { motdPath = orig })

	sec := models.SecurityInfo{}
	ks := models.KernelSecurityInfo{}
	report := Evaluate(sec, ks, 1, false, "apt")
	var res *models.CISResult
	for i := range report.Results {
		if report.Results[i].ID == "1.7.1" {
			res = &report.Results[i]
			break
		}
	}
	if res == nil {
		t.Fatal("rule 1.7.1 not found in Evaluate output")
	}
	if res.Status != models.CISPass {
		t.Errorf("got %s (%s), want PASS", res.Status, res.Finding)
	}
}

// ── 5.4.6 PASS_WARN_AGE ──────────────────────────────────────────────────────

// TestRule5_4_6_PassWarnAge verifies rule 5.4.6 (PASS_WARN_AGE ≥ 7).
// No t.Parallel(): modifies package-level loginDefsPath.
func TestRule5_4_6_PassWarnAge(t *testing.T) {
	cases := []struct {
		name    string
		content string
		wantSt  models.CISStatus
	}{
		{"warn age 7 passes", "PASS_WARN_AGE 7\n", models.CISPass},
		{"warn age 14 passes", "PASS_WARN_AGE 14\n", models.CISPass},
		{"warn age 6 fails", "PASS_WARN_AGE 6\n", models.CISFail},
		{"warn age 0 fails", "PASS_WARN_AGE 0\n", models.CISFail},
		{"field missing fails", "PASS_MAX_DAYS 365\n", models.CISFail},
		{"commented out fails", "# PASS_WARN_AGE 7\n", models.CISFail},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "login.defs")
			if err := os.WriteFile(p, []byte(tc.content), 0o644); err != nil {
				t.Fatal(err)
			}
			orig := loginDefsPath
			loginDefsPath = p
			t.Cleanup(func() { loginDefsPath = orig })

			sec := models.SecurityInfo{}
			ks := models.KernelSecurityInfo{}
			report := Evaluate(sec, ks, 1, false, "apt")
			var res *models.CISResult
			for i := range report.Results {
				if report.Results[i].ID == "5.4.6" {
					res = &report.Results[i]
					break
				}
			}
			if res == nil {
				t.Fatal("rule 5.4.6 not found in Evaluate output")
			}
			if res.Status != tc.wantSt {
				t.Errorf("%s: got %s (%s), want %s", tc.name, res.Status, res.Finding, tc.wantSt)
			}
		})
	}
}

// ── 6.1.9–6.1.13 File Ownership ─────────────────────────────────────────────

// TestCheckFileOwnerRootRoot_Fail verifies that a file not owned by root fails.
// Uses the helper directly so we can inject a temp path without root.
func TestCheckFileOwnerRootRoot_Fail(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "passwd")
	if err := os.WriteFile(p, []byte("root:x:0:0::/root:/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := ruleByID("6.1.9")
	got := checkFileOwnerRootRoot(r, p, "chown root:root /etc/passwd")
	// Running as non-root in CI: uid != 0, so we expect FAIL.
	if got.Status == models.CISSkipped {
		t.Skip("file ownership stat unavailable on this platform")
	}
	if got.Status != models.CISFail {
		t.Errorf("got %s, want FAIL (test runs as non-root)", got.Status)
	}
	if !strings.Contains(got.Finding, "uid=") {
		t.Errorf("finding %q missing uid=", got.Finding)
	}
}

// TestCheckFileOwnerRootRoot_Missing verifies SKIP when the file doesn't exist.
func TestCheckFileOwnerRootRoot_Missing(t *testing.T) {
	t.Parallel()
	r := ruleByID("6.1.9")
	got := checkFileOwnerRootRoot(r, "/nonexistent/file/xyz", "fix")
	if got.Status != models.CISSkipped {
		t.Errorf("got %s, want SKIP for missing file", got.Status)
	}
}

// TestCheckFileOwnerRootRootOrShadow_Fail verifies a non-root-owned file fails.
func TestCheckFileOwnerRootRootOrShadow_Fail(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "shadow")
	if err := os.WriteFile(p, []byte("root:!:0:0:99999:7:::\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	r := ruleByID("6.1.10")
	got := checkFileOwnerRootRootOrShadow(r, p, "chown root:shadow /etc/shadow")
	if got.Status == models.CISSkipped {
		t.Skip("file ownership stat unavailable on this platform")
	}
	if got.Status != models.CISFail {
		t.Errorf("got %s, want FAIL (test runs as non-root, uid != 0)", got.Status)
	}
}

// TestCheckFileOwnerRootRootOrShadow_Missing verifies SKIP when file absent.
func TestCheckFileOwnerRootRootOrShadow_Missing(t *testing.T) {
	t.Parallel()
	r := ruleByID("6.1.10")
	got := checkFileOwnerRootRootOrShadow(r, "/nonexistent/shadow", "fix")
	if got.Status != models.CISSkipped {
		t.Errorf("got %s, want SKIP for missing file", got.Status)
	}
}

// TestRules6_1_9_to_6_1_13_InEvaluate verifies all five ownership rules appear
// in Evaluate output with the expected IDs and section.
func TestRules6_1_9_to_6_1_13_InEvaluate(t *testing.T) {
	t.Parallel()
	sec := models.SecurityInfo{}
	ks := models.KernelSecurityInfo{}
	report := Evaluate(sec, ks, 1, false, "apt")
	want := map[string]bool{
		"6.1.9": false, "6.1.10": false, "6.1.11": false,
		"6.1.12": false, "6.1.13": false,
	}
	for _, res := range report.Results {
		if _, ok := want[res.ID]; ok {
			want[res.ID] = true
			if res.Section != cisCatFiles {
				t.Errorf("rule %s section = %q, want %q", res.ID, res.Section, cisCatFiles)
			}
		}
	}
	for id, found := range want {
		if !found {
			t.Errorf("rule %s missing from Evaluate output", id)
		}
	}
}
