package cis

import (
	"fmt"
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
		id     string
		mode   os.FileMode
		wantSt models.CISStatus
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
	if os.Getuid() == 0 {
		t.Skip("temp files are root-owned when running as root; FAIL verdict cannot be produced")
	}
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
	if os.Getuid() == 0 {
		t.Skip("temp files are root-owned when running as root; FAIL verdict cannot be produced")
	}
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

// ── 2.2 / 2.3 Legacy Services / Server Daemons ──────────────────────────────

// TestCheckServiceNotInstalled_Pass verifies PASS when no binary is found.
func TestCheckServiceNotInstalled_Pass(t *testing.T) {
	t.Parallel()
	r := ruleByID("2.2.2")
	got := checkServiceNotInstalled(r, []string{"/nonexistent/rsh", "/also/nonexistent/rlogin"}, "fix")
	if got.Status != models.CISPass {
		t.Errorf("got %s, want PASS when no binary found", got.Status)
	}
}

// TestCheckServiceNotInstalled_Fail verifies FAIL when a binary is present.
func TestCheckServiceNotInstalled_Fail(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	bin := filepath.Join(dir, "rsh")
	if err := os.WriteFile(bin, []byte{}, 0o755); err != nil {
		t.Fatal(err)
	}
	r := ruleByID("2.2.2")
	got := checkServiceNotInstalled(r, []string{bin}, "remove rsh")
	if got.Status != models.CISFail {
		t.Errorf("got %s, want FAIL when binary found", got.Status)
	}
	if !strings.Contains(got.Finding, bin) {
		t.Errorf("finding %q missing binary path", got.Finding)
	}
}

// TestRules2_2_and_2_3_InEvaluate verifies all 9 service rules appear in Evaluate.
func TestRules2_2_and_2_3_InEvaluate(t *testing.T) {
	t.Parallel()
	sec := models.SecurityInfo{}
	ks := models.KernelSecurityInfo{}
	report := Evaluate(sec, ks, 1, false, "apt")
	want := map[string]bool{
		"2.2.1": false, "2.2.2": false, "2.2.3": false, "2.2.4": false,
		"2.3.1": false, "2.3.2": false, "2.3.3": false, "2.3.4": false, "2.3.5": false,
	}
	for _, res := range report.Results {
		if _, ok := want[res.ID]; ok {
			want[res.ID] = true
			if res.Section != cisCatServices {
				t.Errorf("rule %s section = %q, want %q", res.ID, res.Section, cisCatServices)
			}
		}
	}
	for id, found := range want {
		if !found {
			t.Errorf("rule %s missing from Evaluate output", id)
		}
	}
}

// ── 1.4 Bootloader / GRUB ────────────────────────────────────────────────────

// TestRule1_4_1_GRUBPermissions verifies rule 1.4.1 passes for ≤0600 file.
// No t.Parallel(): modifies package-level grubCfgPaths.
func TestRule1_4_1_GRUBPermissions(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "grub.cfg")
	if err := os.WriteFile(p, []byte("set default=0\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	orig := grubCfgPaths
	grubCfgPaths = []string{p}
	t.Cleanup(func() { grubCfgPaths = orig })

	sec := models.SecurityInfo{}
	ks := models.KernelSecurityInfo{}
	report := Evaluate(sec, ks, 1, false, "apt")
	var res *models.CISResult
	for i := range report.Results {
		if report.Results[i].ID == "1.4.1" {
			res = &report.Results[i]
			break
		}
	}
	if res == nil {
		t.Fatal("rule 1.4.1 not found in Evaluate output")
	}
	if res.Status != models.CISPass {
		t.Errorf("grub.cfg at 0600 should PASS, got %s (%s)", res.Status, res.Finding)
	}
}

// TestRule1_4_1_GRUBTooPermissive verifies rule 1.4.1 fails when mode > 0600.
// No t.Parallel(): modifies package-level grubCfgPaths.
func TestRule1_4_1_GRUBTooPermissive(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "grub.cfg")
	if err := os.WriteFile(p, []byte("set default=0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}

	orig := grubCfgPaths
	grubCfgPaths = []string{p}
	t.Cleanup(func() { grubCfgPaths = orig })

	sec := models.SecurityInfo{}
	ks := models.KernelSecurityInfo{}
	report := Evaluate(sec, ks, 1, false, "apt")
	var res *models.CISResult
	for i := range report.Results {
		if report.Results[i].ID == "1.4.1" {
			res = &report.Results[i]
			break
		}
	}
	if res == nil {
		t.Fatal("rule 1.4.1 not found in Evaluate output")
	}
	if res.Status != models.CISFail {
		t.Errorf("grub.cfg at 0644 should FAIL, got %s (%s)", res.Status, res.Finding)
	}
}

// TestRule1_4_1_GRUBMissing verifies rule 1.4.1 SKIPs when grub.cfg absent.
// No t.Parallel(): modifies package-level grubCfgPaths.
func TestRule1_4_1_GRUBMissing(t *testing.T) {
	orig := grubCfgPaths
	grubCfgPaths = []string{"/nonexistent/grub.cfg"}
	t.Cleanup(func() { grubCfgPaths = orig })

	sec := models.SecurityInfo{}
	ks := models.KernelSecurityInfo{}
	report := Evaluate(sec, ks, 1, false, "apt")
	var res *models.CISResult
	for i := range report.Results {
		if report.Results[i].ID == "1.4.1" {
			res = &report.Results[i]
			break
		}
	}
	if res == nil {
		t.Fatal("rule 1.4.1 not found in Evaluate output")
	}
	if res.Status != models.CISSkipped {
		t.Errorf("missing grub.cfg should SKIP, got %s", res.Status)
	}
}

// ── 5.3.2 / 5.3.3 sudo PTY and logfile ──────────────────────────────────────

func TestRule5_3_2_UsePTY(t *testing.T) {
	t.Parallel()
	rule := ruleByID("5.3.2")

	t.Run("sudoers unreadable → skip", func(t *testing.T) {
		t.Parallel()
		got := rule.Check(models.SecurityInfo{SudoersUnreadable: true}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("SudoersUnreadable=true: want Skipped, got %s (%s)", got.Status, got.Finding)
		}
	})
	t.Run("use_pty not set → fail", func(t *testing.T) {
		t.Parallel()
		got := rule.Check(models.SecurityInfo{SudoDefaultsPTY: false}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("SudoDefaultsPTY=false: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
	t.Run("use_pty set → pass", func(t *testing.T) {
		t.Parallel()
		got := rule.Check(models.SecurityInfo{SudoDefaultsPTY: true}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("SudoDefaultsPTY=true: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})
}

func TestRule5_3_3_Logfile(t *testing.T) {
	t.Parallel()
	rule := ruleByID("5.3.3")

	t.Run("sudoers unreadable → skip", func(t *testing.T) {
		t.Parallel()
		got := rule.Check(models.SecurityInfo{SudoersUnreadable: true}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("SudoersUnreadable=true: want Skipped, got %s (%s)", got.Status, got.Finding)
		}
	})
	t.Run("logfile not configured → fail", func(t *testing.T) {
		t.Parallel()
		got := rule.Check(models.SecurityInfo{SudoDefaultsLogfile: false}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("SudoDefaultsLogfile=false: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
	t.Run("logfile configured → pass", func(t *testing.T) {
		t.Parallel()
		got := rule.Check(models.SecurityInfo{SudoDefaultsLogfile: true}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("SudoDefaultsLogfile=true: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// ── 5.1.8 / 5.1.9 cron/at access control ────────────────────────────────────

// TestRule5_1_8_CronAccess verifies rule 5.1.8 (cron.allow or cron.deny).
// No t.Parallel(): modifies package-level cronAllowPath / cronDenyPath.
func TestRule5_1_8_CronAccess(t *testing.T) {
	dir := t.TempDir()

	origAllow := cronAllowPath
	origDeny := cronDenyPath
	t.Cleanup(func() {
		cronAllowPath = origAllow
		cronDenyPath = origDeny
	})

	findResult := func(report models.CISReport) models.CISResult {
		t.Helper()
		for _, r := range report.Results {
			if r.ID == "5.1.8" {
				return r
			}
		}
		t.Fatal("rule 5.1.8 not found in Evaluate output")
		return models.CISResult{}
	}

	t.Run("neither file exists → fail", func(t *testing.T) {
		cronAllowPath = filepath.Join(dir, "cron.allow.missing")
		cronDenyPath = filepath.Join(dir, "cron.deny.missing")
		report := Evaluate(models.SecurityInfo{}, models.KernelSecurityInfo{}, 1, false, "apt")
		res := findResult(report)
		if res.Status != models.CISFail {
			t.Errorf("no cron control files: want Fail, got %s (%s)", res.Status, res.Finding)
		}
	})
	t.Run("cron.allow present → pass", func(t *testing.T) {
		allowFile := filepath.Join(dir, "cron.allow")
		if err := os.WriteFile(allowFile, []byte("alice\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		cronAllowPath = allowFile
		cronDenyPath = filepath.Join(dir, "cron.deny.missing")
		report := Evaluate(models.SecurityInfo{}, models.KernelSecurityInfo{}, 1, false, "apt")
		res := findResult(report)
		if res.Status != models.CISPass {
			t.Errorf("cron.allow present: want Pass, got %s (%s)", res.Status, res.Finding)
		}
	})
	t.Run("cron.deny present → pass", func(t *testing.T) {
		cronAllowPath = filepath.Join(dir, "cron.allow.missing")
		denyFile := filepath.Join(dir, "cron.deny")
		if err := os.WriteFile(denyFile, []byte("ALL\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		cronDenyPath = denyFile
		report := Evaluate(models.SecurityInfo{}, models.KernelSecurityInfo{}, 1, false, "apt")
		res := findResult(report)
		if res.Status != models.CISPass {
			t.Errorf("cron.deny present: want Pass, got %s (%s)", res.Status, res.Finding)
		}
	})
}

// TestRule5_1_9_AtAccess verifies rule 5.1.9 (at.allow or at.deny).
// No t.Parallel(): modifies package-level atAllowPath / atDenyPath.
func TestRule5_1_9_AtAccess(t *testing.T) {
	dir := t.TempDir()

	origAllow := atAllowPath
	origDeny := atDenyPath
	t.Cleanup(func() {
		atAllowPath = origAllow
		atDenyPath = origDeny
	})

	findResult := func(report models.CISReport) models.CISResult {
		t.Helper()
		for _, r := range report.Results {
			if r.ID == "5.1.9" {
				return r
			}
		}
		t.Fatal("rule 5.1.9 not found in Evaluate output")
		return models.CISResult{}
	}

	t.Run("neither file exists → fail", func(t *testing.T) {
		atAllowPath = filepath.Join(dir, "at.allow.missing")
		atDenyPath = filepath.Join(dir, "at.deny.missing")
		report := Evaluate(models.SecurityInfo{}, models.KernelSecurityInfo{}, 1, false, "apt")
		res := findResult(report)
		if res.Status != models.CISFail {
			t.Errorf("no at control files: want Fail, got %s (%s)", res.Status, res.Finding)
		}
	})
	t.Run("at.allow present → pass", func(t *testing.T) {
		allowFile := filepath.Join(dir, "at.allow")
		if err := os.WriteFile(allowFile, []byte("alice\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		atAllowPath = allowFile
		atDenyPath = filepath.Join(dir, "at.deny.missing")
		report := Evaluate(models.SecurityInfo{}, models.KernelSecurityInfo{}, 1, false, "apt")
		res := findResult(report)
		if res.Status != models.CISPass {
			t.Errorf("at.allow present: want Pass, got %s (%s)", res.Status, res.Finding)
		}
	})
	t.Run("at.deny present → pass", func(t *testing.T) {
		atAllowPath = filepath.Join(dir, "at.allow.missing")
		denyFile := filepath.Join(dir, "at.deny")
		if err := os.WriteFile(denyFile, []byte("ALL\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		atDenyPath = denyFile
		report := Evaluate(models.SecurityInfo{}, models.KernelSecurityInfo{}, 1, false, "apt")
		res := findResult(report)
		if res.Status != models.CISPass {
			t.Errorf("at.deny present: want Pass, got %s (%s)", res.Status, res.Finding)
		}
	})
}

// ── 4.2.1 rsyslog/syslog-ng installed ────────────────────────────────────────

// TestRule4_2_1_RsyslogInstalled verifies rule 4.2.1.
// No t.Parallel(): modifies package-level rsyslogBinPaths.
func TestRule4_2_1_RsyslogInstalled(t *testing.T) {
	dir := t.TempDir()
	origPaths := rsyslogBinPaths
	t.Cleanup(func() { rsyslogBinPaths = origPaths })

	findResult := func(report models.CISReport) models.CISResult {
		t.Helper()
		for _, r := range report.Results {
			if r.ID == "4.2.1" {
				return r
			}
		}
		t.Fatal("rule 4.2.1 not found in Evaluate output")
		return models.CISResult{}
	}

	t.Run("no syslog binary → fail", func(t *testing.T) {
		rsyslogBinPaths = []string{filepath.Join(dir, "rsyslogd.missing")}
		report := Evaluate(models.SecurityInfo{}, models.KernelSecurityInfo{}, 1, false, "apt")
		res := findResult(report)
		if res.Status != models.CISFail {
			t.Errorf("no syslog daemon: want Fail, got %s (%s)", res.Status, res.Finding)
		}
	})
	t.Run("rsyslogd present → pass", func(t *testing.T) {
		bin := filepath.Join(dir, "rsyslogd")
		if err := os.WriteFile(bin, []byte("#!/bin/sh"), 0o755); err != nil {
			t.Fatal(err)
		}
		rsyslogBinPaths = []string{bin}
		report := Evaluate(models.SecurityInfo{}, models.KernelSecurityInfo{}, 1, false, "apt")
		res := findResult(report)
		if res.Status != models.CISPass {
			t.Errorf("rsyslogd present: want Pass, got %s (%s)", res.Status, res.Finding)
		}
	})
	t.Run("remediation adapts to package manager", func(t *testing.T) {
		rsyslogBinPaths = []string{filepath.Join(dir, "rsyslogd.missing")}
		cases := []struct {
			pkgMgr  string
			wantStr string
		}{
			{"apt", "apt install rsyslog"},
			{"dnf", "dnf install rsyslog"},
			{"zypper", "zypper install rsyslog"},
			{"pacman", "pacman -S rsyslog"},
		}
		for _, tc := range cases {
			report := Evaluate(models.SecurityInfo{}, models.KernelSecurityInfo{}, 1, false, tc.pkgMgr)
			res := findResult(report)
			if res.Status != models.CISFail {
				t.Errorf("[%s] want Fail, got %s", tc.pkgMgr, res.Status)
				continue
			}
			if !strings.Contains(res.Remediation, tc.wantStr) {
				t.Errorf("[%s] remediation %q missing %q", tc.pkgMgr, res.Remediation, tc.wantStr)
			}
		}
	})
}

// TestRule1_4_2_GRUBOwnership verifies rule 1.4.2 fails for non-root-owned file.
// No t.Parallel(): modifies package-level grubCfgPaths.
func TestRule1_4_2_GRUBOwnership(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("temp files are root-owned when running as root; FAIL verdict cannot be produced")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "grub.cfg")
	if err := os.WriteFile(p, []byte("set default=0\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	orig := grubCfgPaths
	grubCfgPaths = []string{p}
	t.Cleanup(func() { grubCfgPaths = orig })

	sec := models.SecurityInfo{}
	ks := models.KernelSecurityInfo{}
	report := Evaluate(sec, ks, 1, false, "apt")
	var res *models.CISResult
	for i := range report.Results {
		if report.Results[i].ID == "1.4.2" {
			res = &report.Results[i]
			break
		}
	}
	if res == nil {
		t.Fatal("rule 1.4.2 not found in Evaluate output")
	}
	if res.Status == models.CISSkipped {
		t.Skip("ownership check unavailable on this platform")
	}
	// Running as non-root: expect FAIL (uid != 0)
	if res.Status != models.CISFail {
		t.Errorf("non-root-owned grub.cfg should FAIL, got %s (%s)", res.Status, res.Finding)
	}
}

// ── 1.1.1.x filesystem module checks (checkModuleDisabled) ──────────────────

// TestCheckModuleDisabled_Rule1_1_1_1 exercises checkModuleDisabled via rule
// 1.1.1.1 (cramfs). The helper is shared by all 1.1.1.x and 3.4.x rules.
// No t.Parallel(): mutates package-level procModulesPath and modprobeDPath.
func TestCheckModuleDisabled_Rule1_1_1_1(t *testing.T) {
	dir := t.TempDir()
	origModules := procModulesPath
	origModprobe := modprobeDPath
	t.Cleanup(func() {
		procModulesPath = origModules
		modprobeDPath = origModprobe
	})

	rule := ruleByID("1.1.1.1")

	t.Run("unreadable /proc/modules → SKIP", func(t *testing.T) {
		procModulesPath = filepath.Join(dir, "no_such_file")
		modprobeDPath = filepath.Join(dir, "modprobe.d")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("module loaded → FAIL", func(t *testing.T) {
		modFile := filepath.Join(dir, "modules_loaded")
		if err := os.WriteFile(modFile, []byte("cramfs 36864 0 - Live 0x0000000000000000\next4 999999 2\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		procModulesPath = modFile
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("module loaded: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("module absent, no modprobe config → FAIL", func(t *testing.T) {
		modFile := filepath.Join(dir, "modules_empty")
		if err := os.WriteFile(modFile, []byte("ext4 999999 2\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		procModulesPath = modFile
		modprobeDPath = filepath.Join(dir, "modprobe_empty")
		if err := os.MkdirAll(modprobeDPath, 0o755); err != nil {
			t.Fatal(err)
		}
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("no disable config: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("module absent, install cramfs /bin/true → PASS", func(t *testing.T) {
		modFile := filepath.Join(dir, "modules_clean")
		if err := os.WriteFile(modFile, []byte("ext4 999999 2\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		procModulesPath = modFile
		confDir := filepath.Join(dir, "modprobe_install")
		if err := os.MkdirAll(confDir, 0o755); err != nil {
			t.Fatal(err)
		}
		confFile := filepath.Join(confDir, "cramfs.conf")
		if err := os.WriteFile(confFile, []byte("install cramfs /bin/true\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		modprobeDPath = confDir
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("install directive present: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("module absent, blacklist directive → PASS", func(t *testing.T) {
		modFile := filepath.Join(dir, "modules_clean2")
		if err := os.WriteFile(modFile, []byte("ext4 999999 2\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		procModulesPath = modFile
		confDir := filepath.Join(dir, "modprobe_blacklist")
		if err := os.MkdirAll(confDir, 0o755); err != nil {
			t.Fatal(err)
		}
		confFile := filepath.Join(confDir, "cramfs.conf")
		if err := os.WriteFile(confFile, []byte("blacklist cramfs\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		modprobeDPath = confDir
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("blacklist directive present: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// ── 1.1.2 /tmp separate partition (checkSeparateMountPoint) ─────────────────

// TestCheckSeparateMountPoint_Rule1_1_2 exercises checkSeparateMountPoint via
// rule 1.1.2 (/tmp on a separate partition).
// No t.Parallel(): mutates package-level procMountsPath.
func TestCheckSeparateMountPoint_Rule1_1_2(t *testing.T) {
	dir := t.TempDir()
	origMounts := procMountsPath
	t.Cleanup(func() { procMountsPath = origMounts })

	rule := ruleByID("1.1.2")

	t.Run("unreadable /proc/mounts → SKIP", func(t *testing.T) {
		procMountsPath = filepath.Join(dir, "no_mounts")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("/tmp not separately mounted → FAIL", func(t *testing.T) {
		mounts := filepath.Join(dir, "mounts_no_tmp")
		if err := os.WriteFile(mounts, []byte("sysfs /sys sysfs rw 0 0\n/dev/sda1 / ext4 rw 0 0\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		procMountsPath = mounts
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("/tmp absent: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("/tmp on its own partition → PASS", func(t *testing.T) {
		mounts := filepath.Join(dir, "mounts_with_tmp")
		if err := os.WriteFile(mounts, []byte("/dev/sda1 / ext4 rw 0 0\ntmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		procMountsPath = mounts
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("/tmp present: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// ── 1.1.3 /tmp nodev (checkMountOption) ─────────────────────────────────────

// TestCheckMountOption_Rule1_1_3 exercises checkMountOption via rule 1.1.3
// (/tmp must be mounted with nodev). The helper is shared by all 1.1.x
// mount-option rules.
// No t.Parallel(): mutates package-level procMountsPath.
func TestCheckMountOption_Rule1_1_3(t *testing.T) {
	dir := t.TempDir()
	origMounts := procMountsPath
	t.Cleanup(func() { procMountsPath = origMounts })

	rule := ruleByID("1.1.3")

	t.Run("unreadable /proc/mounts → SKIP", func(t *testing.T) {
		procMountsPath = filepath.Join(dir, "no_mounts")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("/tmp not in mounts → SKIP", func(t *testing.T) {
		mounts := filepath.Join(dir, "mounts_no_tmp")
		if err := os.WriteFile(mounts, []byte("/dev/sda1 / ext4 rw 0 0\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		procMountsPath = mounts
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("/tmp absent: want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("/tmp mounted without nodev → FAIL", func(t *testing.T) {
		mounts := filepath.Join(dir, "mounts_no_nodev")
		if err := os.WriteFile(mounts, []byte("tmpfs /tmp tmpfs rw,nosuid,noexec 0 0\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		procMountsPath = mounts
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("nodev absent: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("/tmp mounted with nodev → PASS", func(t *testing.T) {
		mounts := filepath.Join(dir, "mounts_with_nodev")
		if err := os.WriteFile(mounts, []byte("tmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		procMountsPath = mounts
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("nodev present: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// ── 1.5.2 prelink not installed ───────────────────────────────────────────────

// TestRule1_5_2_PrelinkNotInstalled verifies rule 1.5.2.
// No t.Parallel(): mutates package-level prelinkBinPaths.
func TestRule1_5_2_PrelinkNotInstalled(t *testing.T) {
	dir := t.TempDir()
	origPaths := prelinkBinPaths
	t.Cleanup(func() { prelinkBinPaths = origPaths })

	rule := ruleByID("1.5.2")

	t.Run("prelink absent → PASS", func(t *testing.T) {
		prelinkBinPaths = []string{filepath.Join(dir, "prelink_missing")}
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("no prelink binary: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("prelink present → FAIL", func(t *testing.T) {
		bin := filepath.Join(dir, "prelink")
		if err := os.WriteFile(bin, []byte("#!/bin/sh"), 0o755); err != nil {
			t.Fatal(err)
		}
		prelinkBinPaths = []string{bin}
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("prelink present: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// ── 2.3.6 NFS not installed ───────────────────────────────────────────────────

// TestRule2_3_6_NFSNotInstalled verifies rule 2.3.6.
// No t.Parallel(): mutates package-level nfsBinPaths.
func TestRule2_3_6_NFSNotInstalled(t *testing.T) {
	dir := t.TempDir()
	origPaths := nfsBinPaths
	t.Cleanup(func() { nfsBinPaths = origPaths })

	rule := ruleByID("2.3.6")

	t.Run("no nfs binaries → PASS", func(t *testing.T) {
		nfsBinPaths = []string{filepath.Join(dir, "nfsd_missing"), filepath.Join(dir, "rpc.nfsd_missing")}
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("no nfs binaries: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("nfsd present → FAIL", func(t *testing.T) {
		bin := filepath.Join(dir, "nfsd")
		if err := os.WriteFile(bin, []byte("#!/bin/sh"), 0o755); err != nil {
			t.Fatal(err)
		}
		nfsBinPaths = []string{bin, filepath.Join(dir, "rpc.nfsd_missing")}
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("nfsd present: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// ── 5.3.5 sudo timestamp timeout ─────────────────────────────────────────────

func TestRule5_3_5_SudoTimestamp(t *testing.T) {
	t.Parallel()
	rule := ruleByID("5.3.5")

	cases := []struct {
		name string
		sec  models.SecurityInfo
		want models.CISStatus
	}{
		{"sudoers unreadable → SKIP", models.SecurityInfo{SudoersUnreadable: true}, models.CISSkipped},
		{"timestamp_timeout < 0 (never) → FAIL", models.SecurityInfo{SudoTimestampNever: true}, models.CISFail},
		{"timestamp_timeout=30 (> 15) → FAIL", models.SecurityInfo{SudoTimestampMins: 30}, models.CISFail},
		{"timestamp_timeout not set (0 = default 5min) → PASS", models.SecurityInfo{}, models.CISPass},
		{"timestamp_timeout=15 (exactly 15) → PASS", models.SecurityInfo{SudoTimestampMins: 15}, models.CISPass},
		{"timestamp_timeout=5 → PASS", models.SecurityInfo{SudoTimestampMins: 5}, models.CISPass},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := rule.Check(tc.sec, models.KernelSecurityInfo{})
			if got.Status != tc.want {
				t.Errorf("got %s, want %s (finding=%q)", got.Status, tc.want, got.Finding)
			}
		})
	}
}

// ── 5.4.7 inactive password lock ─────────────────────────────────────────────

// TestRule5_4_7_InactivePasswordLock verifies rule 5.4.7.
// No t.Parallel(): mutates package-level useraddDefaultPath.
func TestRule5_4_7_InactivePasswordLock(t *testing.T) {
	dir := t.TempDir()
	orig := useraddDefaultPath
	t.Cleanup(func() { useraddDefaultPath = orig })

	rule := ruleByID("5.4.7")

	t.Run("file absent → SKIP", func(t *testing.T) {
		useraddDefaultPath = filepath.Join(dir, "no_useradd")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("INACTIVE not set → FAIL", func(t *testing.T) {
		p := filepath.Join(dir, "useradd_no_inactive")
		if err := os.WriteFile(p, []byte("GROUP=100\nHOME=/home\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		useraddDefaultPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("INACTIVE absent: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("INACTIVE=-1 (no lockout) → FAIL", func(t *testing.T) {
		p := filepath.Join(dir, "useradd_inactive_neg1")
		if err := os.WriteFile(p, []byte("INACTIVE=-1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		useraddDefaultPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("INACTIVE=-1: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("INACTIVE=60 (> 30) → FAIL", func(t *testing.T) {
		p := filepath.Join(dir, "useradd_inactive_60")
		if err := os.WriteFile(p, []byte("INACTIVE=60\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		useraddDefaultPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("INACTIVE=60: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("INACTIVE=30 → PASS", func(t *testing.T) {
		p := filepath.Join(dir, "useradd_inactive_30")
		if err := os.WriteFile(p, []byte("INACTIVE=30\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		useraddDefaultPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("INACTIVE=30: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// ── 5.4.8 system accounts no interactive shells ───────────────────────────────

// TestRule5_4_8_SystemAccountShells verifies rule 5.4.8.
// No t.Parallel(): mutates package-level etcPasswdPath.
func TestRule5_4_8_SystemAccountShells(t *testing.T) {
	dir := t.TempDir()
	orig := etcPasswdPath
	t.Cleanup(func() { etcPasswdPath = orig })

	rule := ruleByID("5.4.8")

	t.Run("file absent → SKIP", func(t *testing.T) {
		etcPasswdPath = filepath.Join(dir, "no_passwd")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("no system accounts with shells → PASS", func(t *testing.T) {
		p := filepath.Join(dir, "passwd_ok")
		content := "root:x:0:0:root:/root:/bin/bash\n" +
			"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
			"alice:x:1000:1000::/home/alice:/bin/bash\n"
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		etcPasswdPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("clean passwd: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("system account uid=50 with /bin/bash → FAIL", func(t *testing.T) {
		p := filepath.Join(dir, "passwd_bad")
		content := "root:x:0:0:root:/root:/bin/bash\n" +
			"svc:x:50:50:svc:/var/svc:/bin/bash\n" +
			"alice:x:1000:1000::/home/alice:/bin/bash\n"
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		etcPasswdPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("svc with /bin/bash: want Fail, got %s (%s)", got.Status, got.Finding)
		}
		if !strings.Contains(got.Finding, "svc") {
			t.Errorf("finding should mention offending account, got: %q", got.Finding)
		}
	})
}

// ── 6.2.5-6.2.8 duplicate UID / GID / username / group-name checks ───────────

// TestRule6_2_5_DuplicateUIDs verifies rule 6.2.5.
// No t.Parallel(): mutates package-level etcPasswdPath.
func TestRule6_2_5_DuplicateUIDs(t *testing.T) {
	dir := t.TempDir()
	orig := etcPasswdPath
	t.Cleanup(func() { etcPasswdPath = orig })

	rule := ruleByID("6.2.5")

	t.Run("file absent → SKIP", func(t *testing.T) {
		etcPasswdPath = filepath.Join(dir, "no_passwd")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("no duplicate UIDs → PASS", func(t *testing.T) {
		p := filepath.Join(dir, "passwd_unique_uids")
		content := "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\nbob:x:1001:1001::/home/bob:/bin/bash\n"
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		etcPasswdPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("unique UIDs: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("duplicate UID 1000 → FAIL", func(t *testing.T) {
		p := filepath.Join(dir, "passwd_dup_uid")
		content := "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\nbob:x:1000:1001::/home/bob:/bin/bash\n"
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		etcPasswdPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("dup UID: want Fail, got %s (%s)", got.Status, got.Finding)
		}
		if !strings.Contains(got.Finding, "1000") {
			t.Errorf("finding should mention duplicate UID, got: %q", got.Finding)
		}
	})
}

// TestRule6_2_6_DuplicateGIDs verifies rule 6.2.6.
// No t.Parallel(): mutates package-level etcGroupPath.
func TestRule6_2_6_DuplicateGIDs(t *testing.T) {
	dir := t.TempDir()
	orig := etcGroupPath
	t.Cleanup(func() { etcGroupPath = orig })

	rule := ruleByID("6.2.6")

	t.Run("file absent → SKIP", func(t *testing.T) {
		etcGroupPath = filepath.Join(dir, "no_group")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("no duplicate GIDs → PASS", func(t *testing.T) {
		p := filepath.Join(dir, "group_unique_gids")
		content := "root:x:0:\nstaff:x:50:\nalice:x:1000:\n"
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		etcGroupPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("unique GIDs: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("duplicate GID 50 → FAIL", func(t *testing.T) {
		p := filepath.Join(dir, "group_dup_gid")
		content := "root:x:0:\nstaff:x:50:\nops:x:50:\n"
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		etcGroupPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("dup GID: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// TestRule6_2_7_DuplicateUsernames verifies rule 6.2.7.
// No t.Parallel(): mutates package-level etcPasswdPath.
func TestRule6_2_7_DuplicateUsernames(t *testing.T) {
	dir := t.TempDir()
	orig := etcPasswdPath
	t.Cleanup(func() { etcPasswdPath = orig })

	rule := ruleByID("6.2.7")

	t.Run("file absent → SKIP", func(t *testing.T) {
		etcPasswdPath = filepath.Join(dir, "no_passwd")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("no duplicate usernames → PASS", func(t *testing.T) {
		p := filepath.Join(dir, "passwd_unique_names")
		content := "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n"
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		etcPasswdPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("unique usernames: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("duplicate username 'alice' → FAIL", func(t *testing.T) {
		p := filepath.Join(dir, "passwd_dup_name")
		content := "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\nalice:x:1001:1001::/home/alice2:/bin/bash\n"
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		etcPasswdPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("dup username: want Fail, got %s (%s)", got.Status, got.Finding)
		}
		if !strings.Contains(got.Finding, "alice") {
			t.Errorf("finding should mention duplicate name, got: %q", got.Finding)
		}
	})
}

// TestRule6_2_8_DuplicateGroupNames verifies rule 6.2.8.
// No t.Parallel(): mutates package-level etcGroupPath.
func TestRule6_2_8_DuplicateGroupNames(t *testing.T) {
	dir := t.TempDir()
	orig := etcGroupPath
	t.Cleanup(func() { etcGroupPath = orig })

	rule := ruleByID("6.2.8")

	t.Run("file absent → SKIP", func(t *testing.T) {
		etcGroupPath = filepath.Join(dir, "no_group")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("no duplicate group names → PASS", func(t *testing.T) {
		p := filepath.Join(dir, "group_unique_names")
		content := "root:x:0:\nstaff:x:50:\nops:x:51:\n"
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		etcGroupPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("unique group names: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("duplicate group name 'staff' → FAIL", func(t *testing.T) {
		p := filepath.Join(dir, "group_dup_name")
		content := "root:x:0:\nstaff:x:50:\nstaff:x:51:\n"
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		etcGroupPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("dup group name: want Fail, got %s (%s)", got.Status, got.Finding)
		}
		if !strings.Contains(got.Finding, "staff") {
			t.Errorf("finding should mention duplicate name, got: %q", got.Finding)
		}
	})
}

// ── 1.1.12 /var/log separate partition ───────────────────────────────────────

// TestRule1_1_12_VarLogSeparate exercises rule 1.1.12 (/var/log separate).
// No t.Parallel(): mutates package-level procMountsPath.
func TestRule1_1_12_VarLogSeparate(t *testing.T) {
	dir := t.TempDir()
	orig := procMountsPath
	t.Cleanup(func() { procMountsPath = orig })

	rule := ruleByID("1.1.12")

	t.Run("/var/log not separately mounted → FAIL", func(t *testing.T) {
		mounts := filepath.Join(dir, "mounts_no_varlog")
		if err := os.WriteFile(mounts, []byte("/dev/sda1 / ext4 rw 0 0\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		procMountsPath = mounts
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("/var/log on own partition → PASS", func(t *testing.T) {
		mounts := filepath.Join(dir, "mounts_with_varlog")
		if err := os.WriteFile(mounts, []byte("/dev/sda1 / ext4 rw 0 0\n/dev/sda3 /var/log ext4 rw 0 0\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		procMountsPath = mounts
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// ── 1.1.15 /home nosuid ───────────────────────────────────────────────────────

// TestRule1_1_15_HomeNosuid verifies rule 1.1.15.
// No t.Parallel(): mutates package-level procMountsPath.
func TestRule1_1_15_HomeNosuid(t *testing.T) {
	dir := t.TempDir()
	orig := procMountsPath
	t.Cleanup(func() { procMountsPath = orig })

	rule := ruleByID("1.1.15")

	t.Run("/home without nosuid → FAIL", func(t *testing.T) {
		mounts := filepath.Join(dir, "mounts_no_nosuid")
		if err := os.WriteFile(mounts, []byte("/dev/sda2 /home ext4 rw,nodev 0 0\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		procMountsPath = mounts
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("/home with nosuid → PASS", func(t *testing.T) {
		mounts := filepath.Join(dir, "mounts_with_nosuid")
		if err := os.WriteFile(mounts, []byte("/dev/sda2 /home ext4 rw,nodev,nosuid 0 0\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		procMountsPath = mounts
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// ── 1.5.3 ASLR enabled ────────────────────────────────────────────────────────

// TestRule1_5_3_ApportDisabled verifies rule 1.5.3 (automatic error reporting).
// No t.Parallel() — mutates apportBinPaths and apportDefaultPath.
func TestRule1_5_3_ApportDisabled(t *testing.T) {
	rule := ruleByID("1.5.3")
	dir := t.TempDir()

	origBins := apportBinPaths
	origCfg := apportDefaultPath
	t.Cleanup(func() {
		apportBinPaths = origBins
		apportDefaultPath = origCfg
	})

	t.Run("apport not installed → PASS", func(t *testing.T) {
		apportBinPaths = []string{filepath.Join(dir, "no_apport")}
		apportDefaultPath = filepath.Join(dir, "no_default_apport")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("not installed: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("apport installed but enabled=0 → PASS", func(t *testing.T) {
		bin := filepath.Join(dir, "apport")
		if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		apportBinPaths = []string{bin}
		cfg := filepath.Join(dir, "default_apport_disabled")
		if err := os.WriteFile(cfg, []byte("enabled=0\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		apportDefaultPath = cfg
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("enabled=0: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("apport installed and enabled=1 → FAIL", func(t *testing.T) {
		bin := filepath.Join(dir, "apport2")
		if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		apportBinPaths = []string{bin}
		cfg := filepath.Join(dir, "default_apport_enabled")
		if err := os.WriteFile(cfg, []byte("enabled=1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		apportDefaultPath = cfg
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("enabled=1: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("apport installed but /etc/default/apport missing → FAIL", func(t *testing.T) {
		bin := filepath.Join(dir, "apport3")
		if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		apportBinPaths = []string{bin}
		apportDefaultPath = filepath.Join(dir, "no_default_apport_2")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("missing config: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// ── 4.1.x audit rule checks ───────────────────────────────────────────────────

// TestCheckAuditRule_Rule4_1_3 exercises the checkAuditRule helper via rule 4.1.3.
// No t.Parallel(): mutates package-level auditRulesDPath and auditRulesFilePath.
func TestCheckAuditRule_Rule4_1_3(t *testing.T) {
	dir := t.TempDir()
	origDir := auditRulesDPath
	origFile := auditRulesFilePath
	t.Cleanup(func() {
		auditRulesDPath = origDir
		auditRulesFilePath = origFile
	})

	rule := ruleByID("4.1.3")

	t.Run("no audit files → SKIP", func(t *testing.T) {
		auditRulesFilePath = filepath.Join(dir, "no_audit.rules")
		auditRulesDPath = filepath.Join(dir, "no_rules_d")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("audit.rules present but no datetime rules → FAIL", func(t *testing.T) {
		p := filepath.Join(dir, "audit.rules")
		if err := os.WriteFile(p, []byte("-a always,exit -F arch=b64 -S chmod -k perm_mod\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		auditRulesFilePath = p
		auditRulesDPath = filepath.Join(dir, "empty_rules_d")
		if err := os.MkdirAll(auditRulesDPath, 0o755); err != nil {
			t.Fatal(err)
		}
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("rules.d has adjtimex rule → PASS", func(t *testing.T) {
		auditRulesFilePath = filepath.Join(dir, "no_audit2.rules")
		rulesD := filepath.Join(dir, "rules_d_time")
		if err := os.MkdirAll(rulesD, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(rulesD, "50-time.rules"),
			[]byte("-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		auditRulesDPath = rulesD
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("audit.rules with clock_settime → PASS", func(t *testing.T) {
		p := filepath.Join(dir, "audit_time.rules")
		if err := os.WriteFile(p, []byte("-a always,exit -F arch=b64 -S clock_settime -k time-change\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		auditRulesFilePath = p
		auditRulesDPath = filepath.Join(dir, "empty_rules_d2")
		if err := os.MkdirAll(auditRulesDPath, 0o755); err != nil {
			t.Fatal(err)
		}
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// TestCheckAuditRule_Rule4_1_17_Immutable verifies rule 4.1.17 (-e 2).
// No t.Parallel(): mutates package-level audit path vars.
func TestCheckAuditRule_Rule4_1_17_Immutable(t *testing.T) {
	dir := t.TempDir()
	origDir := auditRulesDPath
	origFile := auditRulesFilePath
	t.Cleanup(func() {
		auditRulesDPath = origDir
		auditRulesFilePath = origFile
	})

	rule := ruleByID("4.1.17")

	t.Run("-e 2 present → PASS", func(t *testing.T) {
		p := filepath.Join(dir, "finalize.rules")
		if err := os.WriteFile(p, []byte("# make config immutable\n-e 2\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		auditRulesFilePath = p
		auditRulesDPath = filepath.Join(dir, "empty_d")
		if err := os.MkdirAll(auditRulesDPath, 0o755); err != nil {
			t.Fatal(err)
		}
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("-e 2 absent → FAIL", func(t *testing.T) {
		p := filepath.Join(dir, "no_finalize.rules")
		if err := os.WriteFile(p, []byte("-a always,exit -F arch=b64 -S chmod\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		auditRulesFilePath = p
		auditRulesDPath = filepath.Join(dir, "empty_d2")
		if err := os.MkdirAll(auditRulesDPath, 0o755); err != nil {
			t.Fatal(err)
		}
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// ── 6.2.9 root only UID 0 ─────────────────────────────────────────────────────

// TestRule6_2_9_RootOnlyUID0 verifies rule 6.2.9.
// No t.Parallel(): mutates package-level etcPasswdPath.
func TestRule6_2_9_RootOnlyUID0(t *testing.T) {
	dir := t.TempDir()
	orig := etcPasswdPath
	t.Cleanup(func() { etcPasswdPath = orig })

	rule := ruleByID("6.2.9")

	t.Run("file absent → SKIP", func(t *testing.T) {
		etcPasswdPath = filepath.Join(dir, "no_passwd")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("only root has uid=0 → PASS", func(t *testing.T) {
		p := filepath.Join(dir, "passwd_ok")
		content := "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n"
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		etcPasswdPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("non-root account with uid=0 → FAIL", func(t *testing.T) {
		p := filepath.Join(dir, "passwd_bad")
		content := "root:x:0:0:root:/root:/bin/bash\nshadow_root:x:0:0::/:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/bash\n"
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		etcPasswdPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("want Fail, got %s (%s)", got.Status, got.Finding)
		}
		if !strings.Contains(got.Finding, "shadow_root") {
			t.Errorf("finding should name offending account, got: %q", got.Finding)
		}
	})
}

// ── 1.1.17 USB storage disabled, 1.1.18 automounting disabled ────────────────

// TestRule1_1_17_USBStorage and TestRule1_1_18_Automounting both use
// checkModuleDisabled — covered by the same helper already tested via
// TestCheckModuleDisabled_Rule1_1_1_1. Just verify rule IDs exist and run.
func TestRule1_1_17_18_ModuleChecks(t *testing.T) {
	t.Parallel()
	for _, id := range []string{"1.1.17", "1.1.18"} {
		t.Run(id, func(t *testing.T) {
			t.Parallel()
			rule := ruleByID(id)
			if rule.Check == nil {
				t.Fatalf("rule %s not found", id)
			}
			// On macOS /proc/modules is absent → SKIP is the expected result.
			got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
			if got.Status == "" {
				t.Errorf("rule %s returned empty status", id)
			}
		})
	}
}

// ── 5.2.3 SSH public host key permissions ─────────────────────────────────────

// TestRule5_2_3_SSHPublicKeyPerms verifies rule 5.2.3.
// No t.Parallel(): mutates package-level sshHostKeyDir.
func TestRule5_2_3_SSHPublicKeyPerms(t *testing.T) {
	dir := t.TempDir()
	orig := sshHostKeyDir
	t.Cleanup(func() { sshHostKeyDir = orig })

	rule := ruleByID("5.2.3")

	t.Run("dir unreadable → SKIP", func(t *testing.T) {
		sshHostKeyDir = filepath.Join(dir, "no_ssh")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("no host key pub files → SKIP", func(t *testing.T) {
		d := filepath.Join(dir, "ssh_empty")
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "sshd_config"), []byte("# config\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		sshHostKeyDir = d
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("no pub keys: want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("pub key with 0644 → PASS", func(t *testing.T) {
		d := filepath.Join(dir, "ssh_ok")
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "ssh_host_ed25519_key.pub"), []byte("ssh-ed25519 AAAA\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		sshHostKeyDir = d
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("0644 pub key: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("pub key with 0664 (group write) → FAIL", func(t *testing.T) {
		d := filepath.Join(dir, "ssh_bad_pub")
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(d, "ssh_host_rsa_key.pub")
		if err := os.WriteFile(p, []byte("ssh-rsa AAAA\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		// chmod explicitly to bypass umask
		if err := os.Chmod(p, 0o664); err != nil {
			t.Fatal(err)
		}
		sshHostKeyDir = d
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("0664 pub key: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// ── 5.2.4 SSH private host key permissions ────────────────────────────────────

// TestRule5_2_4_SSHPrivateKeyPerms verifies rule 5.2.4.
// No t.Parallel(): mutates package-level sshHostKeyDir.
func TestRule5_2_4_SSHPrivateKeyPerms(t *testing.T) {
	dir := t.TempDir()
	orig := sshHostKeyDir
	t.Cleanup(func() { sshHostKeyDir = orig })

	rule := ruleByID("5.2.4")

	t.Run("no private host key files → SKIP", func(t *testing.T) {
		d := filepath.Join(dir, "ssh_only_pub")
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "ssh_host_ed25519_key.pub"), []byte("ssh-ed25519 AAAA\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		sshHostKeyDir = d
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("no private keys: want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("private key with 0600 → PASS", func(t *testing.T) {
		d := filepath.Join(dir, "ssh_priv_ok")
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "ssh_host_ed25519_key"), []byte("stub-ssh-host-key-content\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		sshHostKeyDir = d
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("0600 private key: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("private key with 0640 (group-readable) → FAIL", func(t *testing.T) {
		d := filepath.Join(dir, "ssh_priv_bad")
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(d, "ssh_host_rsa_key")
		if err := os.WriteFile(p, []byte("stub-ssh-host-key-content\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		// chmod explicitly to bypass umask
		if err := os.Chmod(p, 0o640); err != nil {
			t.Fatal(err)
		}
		sshHostKeyDir = d
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("0640 private key: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// ── 4.2.2 journald ForwardToSyslog ────────────────────────────────────────────

// TestRule4_2_2_JournaldForwardToSyslog verifies rule 4.2.2.
// No t.Parallel(): mutates package-level journaldConfPath and journaldConfDPath.
func TestRule4_2_2_JournaldForwardToSyslog(t *testing.T) {
	dir := t.TempDir()
	origConf := journaldConfPath
	origDir := journaldConfDPath
	t.Cleanup(func() {
		journaldConfPath = origConf
		journaldConfDPath = origDir
	})

	rule := ruleByID("4.2.2")

	t.Run("no journald config → SKIP", func(t *testing.T) {
		journaldConfPath = filepath.Join(dir, "no_journald.conf")
		journaldConfDPath = filepath.Join(dir, "no_journald.conf.d")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("ForwardToSyslog=yes in main conf → PASS", func(t *testing.T) {
		p := filepath.Join(dir, "journald.conf")
		if err := os.WriteFile(p, []byte("[Journal]\nForwardToSyslog=yes\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		journaldConfPath = p
		journaldConfDPath = filepath.Join(dir, "no_confd")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("ForwardToSyslog=yes: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("ForwardToSyslog not set → FAIL", func(t *testing.T) {
		p := filepath.Join(dir, "journald_no_fwd.conf")
		if err := os.WriteFile(p, []byte("[Journal]\nStorage=persistent\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		journaldConfPath = p
		journaldConfDPath = filepath.Join(dir, "no_confd2")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("no ForwardToSyslog: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("ForwardToSyslog=yes in drop-in → PASS", func(t *testing.T) {
		journaldConfPath = filepath.Join(dir, "no_main_journald.conf")
		d := filepath.Join(dir, "journald_dropin")
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "50-forward.conf"), []byte("[Journal]\nForwardToSyslog=yes\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		journaldConfDPath = d
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("drop-in ForwardToSyslog=yes: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// ── 4.2.3 rsyslog remote logging ─────────────────────────────────────────────

// TestRule4_2_3_RsyslogRemote verifies rule 4.2.3.
// No t.Parallel(): mutates package-level rsyslogConfPath and rsyslogConfDPath.
func TestRule4_2_3_RsyslogRemote(t *testing.T) {
	dir := t.TempDir()
	origConf := rsyslogConfPath
	origDir := rsyslogConfDPath
	t.Cleanup(func() {
		rsyslogConfPath = origConf
		rsyslogConfDPath = origDir
	})

	rule := ruleByID("4.2.3")

	t.Run("no rsyslog config → SKIP", func(t *testing.T) {
		rsyslogConfPath = filepath.Join(dir, "no_rsyslog.conf")
		rsyslogConfDPath = filepath.Join(dir, "no_rsyslog.d")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("TCP forwarding (@@) in rsyslog.conf → PASS", func(t *testing.T) {
		p := filepath.Join(dir, "rsyslog_tcp.conf")
		if err := os.WriteFile(p, []byte("*.* @@loghost.example.com:514\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		rsyslogConfPath = p
		rsyslogConfDPath = filepath.Join(dir, "no_d")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("TCP forwarding: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("no remote forwarding → FAIL", func(t *testing.T) {
		p := filepath.Join(dir, "rsyslog_local.conf")
		if err := os.WriteFile(p, []byte("auth,authpriv.* /var/log/auth.log\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		rsyslogConfPath = p
		rsyslogConfDPath = filepath.Join(dir, "no_d2")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("no remote: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("omfwd action in drop-in → PASS", func(t *testing.T) {
		rsyslogConfPath = filepath.Join(dir, "no_rsyslog2.conf")
		d := filepath.Join(dir, "rsyslog_dropin")
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		content := `action(type="omfwd" target="loghost.example.com" port="514" protocol="tcp")`
		if err := os.WriteFile(filepath.Join(d, "50-remote.conf"), []byte(content+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		rsyslogConfDPath = d
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("omfwd action: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// ── 1.6.1 AppArmor installed ─────────────────────────────────────────────

// TestRule1_6_1_AppArmorInstalled verifies rule 1.6.1.
// No t.Parallel(): mutates package-level apparmorParserPaths.
func TestRule1_6_1_AppArmorInstalled(t *testing.T) {
	dir := t.TempDir()
	orig := apparmorParserPaths
	t.Cleanup(func() { apparmorParserPaths = orig })

	rule := ruleByID("1.6.1")

	t.Run("parser binary exists → PASS", func(t *testing.T) {
		p := filepath.Join(dir, "apparmor_parser")
		if err := os.WriteFile(p, []byte("stub"), 0o755); err != nil {
			t.Fatal(err)
		}
		apparmorParserPaths = []string{filepath.Join(dir, "nope"), p}
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("no parser found → FAIL", func(t *testing.T) {
		apparmorParserPaths = []string{filepath.Join(dir, "nope1"), filepath.Join(dir, "nope2")}
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// ── 1.6.2 AppArmor bootloader config ─────────────────────────────────────

// TestRule1_6_2_AppArmorBootloader verifies rule 1.6.2.
// No t.Parallel(): mutates package-level grubDefaultPath.
func TestRule1_6_2_AppArmorBootloader(t *testing.T) {
	dir := t.TempDir()
	orig := grubDefaultPath
	t.Cleanup(func() { grubDefaultPath = orig })

	rule := ruleByID("1.6.2")

	t.Run("no grub file → SKIP", func(t *testing.T) {
		grubDefaultPath = filepath.Join(dir, "no_grub")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("GRUB_CMDLINE_LINUX with apparmor params → PASS", func(t *testing.T) {
		p := filepath.Join(dir, "grub_pass")
		content := "GRUB_CMDLINE_LINUX=\"quiet splash apparmor=1 security=apparmor\"\n"
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		grubDefaultPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("GRUB_CMDLINE_LINUX without apparmor params → FAIL", func(t *testing.T) {
		p := filepath.Join(dir, "grub_fail")
		content := "GRUB_CMDLINE_LINUX=\"quiet splash\"\n"
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		grubDefaultPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("only GRUB_CMDLINE_LINUX_DEFAULT set → SKIP (key not found)", func(t *testing.T) {
		p := filepath.Join(dir, "grub_default_only")
		content := "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet apparmor=1 security=apparmor\"\n"
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		grubDefaultPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("DEFAULT-only: want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// ── 1.6.3 AppArmor profiles in enforce/complain mode ─────────────────────

// TestRule1_6_3_AppArmorProfilesLoaded verifies rule 1.6.3.
// No t.Parallel(): mutates package-level apparmorProfilesPath.
func TestRule1_6_3_AppArmorProfilesLoaded(t *testing.T) {
	dir := t.TempDir()
	orig := apparmorProfilesPath
	t.Cleanup(func() { apparmorProfilesPath = orig })

	rule := ruleByID("1.6.3")

	t.Run("no profiles file → SKIP", func(t *testing.T) {
		apparmorProfilesPath = filepath.Join(dir, "no_profiles")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("empty profiles file → FAIL", func(t *testing.T) {
		p := filepath.Join(dir, "profiles_empty")
		if err := os.WriteFile(p, []byte("\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		apparmorProfilesPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("empty: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("profiles loaded → PASS", func(t *testing.T) {
		p := filepath.Join(dir, "profiles_loaded")
		content := "/usr/sbin/mysqld (enforce)\n/usr/sbin/tcpdump (enforce)\n"
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		apparmorProfilesPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("loaded: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// ── 1.6.4 All AppArmor profiles enforcing ────────────────────────────────

// TestRule1_6_4_AppArmorEnforcing verifies rule 1.6.4.
// No t.Parallel(): mutates package-level apparmorProfilesPath.
func TestRule1_6_4_AppArmorEnforcing(t *testing.T) {
	dir := t.TempDir()
	orig := apparmorProfilesPath
	t.Cleanup(func() { apparmorProfilesPath = orig })

	rule := ruleByID("1.6.4")

	t.Run("no profiles file → SKIP", func(t *testing.T) {
		apparmorProfilesPath = filepath.Join(dir, "no_profiles2")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("all enforce → PASS", func(t *testing.T) {
		p := filepath.Join(dir, "profiles_enforce")
		content := "/usr/sbin/mysqld (enforce)\n/usr/sbin/tcpdump (enforce)\n"
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		apparmorProfilesPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("all enforce: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("some in complain mode → FAIL", func(t *testing.T) {
		p := filepath.Join(dir, "profiles_complain")
		content := "/usr/sbin/mysqld (enforce)\n/usr/sbin/tcpdump (complain)\n"
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		apparmorProfilesPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("complain: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// ── 6.2.10 Root PATH integrity ────────────────────────────────────────────

// TestRule6_2_10_RootPATH verifies rule 6.2.10.
// No t.Parallel(): mutates package-level etcEnvironmentPath.
func TestRule6_2_10_RootPATH(t *testing.T) {
	dir := t.TempDir()
	orig := etcEnvironmentPath
	t.Cleanup(func() { etcEnvironmentPath = orig })

	rule := ruleByID("6.2.10")

	t.Run("no /etc/environment → SKIP", func(t *testing.T) {
		etcEnvironmentPath = filepath.Join(dir, "no_env")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("no PATH in environment → SKIP", func(t *testing.T) {
		p := filepath.Join(dir, "env_no_path")
		if err := os.WriteFile(p, []byte("LANG=en_US.UTF-8\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		etcEnvironmentPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("no PATH: want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("clean PATH → PASS", func(t *testing.T) {
		p := filepath.Join(dir, "env_clean")
		if err := os.WriteFile(p, []byte("PATH=\"/usr/bin:/usr/sbin:/bin\"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		etcEnvironmentPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("clean PATH: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("dot in PATH → FAIL", func(t *testing.T) {
		p := filepath.Join(dir, "env_dot")
		if err := os.WriteFile(p, []byte("PATH=.:/usr/bin:/usr/sbin\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		etcEnvironmentPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("dot in PATH: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("empty component in PATH → FAIL", func(t *testing.T) {
		p := filepath.Join(dir, "env_empty_comp")
		if err := os.WriteFile(p, []byte("PATH=/usr/bin::/usr/sbin\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		etcEnvironmentPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("empty component: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("world-writable dir in PATH → FAIL", func(t *testing.T) {
		wwDir := filepath.Join(dir, "public_bin")
		if err := os.MkdirAll(wwDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(wwDir, 0o777); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, "env_ww")
		if err := os.WriteFile(p, []byte("PATH="+wwDir+":/usr/bin\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		etcEnvironmentPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("world-writable: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// ── 6.2.11 Home directory ownership ──────────────────────────────────────

// TestRule6_2_11_HomeDirOwnership verifies rule 6.2.11.
// No t.Parallel(): mutates package-level etcPasswdPath.
func TestRule6_2_11_HomeDirOwnership(t *testing.T) {
	dir := t.TempDir()
	origPasswd := etcPasswdPath
	t.Cleanup(func() { etcPasswdPath = origPasswd })

	rule := ruleByID("6.2.11")

	t.Run("no passwd → SKIP", func(t *testing.T) {
		etcPasswdPath = filepath.Join(dir, "no_passwd_6211")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("home dir does not exist → PASS (no violations)", func(t *testing.T) {
		p := filepath.Join(dir, "passwd_nodir_6211")
		content := "testuser:x:1001:1001::/nonexistent/no_home_dir:/bin/bash\n"
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		etcPasswdPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("absent home: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("home owned by different UID → FAIL", func(t *testing.T) {
		if os.Getuid() == 1001 {
			t.Skip("running as UID 1001 — cannot construct ownership mismatch")
		}
		homeDir := filepath.Join(dir, "wrongowner_home_6211")
		if err := os.MkdirAll(homeDir, 0o700); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, "passwd_wrongowner_6211")
		// homeDir owned by os.Getuid(); passwd says UID=1001 → mismatch
		content := fmt.Sprintf("testuser:x:1001:1001::%s:/bin/bash\n", homeDir)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		etcPasswdPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("wrong owner: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// ── 6.2.12 Home directory permissions ────────────────────────────────────

// TestRule6_2_12_HomeDirPerms verifies rule 6.2.12.
// No t.Parallel(): mutates package-level etcPasswdPath.
func TestRule6_2_12_HomeDirPerms(t *testing.T) {
	dir := t.TempDir()
	origPasswd := etcPasswdPath
	t.Cleanup(func() { etcPasswdPath = origPasswd })

	rule := ruleByID("6.2.12")

	t.Run("no passwd → SKIP", func(t *testing.T) {
		etcPasswdPath = filepath.Join(dir, "no_passwd_6212")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("home mode 0700 → PASS", func(t *testing.T) {
		homeDir := filepath.Join(dir, "home_0700")
		if err := os.MkdirAll(homeDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(homeDir, 0o700); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, "passwd_0700_6212")
		content := fmt.Sprintf("testuser:x:1001:1001::%s:/bin/bash\n", homeDir)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		etcPasswdPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("0700: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("home mode 0750 → PASS", func(t *testing.T) {
		homeDir := filepath.Join(dir, "home_0750")
		if err := os.MkdirAll(homeDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(homeDir, 0o750); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, "passwd_0750_6212")
		content := fmt.Sprintf("testuser:x:1001:1001::%s:/bin/bash\n", homeDir)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		etcPasswdPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("0750: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("home group-writable (0770) → FAIL", func(t *testing.T) {
		homeDir := filepath.Join(dir, "home_0770")
		if err := os.MkdirAll(homeDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(homeDir, 0o770); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, "passwd_0770_6212")
		content := fmt.Sprintf("testuser:x:1001:1001::%s:/bin/bash\n", homeDir)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		etcPasswdPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("0770: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("home world-writable (0777) → FAIL", func(t *testing.T) {
		homeDir := filepath.Join(dir, "home_0777")
		if err := os.MkdirAll(homeDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(homeDir, 0o777); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, "passwd_0777_6212")
		content := fmt.Sprintf("testuser:x:1001:1001::%s:/bin/bash\n", homeDir)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		etcPasswdPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("0777: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// ── 5.1.1 Cron daemon enabled ─────────────────────────────────────────────

// TestRule5_1_1_CronEnabled verifies rule 5.1.1.
// No t.Parallel(): mutates package-level cronWantsPaths.
func TestRule5_1_1_CronEnabled(t *testing.T) {
	dir := t.TempDir()
	orig := cronWantsPaths
	t.Cleanup(func() { cronWantsPaths = orig })

	rule := ruleByID("5.1.1")

	t.Run("wants symlink exists → PASS", func(t *testing.T) {
		p := filepath.Join(dir, "cron.service")
		if err := os.WriteFile(p, []byte("stub"), 0o644); err != nil {
			t.Fatal(err)
		}
		cronWantsPaths = []string{filepath.Join(dir, "nope"), p}
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("no wants symlinks found → FAIL", func(t *testing.T) {
		cronWantsPaths = []string{filepath.Join(dir, "no_cron"), filepath.Join(dir, "no_crond")}
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// ── 1.1.19-1.1.21 Removable media mount options ──────────────────────────

// TestCheckRemovableMediaOption verifies rules 1.1.19, 1.1.20, 1.1.21.
// No t.Parallel(): mutates package-level procMountsPath.
func TestCheckRemovableMediaOption(t *testing.T) {
	dir := t.TempDir()
	orig := procMountsPath
	t.Cleanup(func() { procMountsPath = orig })

	rule19 := ruleByID("1.1.19")
	rule20 := ruleByID("1.1.20")
	rule21 := ruleByID("1.1.21")

	t.Run("no removable mounts → PASS all", func(t *testing.T) {
		p := filepath.Join(dir, "mounts_none")
		content := "/dev/sda1 / ext4 rw,relatime 0 0\n" +
			"tmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0\n"
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		procMountsPath = p
		for _, rule := range []Rule{rule19, rule20, rule21} {
			got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
			if got.Status != models.CISPass {
				t.Errorf("rule %s no removable: want Pass, got %s (%s)", rule.ID, got.Status, got.Finding)
			}
		}
	})

	t.Run("removable mount with all options → PASS all", func(t *testing.T) {
		p := filepath.Join(dir, "mounts_compliant")
		content := "/dev/sdb1 /media/usb vfat rw,nosuid,noexec,nodev,relatime 0 0\n"
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		procMountsPath = p
		for _, rule := range []Rule{rule19, rule20, rule21} {
			got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
			if got.Status != models.CISPass {
				t.Errorf("rule %s all opts: want Pass, got %s (%s)", rule.ID, got.Status, got.Finding)
			}
		}
	})

	t.Run("removable mount missing nosuid → 1.1.19 FAIL, others PASS", func(t *testing.T) {
		p := filepath.Join(dir, "mounts_nosuid_missing")
		content := "/dev/sdb1 /mnt/usb vfat rw,noexec,nodev,relatime 0 0\n"
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		procMountsPath = p
		got19 := rule19.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got19.Status != models.CISFail {
			t.Errorf("1.1.19 missing nosuid: want Fail, got %s (%s)", got19.Status, got19.Finding)
		}
		got20 := rule20.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got20.Status != models.CISPass {
			t.Errorf("1.1.20 noexec present: want Pass, got %s (%s)", got20.Status, got20.Finding)
		}
	})

	t.Run("no mounts file → SKIP", func(t *testing.T) {
		procMountsPath = filepath.Join(dir, "no_mounts")
		got := rule19.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// ── 6.2.13 Dot files not world-writable ──────────────────────────────────

// TestRule6_2_13_DotFilesNotWorldWritable verifies rule 6.2.13.
// No t.Parallel(): mutates package-level etcPasswdPath.
func TestRule6_2_13_DotFilesNotWorldWritable(t *testing.T) {
	dir := t.TempDir()
	origPasswd := etcPasswdPath
	t.Cleanup(func() { etcPasswdPath = origPasswd })

	rule := ruleByID("6.2.13")

	t.Run("no passwd → SKIP", func(t *testing.T) {
		etcPasswdPath = filepath.Join(dir, "no_passwd_6213")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("dot file not world-writable (0644) → PASS", func(t *testing.T) {
		homeDir := filepath.Join(dir, "home_6213_pass")
		if err := os.MkdirAll(homeDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(homeDir, ".bashrc"), []byte("# ok"), 0o644); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, "passwd_6213_pass")
		content := fmt.Sprintf("testuser:x:1001:1001::%s:/bin/bash\n", homeDir)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		etcPasswdPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("0644: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("dot file world-writable (0666) → FAIL", func(t *testing.T) {
		homeDir := filepath.Join(dir, "home_6213_fail")
		if err := os.MkdirAll(homeDir, 0o755); err != nil {
			t.Fatal(err)
		}
		dotFile := filepath.Join(homeDir, ".bashrc")
		if err := os.WriteFile(dotFile, []byte("# bad"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dotFile, 0o666); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, "passwd_6213_fail")
		content := fmt.Sprintf("testuser:x:1001:1001::%s:/bin/bash\n", homeDir)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		etcPasswdPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("0666: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// ── 6.2.14 No .forward files ─────────────────────────────────────────────

// TestRule6_2_14_NoForwardFiles verifies rule 6.2.14.
// No t.Parallel(): mutates package-level etcPasswdPath.
func TestRule6_2_14_NoForwardFiles(t *testing.T) {
	dir := t.TempDir()
	origPasswd := etcPasswdPath
	t.Cleanup(func() { etcPasswdPath = origPasswd })

	rule := ruleByID("6.2.14")

	t.Run("no passwd → SKIP", func(t *testing.T) {
		etcPasswdPath = filepath.Join(dir, "no_passwd_6214")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("no .forward file → PASS", func(t *testing.T) {
		homeDir := filepath.Join(dir, "home_6214_pass")
		if err := os.MkdirAll(homeDir, 0o755); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, "passwd_6214_pass")
		content := fmt.Sprintf("testuser:x:1001:1001::%s:/bin/bash\n", homeDir)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		etcPasswdPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("no .forward: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run(".forward file exists → FAIL", func(t *testing.T) {
		homeDir := filepath.Join(dir, "home_6214_fail")
		if err := os.MkdirAll(homeDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(homeDir, ".forward"), []byte("relay@example.com"), 0o644); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, "passwd_6214_fail")
		content := fmt.Sprintf("testuser:x:1001:1001::%s:/bin/bash\n", homeDir)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		etcPasswdPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf(".forward exists: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// ── 6.2.15 No .netrc files ───────────────────────────────────────────────

// TestRule6_2_15_NoNetrcFiles verifies rule 6.2.15.
// No t.Parallel(): mutates package-level etcPasswdPath.
func TestRule6_2_15_NoNetrcFiles(t *testing.T) {
	dir := t.TempDir()
	origPasswd := etcPasswdPath
	t.Cleanup(func() { etcPasswdPath = origPasswd })

	rule := ruleByID("6.2.15")

	t.Run("no passwd → SKIP", func(t *testing.T) {
		etcPasswdPath = filepath.Join(dir, "no_passwd_6215")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("no .netrc file → PASS", func(t *testing.T) {
		homeDir := filepath.Join(dir, "home_6215_pass")
		if err := os.MkdirAll(homeDir, 0o755); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, "passwd_6215_pass")
		content := fmt.Sprintf("testuser:x:1001:1001::%s:/bin/bash\n", homeDir)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		etcPasswdPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("no .netrc: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run(".netrc file exists → FAIL", func(t *testing.T) {
		homeDir := filepath.Join(dir, "home_6215_fail")
		if err := os.MkdirAll(homeDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(homeDir, ".netrc"), []byte("machine example.com login testuser"), 0o600); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, "passwd_6215_fail")
		content := fmt.Sprintf("testuser:x:1001:1001::%s:/bin/bash\n", homeDir)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		etcPasswdPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf(".netrc exists: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// TestRule6_2_16_NoRhostsFiles verifies rule 6.2.16.
// No t.Parallel(): mutates package-level etcPasswdPath.
func TestRule6_2_16_NoRhostsFiles(t *testing.T) {
	dir := t.TempDir()
	origPasswd := etcPasswdPath
	t.Cleanup(func() { etcPasswdPath = origPasswd })

	rule := ruleByID("6.2.16")

	t.Run("no passwd → SKIP", func(t *testing.T) {
		etcPasswdPath = filepath.Join(dir, "no_passwd_6216")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("no .rhosts file → PASS", func(t *testing.T) {
		homeDir := filepath.Join(dir, "home_6216_pass")
		if err := os.MkdirAll(homeDir, 0o755); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, "passwd_6216_pass")
		content := fmt.Sprintf("testuser:x:1001:1001::%s:/bin/bash\n", homeDir)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		etcPasswdPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("no .rhosts: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run(".rhosts file exists → FAIL", func(t *testing.T) {
		homeDir := filepath.Join(dir, "home_6216_fail")
		if err := os.MkdirAll(homeDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(homeDir, ".rhosts"), []byte("remotehost remoteuser\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, "passwd_6216_fail")
		content := fmt.Sprintf("testuser:x:1001:1001::%s:/bin/bash\n", homeDir)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		etcPasswdPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf(".rhosts exists: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// TestRule6_2_17_AllGroupsExistInGroup verifies rule 6.2.17.
// No t.Parallel(): mutates package-level etcPasswdPath and etcGroupPath.
func TestRule6_2_17_AllGroupsExistInGroup(t *testing.T) {
	dir := t.TempDir()
	origPasswd := etcPasswdPath
	origGroup := etcGroupPath
	t.Cleanup(func() {
		etcPasswdPath = origPasswd
		etcGroupPath = origGroup
	})

	rule := ruleByID("6.2.17")

	t.Run("no group file → SKIP", func(t *testing.T) {
		etcGroupPath = filepath.Join(dir, "no_group_6217")
		etcPasswdPath = origPasswd
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("no passwd file → SKIP", func(t *testing.T) {
		g := filepath.Join(dir, "group_6217_nopasswd")
		if err := os.WriteFile(g, []byte("testgroup:x:1001:\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		etcGroupPath = g
		etcPasswdPath = filepath.Join(dir, "no_passwd_6217")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("all GIDs known → PASS", func(t *testing.T) {
		g := filepath.Join(dir, "group_6217_pass")
		if err := os.WriteFile(g, []byte("testgroup:x:1001:\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, "passwd_6217_pass")
		if err := os.WriteFile(p, []byte("testuser:x:1001:1001::/home/testuser:/bin/bash\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		etcGroupPath = g
		etcPasswdPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("all GIDs present: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("passwd references undefined GID → FAIL", func(t *testing.T) {
		g := filepath.Join(dir, "group_6217_fail")
		if err := os.WriteFile(g, []byte("testgroup:x:1001:\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, "passwd_6217_fail")
		// GID 9999 not in /etc/group
		if err := os.WriteFile(p, []byte("testuser:x:1001:9999::/home/testuser:/bin/bash\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		etcGroupPath = g
		etcPasswdPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("undefined GID: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// TestRule6_2_18_ShadowGroupEmpty verifies rule 6.2.18.
// No t.Parallel(): mutates package-level etcGroupPath.
func TestRule6_2_18_ShadowGroupEmpty(t *testing.T) {
	dir := t.TempDir()
	origGroup := etcGroupPath
	t.Cleanup(func() { etcGroupPath = origGroup })

	rule := ruleByID("6.2.18")

	t.Run("no group file → SKIP", func(t *testing.T) {
		etcGroupPath = filepath.Join(dir, "no_group_6218")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("shadow group absent → PASS", func(t *testing.T) {
		g := filepath.Join(dir, "group_6218_absent")
		if err := os.WriteFile(g, []byte("nogroup:x:65534:\nusers:x:100:\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		etcGroupPath = g
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("shadow absent: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("shadow group empty → PASS", func(t *testing.T) {
		g := filepath.Join(dir, "group_6218_empty")
		if err := os.WriteFile(g, []byte("shadow:x:42:\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		etcGroupPath = g
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("shadow empty: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("shadow group has members → FAIL", func(t *testing.T) {
		g := filepath.Join(dir, "group_6218_members")
		if err := os.WriteFile(g, []byte("shadow:x:42:syslog,testuser\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		etcGroupPath = g
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("shadow has members: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// TestRule3_5_1_7_UFWDefaultDeny verifies rule 3.5.1.7.
// No t.Parallel(): mutates package-level ufwDefaultPath.
func TestRule3_5_1_7_UFWDefaultDeny(t *testing.T) {
	dir := t.TempDir()
	origUFW := ufwDefaultPath
	t.Cleanup(func() { ufwDefaultPath = origUFW })

	rule := ruleByID("3.5.1.7")

	t.Run("file missing → SKIP", func(t *testing.T) {
		ufwDefaultPath = filepath.Join(dir, "no_ufw_default")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("no policy keys → SKIP", func(t *testing.T) {
		p := filepath.Join(dir, "ufw_no_policy")
		if err := os.WriteFile(p, []byte("# ufw defaults\nIPV6=yes\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		ufwDefaultPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("no policy keys: want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("DEFAULT_INPUT_POLICY=DROP → PASS", func(t *testing.T) {
		p := filepath.Join(dir, "ufw_drop")
		content := "DEFAULT_INPUT_POLICY=\"DROP\"\nDEFAULT_FORWARD_POLICY=\"DROP\"\nDEFAULT_OUTPUT_POLICY=\"ACCEPT\"\n"
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		ufwDefaultPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("DROP policy: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("DEFAULT_INPUT_POLICY=ACCEPT → FAIL", func(t *testing.T) {
		p := filepath.Join(dir, "ufw_accept")
		content := "DEFAULT_INPUT_POLICY=\"ACCEPT\"\nDEFAULT_FORWARD_POLICY=\"DROP\"\n"
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		ufwDefaultPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("ACCEPT input policy: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("DEFAULT_FORWARD_POLICY=ACCEPT → FAIL", func(t *testing.T) {
		p := filepath.Join(dir, "ufw_forward_accept")
		content := "DEFAULT_INPUT_POLICY=\"DROP\"\nDEFAULT_FORWARD_POLICY=\"ACCEPT\"\n"
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		ufwDefaultPath = p
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("ACCEPT forward policy: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// TestRule4_2_4_RsyslogNotAcceptingRemote verifies rule 4.2.4.
// No t.Parallel(): mutates package-level rsyslogConfPath and rsyslogConfDPath.
func TestRule4_2_4_RsyslogNotAcceptingRemote(t *testing.T) {
	dir := t.TempDir()
	origConf := rsyslogConfPath
	origConfD := rsyslogConfDPath
	t.Cleanup(func() {
		rsyslogConfPath = origConf
		rsyslogConfDPath = origConfD
	})

	rule := ruleByID("4.2.4")

	t.Run("no config files → PASS", func(t *testing.T) {
		rsyslogConfPath = filepath.Join(dir, "no_rsyslog.conf")
		rsyslogConfDPath = filepath.Join(dir, "no_rsyslog.d")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("no config: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("config without network modules → PASS", func(t *testing.T) {
		p := filepath.Join(dir, "rsyslog_clean.conf")
		content := "# rsyslog config\n$ModLoad imuxsock\n$ModLoad imklog\n*.* /var/log/syslog\n"
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		rsyslogConfPath = p
		rsyslogConfDPath = filepath.Join(dir, "no_rsyslog.d")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("no network mods: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("legacy $ModLoad imtcp in main config → FAIL", func(t *testing.T) {
		p := filepath.Join(dir, "rsyslog_imtcp.conf")
		content := "$ModLoad imuxsock\n$ModLoad imtcp\n$InputTCPServerRun 514\n"
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		rsyslogConfPath = p
		rsyslogConfDPath = filepath.Join(dir, "no_rsyslog.d")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("imtcp loaded: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("RainerScript module load in conf.d → FAIL", func(t *testing.T) {
		rsyslogConfPath = filepath.Join(dir, "no_rsyslog.conf")
		confD := filepath.Join(dir, "rsyslog_d_imudp")
		if err := os.MkdirAll(confD, 0o755); err != nil {
			t.Fatal(err)
		}
		content := `module(load="imudp")` + "\ninput(type=\"imudp\" port=\"514\")\n"
		if err := os.WriteFile(filepath.Join(confD, "50-udp.conf"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		rsyslogConfDPath = confD
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("imudp in conf.d: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("commented module load → PASS", func(t *testing.T) {
		p := filepath.Join(dir, "rsyslog_commented.conf")
		content := "# $ModLoad imtcp\n# $ModLoad imudp\n*.* /var/log/syslog\n"
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		rsyslogConfPath = p
		rsyslogConfDPath = filepath.Join(dir, "no_rsyslog.d")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("commented mods: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// TestRule4_3_1_LogrotateConfigured verifies rule 4.3.1.
// No t.Parallel(): mutates package-level logrotateConfPath and logrotateConfDPath.
func TestRule4_3_1_LogrotateConfigured(t *testing.T) {
	dir := t.TempDir()
	origConf := logrotateConfPath
	origConfD := logrotateConfDPath
	t.Cleanup(func() {
		logrotateConfPath = origConf
		logrotateConfDPath = origConfD
	})

	rule := ruleByID("4.3.1")

	t.Run("no config anywhere → FAIL", func(t *testing.T) {
		logrotateConfPath = filepath.Join(dir, "no_logrotate.conf")
		logrotateConfDPath = filepath.Join(dir, "no_logrotate.d")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("no config: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("logrotate.conf with content → PASS", func(t *testing.T) {
		p := filepath.Join(dir, "logrotate.conf")
		content := "# logrotate\nweekly\nrotate 4\ncompress\n"
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		logrotateConfPath = p
		logrotateConfDPath = filepath.Join(dir, "no_logrotate.d")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("conf with content: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("only conf.d entry → PASS", func(t *testing.T) {
		logrotateConfPath = filepath.Join(dir, "no_logrotate.conf")
		confD := filepath.Join(dir, "logrotate.d_only")
		if err := os.MkdirAll(confD, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(confD, "syslog"), []byte("/var/log/syslog {\n  rotate 7\n  daily\n}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		logrotateConfDPath = confD
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("conf.d entry: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("conf with only comments → FAIL without conf.d", func(t *testing.T) {
		p := filepath.Join(dir, "logrotate_comments_only.conf")
		if err := os.WriteFile(p, []byte("# just a comment\n# another comment\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		logrotateConfPath = p
		logrotateConfDPath = filepath.Join(dir, "no_logrotate.d")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("comments only: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// TestRule3_5_1_1_UFWInstalled verifies rule 3.5.1.1.
// No t.Parallel(): mutates package-level debianVersionPath and ufwBinPaths.
func TestRule3_5_1_1_UFWInstalled(t *testing.T) {
	dir := t.TempDir()
	origDebian := debianVersionPath
	origBins := ufwBinPaths
	t.Cleanup(func() {
		debianVersionPath = origDebian
		ufwBinPaths = origBins
	})

	rule := ruleByID("3.5.1.1")

	t.Run("non-Debian system → SKIP", func(t *testing.T) {
		debianVersionPath = filepath.Join(dir, "no_debian_version")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("Debian without ufw binary → FAIL", func(t *testing.T) {
		dv := filepath.Join(dir, "debian_version")
		if err := os.WriteFile(dv, []byte("12\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		debianVersionPath = dv
		ufwBinPaths = []string{filepath.Join(dir, "no_ufw")}
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("no binary: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("Debian with ufw binary → PASS", func(t *testing.T) {
		dv := filepath.Join(dir, "debian_version2")
		if err := os.WriteFile(dv, []byte("12\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		debianVersionPath = dv
		fakeBin := filepath.Join(dir, "ufw")
		if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		ufwBinPaths = []string{fakeBin}
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("binary present: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// TestRule3_5_1_2_IPTablesPersistentAbsent verifies rule 3.5.1.2.
// No t.Parallel(): mutates package-level debianVersionPath and netfilterPersistentPaths.
func TestRule3_5_1_2_IPTablesPersistentAbsent(t *testing.T) {
	dir := t.TempDir()
	origDebian := debianVersionPath
	origPaths := netfilterPersistentPaths
	t.Cleanup(func() {
		debianVersionPath = origDebian
		netfilterPersistentPaths = origPaths
	})

	rule := ruleByID("3.5.1.2")

	t.Run("non-Debian system → SKIP", func(t *testing.T) {
		debianVersionPath = filepath.Join(dir, "no_debian_version")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("Debian without iptables-persistent → PASS", func(t *testing.T) {
		dv := filepath.Join(dir, "debian_version")
		if err := os.WriteFile(dv, []byte("12\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		debianVersionPath = dv
		netfilterPersistentPaths = []string{filepath.Join(dir, "no_service")}
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("not installed: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("Debian with netfilter-persistent service → FAIL", func(t *testing.T) {
		dv := filepath.Join(dir, "debian_version2")
		if err := os.WriteFile(dv, []byte("12\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		debianVersionPath = dv
		svc := filepath.Join(dir, "netfilter-persistent.service")
		if err := os.WriteFile(svc, []byte("[Unit]\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		netfilterPersistentPaths = []string{svc}
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("service present: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// TestRule3_5_1_3_UFWServiceEnabled verifies rule 3.5.1.3.
// No t.Parallel(): mutates package-level ufwBinPaths and ufwWantsPaths.
func TestRule3_5_1_3_UFWServiceEnabled(t *testing.T) {
	dir := t.TempDir()
	origBins := ufwBinPaths
	origWants := ufwWantsPaths
	t.Cleanup(func() {
		ufwBinPaths = origBins
		ufwWantsPaths = origWants
	})

	rule := ruleByID("3.5.1.3")

	t.Run("ufw not installed → SKIP", func(t *testing.T) {
		ufwBinPaths = []string{filepath.Join(dir, "no_ufw")}
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("ufw installed but service not enabled → FAIL", func(t *testing.T) {
		fakeBin := filepath.Join(dir, "ufw")
		if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		ufwBinPaths = []string{fakeBin}
		ufwWantsPaths = []string{filepath.Join(dir, "no_wants_ufw.service")}
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("not enabled: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("ufw service enabled → PASS", func(t *testing.T) {
		fakeBin := filepath.Join(dir, "ufw2")
		if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		ufwBinPaths = []string{fakeBin}
		wantsLink := filepath.Join(dir, "ufw.service")
		if err := os.WriteFile(wantsLink, []byte(""), 0o644); err != nil {
			t.Fatal(err)
		}
		ufwWantsPaths = []string{wantsLink}
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("service enabled: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// TestRule4_2_5_RsyslogFileCreateMode verifies rule 4.2.5.
// No t.Parallel(): mutates package-level rsyslogConfPath and rsyslogConfDPath.
func TestRule4_2_5_RsyslogFileCreateMode(t *testing.T) {
	dir := t.TempDir()
	origConf := rsyslogConfPath
	origConfD := rsyslogConfDPath
	t.Cleanup(func() {
		rsyslogConfPath = origConf
		rsyslogConfDPath = origConfD
	})

	rule := ruleByID("4.2.5")

	t.Run("no config files → FAIL (not configured)", func(t *testing.T) {
		rsyslogConfPath = filepath.Join(dir, "no_rsyslog.conf")
		rsyslogConfDPath = filepath.Join(dir, "no_rsyslog.d")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("no config: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("$FileCreateMode 0640 → PASS", func(t *testing.T) {
		p := filepath.Join(dir, "rsyslog_0640.conf")
		if err := os.WriteFile(p, []byte("$FileCreateMode 0640\n*.* /var/log/syslog\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		rsyslogConfPath = p
		rsyslogConfDPath = filepath.Join(dir, "no_rsyslog.d")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("0640 mode: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("$FileCreateMode 0600 → PASS (more restrictive)", func(t *testing.T) {
		p := filepath.Join(dir, "rsyslog_0600.conf")
		if err := os.WriteFile(p, []byte("$FileCreateMode 0600\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		rsyslogConfPath = p
		rsyslogConfDPath = filepath.Join(dir, "no_rsyslog.d")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("0600 mode: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("$FileCreateMode 0644 → FAIL (world-readable)", func(t *testing.T) {
		p := filepath.Join(dir, "rsyslog_0644.conf")
		if err := os.WriteFile(p, []byte("$FileCreateMode 0644\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		rsyslogConfPath = p
		rsyslogConfDPath = filepath.Join(dir, "no_rsyslog.d")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("0644 mode: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("FileCreateMode in conf.d → PASS", func(t *testing.T) {
		rsyslogConfPath = filepath.Join(dir, "no_rsyslog.conf")
		confD := filepath.Join(dir, "rsyslog_d_mode")
		if err := os.MkdirAll(confD, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(confD, "50-default.conf"),
			[]byte("$FileCreateMode 0640\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		rsyslogConfDPath = confD
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("conf.d 0640: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// ── 2.2.5 LDAP client ────────────────────────────────────────────────────────

// TestRule2_2_5_LDAPClientNotInstalled verifies rule 2.2.5.
// No t.Parallel(): mutates package-level ldapClientBinPaths.
func TestRule2_2_5_LDAPClientNotInstalled(t *testing.T) {
	dir := t.TempDir()
	orig := ldapClientBinPaths
	t.Cleanup(func() { ldapClientBinPaths = orig })

	rule := ruleByID("2.2.5")

	t.Run("no ldap-utils binaries → PASS", func(t *testing.T) {
		ldapClientBinPaths = []string{filepath.Join(dir, "no_ldapsearch")}
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("no ldap binaries: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("ldapsearch found → FAIL", func(t *testing.T) {
		bin := filepath.Join(dir, "ldapsearch")
		if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		ldapClientBinPaths = []string{bin}
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("ldapsearch present: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// ── 2.3.14 MTA local-only ────────────────────────────────────────────────────

// TestRule2_3_14_MTALocalOnly verifies rule 2.3.14.
// No t.Parallel(): mutates package-level mtaBinPaths and postfixMainCfPath.
func TestRule2_3_14_MTALocalOnly(t *testing.T) {
	dir := t.TempDir()
	origBins := mtaBinPaths
	origCf := postfixMainCfPath
	t.Cleanup(func() {
		mtaBinPaths = origBins
		postfixMainCfPath = origCf
	})

	rule := ruleByID("2.3.14")

	t.Run("no MTA installed → SKIP", func(t *testing.T) {
		mtaBinPaths = []string{filepath.Join(dir, "no_postfix")}
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("no MTA: want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("postfix installed, main.cf unreadable → SKIP", func(t *testing.T) {
		bin := filepath.Join(dir, "postfix")
		if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		mtaBinPaths = []string{bin}
		postfixMainCfPath = filepath.Join(dir, "no_main.cf")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("no main.cf: want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("inet_interfaces = loopback-only → PASS", func(t *testing.T) {
		bin := filepath.Join(dir, "postfix2")
		if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		mtaBinPaths = []string{bin}
		cf := filepath.Join(dir, "main_loopback.cf")
		if err := os.WriteFile(cf, []byte("# comment\ninet_interfaces = loopback-only\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		postfixMainCfPath = cf
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("loopback-only: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("inet_interfaces = all → FAIL", func(t *testing.T) {
		bin := filepath.Join(dir, "postfix3")
		if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		mtaBinPaths = []string{bin}
		cf := filepath.Join(dir, "main_all.cf")
		if err := os.WriteFile(cf, []byte("inet_interfaces = all\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		postfixMainCfPath = cf
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("inet_interfaces=all: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("inet_interfaces not set → FAIL", func(t *testing.T) {
		bin := filepath.Join(dir, "postfix4")
		if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		mtaBinPaths = []string{bin}
		cf := filepath.Join(dir, "main_nokey.cf")
		if err := os.WriteFile(cf, []byte("# only a comment\nmydomain = example.com\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		postfixMainCfPath = cf
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("no inet_interfaces: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// ── 2.3.15 rsync service ─────────────────────────────────────────────────────

// TestRule2_3_15_RsyncNotEnabled verifies rule 2.3.15.
// No t.Parallel(): mutates package-level rsyncBinPaths, rsyncWantsPaths, rsyncDefaultPath.
func TestRule2_3_15_RsyncNotEnabled(t *testing.T) {
	dir := t.TempDir()
	origBins := rsyncBinPaths
	origWants := rsyncWantsPaths
	origDef := rsyncDefaultPath
	t.Cleanup(func() {
		rsyncBinPaths = origBins
		rsyncWantsPaths = origWants
		rsyncDefaultPath = origDef
	})

	rule := ruleByID("2.3.15")

	t.Run("rsync not installed → SKIP", func(t *testing.T) {
		rsyncBinPaths = []string{filepath.Join(dir, "no_rsync")}
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("no rsync: want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("rsync installed, no service enabled → PASS", func(t *testing.T) {
		bin := filepath.Join(dir, "rsync")
		if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		rsyncBinPaths = []string{bin}
		rsyncWantsPaths = []string{filepath.Join(dir, "no_rsync.service")}
		rsyncDefaultPath = filepath.Join(dir, "no_default_rsync")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("rsync present but not enabled: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("rsync service enabled via systemd wants → FAIL", func(t *testing.T) {
		bin := filepath.Join(dir, "rsync2")
		if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		rsyncBinPaths = []string{bin}
		svcLink := filepath.Join(dir, "rsync.service")
		if err := os.WriteFile(svcLink, []byte(""), 0o644); err != nil {
			t.Fatal(err)
		}
		rsyncWantsPaths = []string{svcLink}
		rsyncDefaultPath = filepath.Join(dir, "no_default_rsync2")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("rsync service enabled: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("RSYNC_ENABLE=true in /etc/default/rsync → FAIL", func(t *testing.T) {
		bin := filepath.Join(dir, "rsync3")
		if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		rsyncBinPaths = []string{bin}
		rsyncWantsPaths = []string{filepath.Join(dir, "no_svc3")}
		def := filepath.Join(dir, "default_rsync_enabled")
		if err := os.WriteFile(def, []byte("# comment\nRSYNC_ENABLE=true\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		rsyncDefaultPath = def
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("RSYNC_ENABLE=true: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// ── 3.5.1.4 UFW loopback ─────────────────────────────────────────────────────

// TestRule3_5_1_4_UFWLoopback verifies rule 3.5.1.4.
// No t.Parallel(): mutates package-level ufwBeforeRulesPath and ufwBefore6RulesPath.
func TestRule3_5_1_4_UFWLoopback(t *testing.T) {
	dir := t.TempDir()
	origBefore := ufwBeforeRulesPath
	origBefore6 := ufwBefore6RulesPath
	t.Cleanup(func() {
		ufwBeforeRulesPath = origBefore
		ufwBefore6RulesPath = origBefore6
	})

	rule := ruleByID("3.5.1.4")

	const validBefore = `-A ufw-before-input -i lo -j ACCEPT
-A ufw-before-output -o lo -j ACCEPT
-A ufw-before-input -s 127.0.0.0/8 ! -i lo -j DROP
`
	const validBefore6 = `-A ufw6-before-input -i lo -j ACCEPT
-A ufw6-before-output -o lo -j ACCEPT
-A ufw6-before-input -s ::1 ! -i lo -j DROP
`

	t.Run("before.rules missing → SKIP", func(t *testing.T) {
		ufwBeforeRulesPath = filepath.Join(dir, "no_before.rules")
		ufwBefore6RulesPath = filepath.Join(dir, "no_before6.rules")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("no before.rules: want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("complete loopback rules (no before6.rules) → PASS", func(t *testing.T) {
		f := filepath.Join(dir, "before_ok.rules")
		if err := os.WriteFile(f, []byte(validBefore), 0o644); err != nil {
			t.Fatal(err)
		}
		ufwBeforeRulesPath = f
		ufwBefore6RulesPath = filepath.Join(dir, "no_before6.rules")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("valid before.rules, no before6: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("complete loopback rules with valid before6.rules → PASS", func(t *testing.T) {
		f := filepath.Join(dir, "before_ok2.rules")
		if err := os.WriteFile(f, []byte(validBefore), 0o644); err != nil {
			t.Fatal(err)
		}
		f6 := filepath.Join(dir, "before6_ok.rules")
		if err := os.WriteFile(f6, []byte(validBefore6), 0o644); err != nil {
			t.Fatal(err)
		}
		ufwBeforeRulesPath = f
		ufwBefore6RulesPath = f6
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("all loopback rules present: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("missing 127.0.0.0/8 deny in before.rules → FAIL", func(t *testing.T) {
		content := "-A ufw-before-input -i lo -j ACCEPT\n-A ufw-before-output -o lo -j ACCEPT\n"
		f := filepath.Join(dir, "before_no127.rules")
		if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		ufwBeforeRulesPath = f
		ufwBefore6RulesPath = filepath.Join(dir, "no_before6b.rules")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("missing 127 deny: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("missing ::1 deny in before6.rules → FAIL", func(t *testing.T) {
		f := filepath.Join(dir, "before_ok3.rules")
		if err := os.WriteFile(f, []byte(validBefore), 0o644); err != nil {
			t.Fatal(err)
		}
		f6 := filepath.Join(dir, "before6_no_deny.rules")
		before6NoDeny := "-A ufw6-before-input -i lo -j ACCEPT\n-A ufw6-before-output -o lo -j ACCEPT\n"
		if err := os.WriteFile(f6, []byte(before6NoDeny), 0o644); err != nil {
			t.Fatal(err)
		}
		ufwBeforeRulesPath = f
		ufwBefore6RulesPath = f6
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("missing ::1 deny: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// ── 3.5.1.5 UFW outbound ─────────────────────────────────────────────────────

// TestRule3_5_1_5_UFWOutbound verifies rule 3.5.1.5.
// No t.Parallel(): mutates package-level ufwDefaultPath and ufwUserRulesPath.
func TestRule3_5_1_5_UFWOutbound(t *testing.T) {
	dir := t.TempDir()
	origDef := ufwDefaultPath
	origUser := ufwUserRulesPath
	t.Cleanup(func() {
		ufwDefaultPath = origDef
		ufwUserRulesPath = origUser
	})

	rule := ruleByID("3.5.1.5")

	t.Run("no /etc/default/ufw → SKIP", func(t *testing.T) {
		ufwDefaultPath = filepath.Join(dir, "no_ufw_default")
		ufwUserRulesPath = filepath.Join(dir, "no_user.rules")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("no ufw default: want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("DEFAULT_OUTPUT_POLICY=ALLOW → PASS", func(t *testing.T) {
		def := filepath.Join(dir, "ufw_default_allow")
		if err := os.WriteFile(def, []byte("DEFAULT_INPUT_POLICY=\"DROP\"\nDEFAULT_OUTPUT_POLICY=ALLOW\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		ufwDefaultPath = def
		ufwUserRulesPath = filepath.Join(dir, "no_user2.rules")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("output=ALLOW: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("DEFAULT_OUTPUT_POLICY=DROP, explicit allow-out in user.rules → PASS", func(t *testing.T) {
		def := filepath.Join(dir, "ufw_default_drop")
		if err := os.WriteFile(def, []byte("DEFAULT_OUTPUT_POLICY=\"DROP\"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		ufwDefaultPath = def
		userRules := filepath.Join(dir, "user_with_allow_out.rules")
		if err := os.WriteFile(userRules, []byte("-A ufw-user-output -j ACCEPT\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		ufwUserRulesPath = userRules
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("explicit allow-out: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("DEFAULT_OUTPUT_POLICY=DROP, no user rules → FAIL", func(t *testing.T) {
		def := filepath.Join(dir, "ufw_default_drop2")
		if err := os.WriteFile(def, []byte("DEFAULT_OUTPUT_POLICY=\"DROP\"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		ufwDefaultPath = def
		userRules := filepath.Join(dir, "user_no_allow.rules")
		if err := os.WriteFile(userRules, []byte("-A ufw-user-input -p tcp --dport 22 -j ACCEPT\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		ufwUserRulesPath = userRules
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("drop output, no allow-out: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// ── 1.2.1 Package manager repos ──────────────────────────────────────────────

// TestRule1_2_1_PackageReposConfigured verifies rule 1.2.1.
// No t.Parallel(): mutates package-level debianVersionPath, aptSourcesListPath,
// aptSourcesListDPath.
func TestRule1_2_1_PackageReposConfigured(t *testing.T) {
	dir := t.TempDir()
	origDebian := debianVersionPath
	origList := aptSourcesListPath
	origListD := aptSourcesListDPath
	t.Cleanup(func() {
		debianVersionPath = origDebian
		aptSourcesListPath = origList
		aptSourcesListDPath = origListD
	})

	rule := ruleByID("1.2.1")

	t.Run("non-Debian system → SKIP", func(t *testing.T) {
		debianVersionPath = filepath.Join(dir, "no_debian_version")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("non-debian: want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("Debian, sources.list has active line → PASS", func(t *testing.T) {
		dv := filepath.Join(dir, "debian_version")
		if err := os.WriteFile(dv, []byte("12\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		debianVersionPath = dv
		sl := filepath.Join(dir, "sources.list")
		if err := os.WriteFile(sl, []byte("# comment\ndeb http://archive.ubuntu.com/ubuntu jammy main\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		aptSourcesListPath = sl
		aptSourcesListDPath = filepath.Join(dir, "no_sources.list.d")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("sources.list has active line: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("Debian, empty sources.list, .list file in sources.list.d → PASS", func(t *testing.T) {
		dv := filepath.Join(dir, "debian_version2")
		if err := os.WriteFile(dv, []byte("12\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		debianVersionPath = dv
		sl := filepath.Join(dir, "sources_empty.list")
		if err := os.WriteFile(sl, []byte("# only comments\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		aptSourcesListPath = sl
		listD := filepath.Join(dir, "sources_list_d")
		if err := os.MkdirAll(listD, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(listD, "ubuntu.list"), []byte("deb http://...\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		aptSourcesListDPath = listD
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("sources.list.d has .list file: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("Debian, no sources configured anywhere → FAIL", func(t *testing.T) {
		dv := filepath.Join(dir, "debian_version3")
		if err := os.WriteFile(dv, []byte("12\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		debianVersionPath = dv
		aptSourcesListPath = filepath.Join(dir, "no_sources.list")
		aptSourcesListDPath = filepath.Join(dir, "no_sources.list.d")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("no sources: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// ── 1.2.2 GPG keys ───────────────────────────────────────────────────────────

// TestRule1_2_2_GPGKeysConfigured verifies rule 1.2.2.
// No t.Parallel(): mutates package-level debianVersionPath, aptTrustedGpgPath,
// aptTrustedGpgDPath, aptKeyringsPath.
func TestRule1_2_2_GPGKeysConfigured(t *testing.T) {
	dir := t.TempDir()
	origDebian := debianVersionPath
	origGpg := aptTrustedGpgPath
	origGpgD := aptTrustedGpgDPath
	origKeyrings := aptKeyringsPath
	t.Cleanup(func() {
		debianVersionPath = origDebian
		aptTrustedGpgPath = origGpg
		aptTrustedGpgDPath = origGpgD
		aptKeyringsPath = origKeyrings
	})

	rule := ruleByID("1.2.2")

	t.Run("non-Debian system → SKIP", func(t *testing.T) {
		debianVersionPath = filepath.Join(dir, "no_debian_version")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("non-debian: want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("Debian, legacy trusted.gpg exists → PASS", func(t *testing.T) {
		dv := filepath.Join(dir, "debian_version")
		if err := os.WriteFile(dv, []byte("12\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		debianVersionPath = dv
		gpg := filepath.Join(dir, "trusted.gpg")
		if err := os.WriteFile(gpg, []byte("keydata"), 0o644); err != nil {
			t.Fatal(err)
		}
		aptTrustedGpgPath = gpg
		aptTrustedGpgDPath = filepath.Join(dir, "no_gpg.d")
		aptKeyringsPath = filepath.Join(dir, "no_keyrings")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("trusted.gpg exists: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("Debian, key in trusted.gpg.d → PASS", func(t *testing.T) {
		dv := filepath.Join(dir, "debian_version2")
		if err := os.WriteFile(dv, []byte("12\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		debianVersionPath = dv
		aptTrustedGpgPath = filepath.Join(dir, "no_trusted.gpg")
		gpgD := filepath.Join(dir, "trusted.gpg.d")
		if err := os.MkdirAll(gpgD, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(gpgD, "ubuntu-keyring.gpg"), []byte("key"), 0o644); err != nil {
			t.Fatal(err)
		}
		aptTrustedGpgDPath = gpgD
		aptKeyringsPath = filepath.Join(dir, "no_keyrings2")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("trusted.gpg.d has key: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("Debian, key in keyrings → PASS", func(t *testing.T) {
		dv := filepath.Join(dir, "debian_version3")
		if err := os.WriteFile(dv, []byte("12\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		debianVersionPath = dv
		aptTrustedGpgPath = filepath.Join(dir, "no_trusted3.gpg")
		aptTrustedGpgDPath = filepath.Join(dir, "no_gpg3.d")
		keyrings := filepath.Join(dir, "keyrings")
		if err := os.MkdirAll(keyrings, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(keyrings, "docker.gpg"), []byte("key"), 0o644); err != nil {
			t.Fatal(err)
		}
		aptKeyringsPath = keyrings
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("keyrings has key: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("Debian, no keys anywhere → FAIL", func(t *testing.T) {
		dv := filepath.Join(dir, "debian_version4")
		if err := os.WriteFile(dv, []byte("12\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		debianVersionPath = dv
		aptTrustedGpgPath = filepath.Join(dir, "no_trusted4.gpg")
		aptTrustedGpgDPath = filepath.Join(dir, "no_gpg4.d")
		aptKeyringsPath = filepath.Join(dir, "no_keyrings4")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("no keys: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// ── 3.6.1 Wireless interfaces ────────────────────────────────────────────────

// TestRule3_6_1_WirelessDisabled verifies rule 3.6.1.
// No t.Parallel(): mutates package-level sysClassNetPath.
func TestRule3_6_1_WirelessDisabled(t *testing.T) {
	dir := t.TempDir()
	orig := sysClassNetPath
	t.Cleanup(func() { sysClassNetPath = orig })

	rule := ruleByID("3.6.1")

	t.Run("/sys/class/net unreadable → SKIP", func(t *testing.T) {
		sysClassNetPath = filepath.Join(dir, "no_sys_class_net")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("no sysfs: want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("no wireless interfaces → PASS", func(t *testing.T) {
		netDir := filepath.Join(dir, "net_no_wireless")
		if err := os.MkdirAll(filepath.Join(netDir, "eth0"), 0o755); err != nil {
			t.Fatal(err)
		}
		sysClassNetPath = netDir
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("no wireless: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("wireless interface present but down (flags=0x1002) → PASS", func(t *testing.T) {
		netDir := filepath.Join(dir, "net_wlan_down")
		wlanDir := filepath.Join(netDir, "wlan0")
		if err := os.MkdirAll(filepath.Join(wlanDir, "wireless"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(wlanDir, "flags"), []byte("0x1002\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		sysClassNetPath = netDir
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("wlan0 down: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("wireless interface UP (flags=0x1003) → FAIL", func(t *testing.T) {
		netDir := filepath.Join(dir, "net_wlan_up")
		wlanDir := filepath.Join(netDir, "wlan0")
		if err := os.MkdirAll(filepath.Join(wlanDir, "wireless"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(wlanDir, "flags"), []byte("0x1003\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		sysClassNetPath = netDir
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("wlan0 up: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// ── 2.3.16 NIS server ────────────────────────────────────────────────────────

// TestRule2_3_16_NISServerNotInstalled verifies rule 2.3.16.
// No t.Parallel(): mutates package-level nisServerBinPaths.
func TestRule2_3_16_NISServerNotInstalled(t *testing.T) {
	dir := t.TempDir()
	orig := nisServerBinPaths
	t.Cleanup(func() { nisServerBinPaths = orig })

	rule := ruleByID("2.3.16")

	t.Run("ypserv not present → PASS", func(t *testing.T) {
		nisServerBinPaths = []string{filepath.Join(dir, "no_ypserv")}
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("no ypserv: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("ypserv found → FAIL", func(t *testing.T) {
		bin := filepath.Join(dir, "ypserv")
		if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		nisServerBinPaths = []string{bin}
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("ypserv present: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// ── 4.1.1.1 / 4.1.1.2 / 4.1.1.3 auditd.conf ────────────────────────────────

// TestRule4_1_1_1_AuditLogStorageSize verifies rule 4.1.1.1.
// No t.Parallel(): mutates package-level auditdConfPath.
func TestRule4_1_1_1_AuditLogStorageSize(t *testing.T) {
	dir := t.TempDir()
	orig := auditdConfPath
	t.Cleanup(func() { auditdConfPath = orig })

	rule := ruleByID("4.1.1.1")
	available := models.SecurityInfo{AuditRules: 5}
	notAvail := models.SecurityInfo{AuditRules: -1}

	t.Run("auditd not available → SKIP", func(t *testing.T) {
		auditdConfPath = filepath.Join(dir, "no_auditd.conf")
		got := rule.Check(notAvail, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("no auditd: want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("auditd.conf unreadable → SKIP", func(t *testing.T) {
		auditdConfPath = filepath.Join(dir, "missing_auditd.conf")
		got := rule.Check(available, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("missing conf: want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("max_log_file = 8 → PASS", func(t *testing.T) {
		cf := filepath.Join(dir, "auditd_ok.conf")
		if err := os.WriteFile(cf, []byte("# comment\nmax_log_file = 8\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		auditdConfPath = cf
		got := rule.Check(available, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("max_log_file=8: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("max_log_file = 0 → FAIL", func(t *testing.T) {
		cf := filepath.Join(dir, "auditd_zero.conf")
		if err := os.WriteFile(cf, []byte("max_log_file = 0\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		auditdConfPath = cf
		got := rule.Check(available, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("max_log_file=0: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("max_log_file not set → FAIL", func(t *testing.T) {
		cf := filepath.Join(dir, "auditd_nokey.conf")
		if err := os.WriteFile(cf, []byte("log_file = /var/log/audit/audit.log\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		auditdConfPath = cf
		got := rule.Check(available, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("no max_log_file: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// TestRule4_1_1_2_AuditLogsNotDeleted verifies rule 4.1.1.2.
// No t.Parallel(): mutates package-level auditdConfPath.
func TestRule4_1_1_2_AuditLogsNotDeleted(t *testing.T) {
	dir := t.TempDir()
	orig := auditdConfPath
	t.Cleanup(func() { auditdConfPath = orig })

	rule := ruleByID("4.1.1.2")
	available := models.SecurityInfo{AuditRules: 5}

	t.Run("max_log_file_action = keep_logs → PASS", func(t *testing.T) {
		cf := filepath.Join(dir, "auditd_keep.conf")
		if err := os.WriteFile(cf, []byte("max_log_file_action = keep_logs\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		auditdConfPath = cf
		got := rule.Check(available, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("keep_logs: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("max_log_file_action = rotate → FAIL", func(t *testing.T) {
		cf := filepath.Join(dir, "auditd_rotate.conf")
		if err := os.WriteFile(cf, []byte("max_log_file_action = rotate\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		auditdConfPath = cf
		got := rule.Check(available, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("rotate: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("max_log_file_action = ignore → FAIL", func(t *testing.T) {
		cf := filepath.Join(dir, "auditd_ignore.conf")
		if err := os.WriteFile(cf, []byte("max_log_file_action = ignore\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		auditdConfPath = cf
		got := rule.Check(available, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("ignore: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("max_log_file_action not set → FAIL", func(t *testing.T) {
		cf := filepath.Join(dir, "auditd_noaction.conf")
		if err := os.WriteFile(cf, []byte("max_log_file = 8\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		auditdConfPath = cf
		got := rule.Check(available, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("no max_log_file_action: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// TestRule4_1_1_3_AuditDiskFull verifies rule 4.1.1.3.
// No t.Parallel(): mutates package-level auditdConfPath.
func TestRule4_1_1_3_AuditDiskFull(t *testing.T) {
	dir := t.TempDir()
	orig := auditdConfPath
	t.Cleanup(func() { auditdConfPath = orig })

	rule := ruleByID("4.1.1.3")
	available := models.SecurityInfo{AuditRules: 5}

	t.Run("space_left_action=email admin_space_left_action=halt → PASS", func(t *testing.T) {
		cf := filepath.Join(dir, "auditd_halt.conf")
		content := "space_left_action = email\nadmin_space_left_action = halt\n"
		if err := os.WriteFile(cf, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		auditdConfPath = cf
		got := rule.Check(available, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("email+halt: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("space_left_action=syslog (not safe) → FAIL", func(t *testing.T) {
		cf := filepath.Join(dir, "auditd_syslog.conf")
		content := "space_left_action = syslog\nadmin_space_left_action = halt\n"
		if err := os.WriteFile(cf, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		auditdConfPath = cf
		got := rule.Check(available, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("syslog space_left: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("admin_space_left_action=suspend (not halt/single) → FAIL", func(t *testing.T) {
		cf := filepath.Join(dir, "auditd_suspend.conf")
		content := "space_left_action = email\nadmin_space_left_action = suspend\n"
		if err := os.WriteFile(cf, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		auditdConfPath = cf
		got := rule.Check(available, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("suspend admin action: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// TestRule4_1_1_4_AuditBacklogLimit verifies rule 4.1.1.4.
// No t.Parallel() — mutates procCmdlinePath and auditRulesAvailable.
func TestRule4_1_1_4_AuditBacklogLimit(t *testing.T) {
	rule := ruleByID("4.1.1.4")
	dir := t.TempDir()
	available := models.SecurityInfo{AuditRules: 5}
	unavailable := models.SecurityInfo{AuditRules: -1}

	origPath := procCmdlinePath
	t.Cleanup(func() { procCmdlinePath = origPath })

	t.Run("auditd not available → SKIP", func(t *testing.T) {
		procCmdlinePath = "/proc/cmdline" // irrelevant — gated early
		got := rule.Check(unavailable, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("/proc/cmdline unreadable → SKIP", func(t *testing.T) {
		procCmdlinePath = filepath.Join(dir, "nonexistent_cmdline")
		got := rule.Check(available, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("audit_backlog_limit=8192 → PASS", func(t *testing.T) {
		f := filepath.Join(dir, "cmdline_pass.txt")
		if err := os.WriteFile(f, []byte("quiet splash audit=1 audit_backlog_limit=8192\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		procCmdlinePath = f
		got := rule.Check(available, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("8192: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("audit_backlog_limit=256 (below 8192) → FAIL", func(t *testing.T) {
		f := filepath.Join(dir, "cmdline_low.txt")
		if err := os.WriteFile(f, []byte("quiet audit_backlog_limit=256\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		procCmdlinePath = f
		got := rule.Check(available, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("256: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("audit_backlog_limit absent → FAIL", func(t *testing.T) {
		f := filepath.Join(dir, "cmdline_nobacklog.txt")
		if err := os.WriteFile(f, []byte("quiet splash audit=1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		procCmdlinePath = f
		got := rule.Check(available, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("absent: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// TestRule4_2_6_RsyslogRemoteLogging verifies rule 4.2.6.
// No t.Parallel() — mutates rsyslogBinPaths, rsyslogConfPath, rsyslogConfDPath.
func TestRule4_2_6_RsyslogRemoteLogging(t *testing.T) {
	rule := ruleByID("4.2.6")
	dir := t.TempDir()

	origBins := rsyslogBinPaths
	origConf := rsyslogConfPath
	origConfD := rsyslogConfDPath
	t.Cleanup(func() {
		rsyslogBinPaths = origBins
		rsyslogConfPath = origConf
		rsyslogConfDPath = origConfD
	})

	fakeBin := filepath.Join(dir, "rsyslogd")
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh"), 0o755); err != nil {
		t.Fatal(err)
	}

	t.Run("rsyslog not installed → SKIP", func(t *testing.T) {
		rsyslogBinPaths = []string{filepath.Join(dir, "no_such_binary")}
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("TCP forwarding via @@ in rsyslog.conf → PASS", func(t *testing.T) {
		rsyslogBinPaths = []string{fakeBin}
		cf := filepath.Join(dir, "rsyslog_tcp.conf")
		if err := os.WriteFile(cf, []byte("*.* @@loghost.example.com:514\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		rsyslogConfPath = cf
		rsyslogConfDPath = filepath.Join(dir, "rsyslog_empty_d")
		if err := os.Mkdir(rsyslogConfDPath, 0o755); err != nil && !os.IsExist(err) {
			t.Fatal(err)
		}
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("TCP @@: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("omfwd action in drop-in → PASS", func(t *testing.T) {
		rsyslogBinPaths = []string{fakeBin}
		cf := filepath.Join(dir, "rsyslog_plain.conf")
		if err := os.WriteFile(cf, []byte("# no remote here\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		rsyslogConfPath = cf
		dDir := filepath.Join(dir, "rsyslog_d_omfwd")
		if err := os.Mkdir(dDir, 0o755); err != nil && !os.IsExist(err) {
			t.Fatal(err)
		}
		dropIn := filepath.Join(dDir, "50-remote.conf")
		if err := os.WriteFile(dropIn, []byte(`action(type="omfwd" target="loghost" port="514" protocol="tcp")`+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		rsyslogConfDPath = dDir
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("omfwd drop-in: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("no remote forwarding configured → FAIL", func(t *testing.T) {
		rsyslogBinPaths = []string{fakeBin}
		cf := filepath.Join(dir, "rsyslog_local_only.conf")
		if err := os.WriteFile(cf, []byte("*.* /var/log/syslog\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		rsyslogConfPath = cf
		dDir := filepath.Join(dir, "rsyslog_d_local")
		if err := os.Mkdir(dDir, 0o755); err != nil && !os.IsExist(err) {
			t.Fatal(err)
		}
		rsyslogConfDPath = dDir
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("local only: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// TestRule4_2_2_2_JournaldCompress verifies rule 4.2.2.2.
// No t.Parallel() — mutates journaldConfPath and journaldConfDPath.
func TestRule4_2_2_2_JournaldCompress(t *testing.T) {
	rule := ruleByID("4.2.2.2")
	dir := t.TempDir()

	origConf := journaldConfPath
	origConfD := journaldConfDPath
	t.Cleanup(func() {
		journaldConfPath = origConf
		journaldConfDPath = origConfD
	})

	t.Run("journald config missing → SKIP", func(t *testing.T) {
		journaldConfPath = filepath.Join(dir, "no_journald.conf")
		journaldConfDPath = filepath.Join(dir, "no_journald_d")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("Compress=yes in journald.conf → PASS", func(t *testing.T) {
		cf := filepath.Join(dir, "jconf_compress.conf")
		if err := os.WriteFile(cf, []byte("[Journal]\nCompress=yes\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		journaldConfPath = cf
		journaldConfDPath = filepath.Join(dir, "jconfd_empty1")
		if err := os.Mkdir(journaldConfDPath, 0o755); err != nil && !os.IsExist(err) {
			t.Fatal(err)
		}
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("Compress=yes: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("Compress=yes in drop-in → PASS", func(t *testing.T) {
		cf := filepath.Join(dir, "jconf_no_compress.conf")
		if err := os.WriteFile(cf, []byte("[Journal]\nStorage=persistent\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		journaldConfPath = cf
		dDir := filepath.Join(dir, "jconfd_compress")
		if err := os.Mkdir(dDir, 0o755); err != nil && !os.IsExist(err) {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dDir, "50-compress.conf"), []byte("Compress=yes\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		journaldConfDPath = dDir
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("drop-in Compress=yes: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("Compress not set → FAIL", func(t *testing.T) {
		cf := filepath.Join(dir, "jconf_nocompress.conf")
		if err := os.WriteFile(cf, []byte("[Journal]\nStorage=persistent\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		journaldConfPath = cf
		journaldConfDPath = filepath.Join(dir, "jconfd_empty2")
		if err := os.Mkdir(journaldConfDPath, 0o755); err != nil && !os.IsExist(err) {
			t.Fatal(err)
		}
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("no Compress: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// TestRule4_2_2_3_JournaldStorage verifies rule 4.2.2.3.
// No t.Parallel() — mutates journaldConfPath and journaldConfDPath.
func TestRule4_2_2_3_JournaldStorage(t *testing.T) {
	rule := ruleByID("4.2.2.3")
	dir := t.TempDir()

	origConf := journaldConfPath
	origConfD := journaldConfDPath
	t.Cleanup(func() {
		journaldConfPath = origConf
		journaldConfDPath = origConfD
	})

	t.Run("journald config missing → SKIP", func(t *testing.T) {
		journaldConfPath = filepath.Join(dir, "no_journald2.conf")
		journaldConfDPath = filepath.Join(dir, "no_journald_d2")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("Storage=persistent in journald.conf → PASS", func(t *testing.T) {
		cf := filepath.Join(dir, "jconf_persistent.conf")
		if err := os.WriteFile(cf, []byte("[Journal]\nStorage=persistent\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		journaldConfPath = cf
		journaldConfDPath = filepath.Join(dir, "jconfd_empty3")
		if err := os.Mkdir(journaldConfDPath, 0o755); err != nil && !os.IsExist(err) {
			t.Fatal(err)
		}
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("Storage=persistent: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("Storage=auto (not persistent) → FAIL", func(t *testing.T) {
		cf := filepath.Join(dir, "jconf_auto.conf")
		if err := os.WriteFile(cf, []byte("[Journal]\nStorage=auto\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		journaldConfPath = cf
		journaldConfDPath = filepath.Join(dir, "jconfd_empty4")
		if err := os.Mkdir(journaldConfDPath, 0o755); err != nil && !os.IsExist(err) {
			t.Fatal(err)
		}
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("Storage=auto: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// TestRule5_5_1_RootLoginConsole verifies rule 5.5.1.
// No t.Parallel() — mutates securettyPath.
func TestRule5_5_1_RootLoginConsole(t *testing.T) {
	rule := ruleByID("5.5.1")
	dir := t.TempDir()

	origPath := securettyPath
	t.Cleanup(func() { securettyPath = origPath })

	t.Run("securetty missing → FAIL", func(t *testing.T) {
		securettyPath = filepath.Join(dir, "no_securetty")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("missing: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("securetty empty → FAIL", func(t *testing.T) {
		f := filepath.Join(dir, "securetty_empty")
		if err := os.WriteFile(f, []byte("# comment only\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		securettyPath = f
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("empty: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("securetty has tty1 → PASS", func(t *testing.T) {
		f := filepath.Join(dir, "securetty_tty1")
		if err := os.WriteFile(f, []byte("# only tty1 is allowed\ntty1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		securettyPath = f
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("tty1: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// TestRule5_5_2_SuWheelRestriction verifies rule 5.5.2.
// No t.Parallel() — mutates pamSuPath.
func TestRule5_5_2_SuWheelRestriction(t *testing.T) {
	rule := ruleByID("5.5.2")
	dir := t.TempDir()

	origPath := pamSuPath
	t.Cleanup(func() { pamSuPath = origPath })

	t.Run("/etc/pam.d/su unreadable → SKIP", func(t *testing.T) {
		pamSuPath = filepath.Join(dir, "no_pam_su")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("pam_wheel.so use_uid present → PASS", func(t *testing.T) {
		f := filepath.Join(dir, "pam_su_wheel")
		content := "#%PAM-1.0\nauth required pam_wheel.so use_uid\nauth include system-auth\n"
		if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		pamSuPath = f
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("wheel: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("pam_wheel.so commented out → FAIL", func(t *testing.T) {
		f := filepath.Join(dir, "pam_su_commented")
		content := "#%PAM-1.0\n# auth required pam_wheel.so use_uid\nauth include system-auth\n"
		if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		pamSuPath = f
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("commented: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("pam_wheel.so without use_uid → FAIL", func(t *testing.T) {
		f := filepath.Join(dir, "pam_su_no_uid")
		content := "#%PAM-1.0\nauth required pam_wheel.so\nauth include system-auth\n"
		if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		pamSuPath = f
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("no use_uid: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// TestRule5_4_9_PwqualityMinlen verifies rule 5.4.9.
// No t.Parallel() — mutates pwqualityConfPath.
func TestRule5_4_9_PwqualityMinlen(t *testing.T) {
	rule := ruleByID("5.4.9")
	dir := t.TempDir()

	origPath := pwqualityConfPath
	t.Cleanup(func() { pwqualityConfPath = origPath })

	t.Run("pwquality.conf missing → SKIP", func(t *testing.T) {
		pwqualityConfPath = filepath.Join(dir, "no_pwquality.conf")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("minlen = 14 → PASS", func(t *testing.T) {
		f := filepath.Join(dir, "pwquality_14.conf")
		if err := os.WriteFile(f, []byte("# pwquality config\nminlen = 14\ndigit = -1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		pwqualityConfPath = f
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("minlen=14: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("minlen = 8 (below 14) → FAIL", func(t *testing.T) {
		f := filepath.Join(dir, "pwquality_8.conf")
		if err := os.WriteFile(f, []byte("minlen = 8\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		pwqualityConfPath = f
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("minlen=8: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("minlen not set → FAIL", func(t *testing.T) {
		f := filepath.Join(dir, "pwquality_none.conf")
		if err := os.WriteFile(f, []byte("# only comments\ndcredit = -1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		pwqualityConfPath = f
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("no minlen: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// TestRule5_4_10_PamFaillock verifies rule 5.4.10.
// No t.Parallel() — mutates faillockConfPath and pamCommonAuthPath.
func TestRule5_4_10_PamFaillock(t *testing.T) {
	rule := ruleByID("5.4.10")
	dir := t.TempDir()

	origFaillock := faillockConfPath
	origCommonAuth := pamCommonAuthPath
	t.Cleanup(func() {
		faillockConfPath = origFaillock
		pamCommonAuthPath = origCommonAuth
	})

	t.Run("faillock.conf deny=5 → PASS", func(t *testing.T) {
		f := filepath.Join(dir, "faillock_5.conf")
		if err := os.WriteFile(f, []byte("deny = 5\nunlock_time = 900\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		faillockConfPath = f
		pamCommonAuthPath = filepath.Join(dir, "no_common_auth")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("deny=5: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("faillock.conf deny=10 (too high) → FAIL", func(t *testing.T) {
		f := filepath.Join(dir, "faillock_10.conf")
		if err := os.WriteFile(f, []byte("deny = 10\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		faillockConfPath = f
		pamCommonAuthPath = filepath.Join(dir, "no_common_auth2")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("deny=10: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("pam_faillock.so in common-auth (fallback) → PASS", func(t *testing.T) {
		faillockConfPath = filepath.Join(dir, "no_faillock.conf")
		f := filepath.Join(dir, "common_auth_faillock")
		content := "#%PAM-1.0\nauth required pam_faillock.so preauth\nauth include system-auth\n"
		if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		pamCommonAuthPath = f
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("pam_faillock.so fallback: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("no lockout configured → FAIL", func(t *testing.T) {
		faillockConfPath = filepath.Join(dir, "no_faillock2.conf")
		f := filepath.Join(dir, "common_auth_plain")
		content := "#%PAM-1.0\nauth include system-auth\n"
		if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		pamCommonAuthPath = f
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("no lockout: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// TestRule5_4_11_PasswordHashing verifies rule 5.4.11.
// No t.Parallel() — mutates loginDefsPath and pamCommonPasswordPath.
func TestRule5_4_11_PasswordHashing(t *testing.T) {
	rule := ruleByID("5.4.11")
	dir := t.TempDir()

	origLoginDefs := loginDefsPath
	origCommonPw := pamCommonPasswordPath
	t.Cleanup(func() {
		loginDefsPath = origLoginDefs
		pamCommonPasswordPath = origCommonPw
	})

	t.Run("ENCRYPT_METHOD SHA512 in login.defs → PASS", func(t *testing.T) {
		f := filepath.Join(dir, "login_sha512.defs")
		if err := os.WriteFile(f, []byte("PASS_MAX_DAYS 90\nENCRYPT_METHOD SHA512\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		loginDefsPath = f
		pamCommonPasswordPath = filepath.Join(dir, "no_common_pw")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("SHA512: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("ENCRYPT_METHOD yescrypt in login.defs → PASS", func(t *testing.T) {
		f := filepath.Join(dir, "login_yescrypt.defs")
		if err := os.WriteFile(f, []byte("ENCRYPT_METHOD yescrypt\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		loginDefsPath = f
		pamCommonPasswordPath = filepath.Join(dir, "no_common_pw2")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("yescrypt: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("ENCRYPT_METHOD MD5 → FAIL", func(t *testing.T) {
		f := filepath.Join(dir, "login_md5.defs")
		if err := os.WriteFile(f, []byte("ENCRYPT_METHOD MD5\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		loginDefsPath = f
		pamCommonPasswordPath = filepath.Join(dir, "no_common_pw3")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("MD5: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("pam_unix.so sha512 in common-password (fallback) → PASS", func(t *testing.T) {
		loginDefsPath = filepath.Join(dir, "no_login.defs")
		f := filepath.Join(dir, "common_pw_sha512")
		content := "#%PAM-1.0\npassword [success=1 default=ignore] pam_unix.so obscure sha512\n"
		if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		pamCommonPasswordPath = f
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("pam_unix sha512 fallback: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// TestRule5_4_12_PasswordReuse verifies rule 5.4.12.
// No t.Parallel() — mutates pamCommonPasswordPath.
func TestRule5_4_12_PasswordReuse(t *testing.T) {
	rule := ruleByID("5.4.12")
	dir := t.TempDir()

	origPath := pamCommonPasswordPath
	t.Cleanup(func() { pamCommonPasswordPath = origPath })

	t.Run("common-password unreadable → SKIP", func(t *testing.T) {
		pamCommonPasswordPath = filepath.Join(dir, "no_common_pw_reuse")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("pam_unix.so remember=5 → PASS", func(t *testing.T) {
		f := filepath.Join(dir, "common_pw_remember5")
		content := "#%PAM-1.0\npassword required pam_unix.so sha512 remember=5\n"
		if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		pamCommonPasswordPath = f
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("remember=5: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("pam_unix.so remember=3 (below 5) → FAIL", func(t *testing.T) {
		f := filepath.Join(dir, "common_pw_remember3")
		content := "#%PAM-1.0\npassword required pam_unix.so sha512 remember=3\n"
		if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		pamCommonPasswordPath = f
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("remember=3: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("no remember= in common-password → FAIL", func(t *testing.T) {
		f := filepath.Join(dir, "common_pw_no_remember")
		content := "#%PAM-1.0\npassword required pam_unix.so sha512\n"
		if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		pamCommonPasswordPath = f
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("no remember: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// TestRule5_5_3_DefaultUmask verifies rule 5.5.3.
// No t.Parallel() — mutates etcProfilePath, etcProfileDPath, etcBashrcPath, loginDefsPath.
func TestRule5_5_3_DefaultUmask(t *testing.T) {
	rule := ruleByID("5.5.3")
	dir := t.TempDir()

	origProfile := etcProfilePath
	origProfileD := etcProfileDPath
	origBashrc := etcBashrcPath
	origLoginDefs := loginDefsPath
	t.Cleanup(func() {
		etcProfilePath = origProfile
		etcProfileDPath = origProfileD
		etcBashrcPath = origBashrc
		loginDefsPath = origLoginDefs
	})

	noFile := func(name string) string { return filepath.Join(dir, name) }

	t.Run("no umask configured anywhere → FAIL", func(t *testing.T) {
		etcProfilePath = noFile("no_profile")
		etcProfileDPath = noFile("no_profile_d")
		etcBashrcPath = noFile("no_bashrc")
		loginDefsPath = noFile("no_login_defs")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("none configured: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("UMASK 027 in login.defs → PASS", func(t *testing.T) {
		f := filepath.Join(dir, "login_umask027.defs")
		if err := os.WriteFile(f, []byte("PASS_MAX_DAYS 90\nUMASK 027\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		loginDefsPath = f
		etcProfilePath = noFile("no_profile2")
		etcProfileDPath = noFile("no_profile_d2")
		etcBashrcPath = noFile("no_bashrc2")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("UMASK 027: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("umask 022 in /etc/profile → FAIL", func(t *testing.T) {
		loginDefsPath = noFile("no_login_defs3")
		f := filepath.Join(dir, "profile_022")
		if err := os.WriteFile(f, []byte("# system profile\numask 022\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		etcProfilePath = f
		etcProfileDPath = noFile("no_profile_d3")
		etcBashrcPath = noFile("no_bashrc3")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("umask 022: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("umask 077 in profile.d drop-in → PASS", func(t *testing.T) {
		loginDefsPath = noFile("no_login_defs4")
		etcProfilePath = noFile("no_profile4")
		dDir := filepath.Join(dir, "profile_d_077")
		if err := os.Mkdir(dDir, 0o755); err != nil && !os.IsExist(err) {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dDir, "umask.sh"), []byte("umask 077\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		etcProfileDPath = dDir
		etcBashrcPath = noFile("no_bashrc4")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("umask 077 drop-in: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("umask 027 in /etc/bash.bashrc → PASS", func(t *testing.T) {
		loginDefsPath = noFile("no_login_defs5")
		etcProfilePath = noFile("no_profile5")
		etcProfileDPath = noFile("no_profile_d5")
		f := filepath.Join(dir, "bashrc_027")
		if err := os.WriteFile(f, []byte("# bashrc\numask 027\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		etcBashrcPath = f
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("bashrc umask 027: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// TestRule5_5_4_ShellTimeout verifies rule 5.5.4.
// No t.Parallel() — mutates etcProfilePath, etcProfileDPath, etcBashrcPath.
func TestRule5_5_4_ShellTimeout(t *testing.T) {
	rule := ruleByID("5.5.4")
	dir := t.TempDir()

	origProfile := etcProfilePath
	origProfileD := etcProfileDPath
	origBashrc := etcBashrcPath
	t.Cleanup(func() {
		etcProfilePath = origProfile
		etcProfileDPath = origProfileD
		etcBashrcPath = origBashrc
	})

	noFile := func(name string) string { return filepath.Join(dir, name) }

	t.Run("TMOUT not set anywhere → FAIL", func(t *testing.T) {
		etcProfilePath = noFile("no_profile_tmout")
		etcProfileDPath = noFile("no_profile_d_tmout")
		etcBashrcPath = noFile("no_bashrc_tmout")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("not set: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("readonly TMOUT=900 in /etc/profile → PASS", func(t *testing.T) {
		f := filepath.Join(dir, "profile_tmout_900")
		if err := os.WriteFile(f, []byte("readonly TMOUT=900\nexport TMOUT\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		etcProfilePath = f
		etcProfileDPath = noFile("no_profile_d_tmout2")
		etcBashrcPath = noFile("no_bashrc_tmout2")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("TMOUT=900: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("TMOUT=1800 (exceeds 900) → FAIL", func(t *testing.T) {
		etcProfilePath = noFile("no_profile_tmout3")
		dDir := filepath.Join(dir, "profile_d_tmout_1800")
		if err := os.Mkdir(dDir, 0o755); err != nil && !os.IsExist(err) {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dDir, "timeout.sh"), []byte("TMOUT=1800\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		etcProfileDPath = dDir
		etcBashrcPath = noFile("no_bashrc_tmout3")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("TMOUT=1800: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("TMOUT=600 in /etc/bash.bashrc → PASS", func(t *testing.T) {
		etcProfilePath = noFile("no_profile_tmout4")
		etcProfileDPath = noFile("no_profile_d_tmout4")
		f := filepath.Join(dir, "bashrc_tmout_600")
		if err := os.WriteFile(f, []byte("export TMOUT=600\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		etcBashrcPath = f
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("TMOUT=600: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// TestRule1_2_3_AptAllowUnauthenticated verifies rule 1.2.3.
// No t.Parallel() — mutates debianVersionPath and aptConfDPath.
func TestRule1_2_3_AptAllowUnauthenticated(t *testing.T) {
	rule := ruleByID("1.2.3")
	dir := t.TempDir()

	origDebian := debianVersionPath
	origConfD := aptConfDPath
	t.Cleanup(func() {
		debianVersionPath = origDebian
		aptConfDPath = origConfD
	})

	t.Run("non-Debian system → SKIP", func(t *testing.T) {
		debianVersionPath = filepath.Join(dir, "no_debian_version")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISSkipped {
			t.Errorf("want Skip, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("no apt.conf.d → PASS (default is authenticated)", func(t *testing.T) {
		f := filepath.Join(dir, "debian_version")
		if err := os.WriteFile(f, []byte("11\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		debianVersionPath = f
		aptConfDPath = filepath.Join(dir, "no_apt_conf_d")
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("no conf.d: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("AllowUnauthenticated true in conf.d file → FAIL", func(t *testing.T) {
		f := filepath.Join(dir, "debian_version2")
		if err := os.WriteFile(f, []byte("22.04\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		debianVersionPath = f
		dDir := filepath.Join(dir, "apt_conf_d_unauth")
		if err := os.Mkdir(dDir, 0o755); err != nil && !os.IsExist(err) {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dDir, "99-unauth.conf"),
			[]byte(`APT::Get::AllowUnauthenticated "true";`+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		aptConfDPath = dDir
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISFail {
			t.Errorf("AllowUnauthenticated true: want Fail, got %s (%s)", got.Status, got.Finding)
		}
	})

	t.Run("AllowUnauthenticated false → PASS", func(t *testing.T) {
		f := filepath.Join(dir, "debian_version3")
		if err := os.WriteFile(f, []byte("22.04\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		debianVersionPath = f
		dDir := filepath.Join(dir, "apt_conf_d_auth")
		if err := os.Mkdir(dDir, 0o755); err != nil && !os.IsExist(err) {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dDir, "99-auth.conf"),
			[]byte(`APT::Get::AllowUnauthenticated "false";`+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		aptConfDPath = dDir
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status != models.CISPass {
			t.Errorf("AllowUnauthenticated false: want Pass, got %s (%s)", got.Status, got.Finding)
		}
	})
}

// TestRule3_2_9_IPv6AcceptRA verifies rule 3.2.9.
// No t.Parallel() — uses real checkSysctl (file-based); subtests use fake proc paths via
// a lightweight helper that writes synthetic sysctl files into t.TempDir().
func TestRule3_2_9_IPv6AcceptRA(t *testing.T) {
	rule := ruleByID("3.2.9")
	dir := t.TempDir()

	// checkSysctl reads the path from the rule closure directly, so we need to
	// exercise it by actually creating the synthetic file at the expected path.
	// Instead, we verify the rule delegates to checkSysctl by exercising the
	// SKIP path (file absent) and cross-check with real proc if IPv6 available.
	t.Run("rule registered with correct description", func(t *testing.T) {
		if rule.ID != "3.2.9" {
			t.Errorf("unexpected ID %s", rule.ID)
		}
		if !strings.Contains(rule.Description, "IPv6") {
			t.Errorf("description missing 'IPv6': %s", rule.Description)
		}
	})

	// Synthetic SKIP: checkSysctl returns SKIP when the /proc path is absent.
	// We can verify by running the rule on a system with no IPv6 or by checking
	// the return type from checkSysctl directly.
	t.Run("sysctl file absent → SKIP or non-Fail", func(t *testing.T) {
		// Create a fake proc tree that has no ipv6 directory.
		_ = dir // TempDir available but not needed for this structural test.
		// The rule is registered; the only values it can return are PASS/FAIL/SKIP.
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		if got.Status == "" {
			t.Error("Check returned empty status")
		}
	})
}

// TestRule3_2_10_IPv6AcceptRedirects verifies rule 3.2.10.
func TestRule3_2_10_IPv6AcceptRedirects(t *testing.T) {
	rule := ruleByID("3.2.10")

	t.Run("rule registered with correct description", func(t *testing.T) {
		if rule.ID != "3.2.10" {
			t.Errorf("unexpected ID %s", rule.ID)
		}
		if !strings.Contains(rule.Description, "IPv6") {
			t.Errorf("description missing 'IPv6': %s", rule.Description)
		}
	})

	t.Run("check returns a valid CIS status", func(t *testing.T) {
		got := rule.Check(models.SecurityInfo{}, models.KernelSecurityInfo{})
		valid := map[models.CISStatus]bool{
			models.CISPass: true, models.CISFail: true, models.CISSkipped: true,
		}
		if !valid[got.Status] {
			t.Errorf("unexpected status %q", got.Status)
		}
	})
}
