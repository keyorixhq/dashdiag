package cis

import (
	"os"
	"path/filepath"
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

		// 6.2.3 only root is UID 0
		{"6.2.3 extra uid0 fails", "6.2.3", models.SecurityInfo{UID0Users: []string{"toor"}}, models.CISFail},
		{"6.2.3 none passes", "6.2.3", models.SecurityInfo{}, models.CISPass},

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
		rep := Evaluate(sec, ks, 1, false)
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
		rep := Evaluate(sec, ks, 2, false)
		ids := resultIDs(rep)
		if !ids["C2"] {
			t.Errorf("L2 run should include C2; got %v", ids)
		}
		assertTally(t, rep)
	})

	t.Run("STIG mode swaps IDs and excludes CIS-only", func(t *testing.T) {
		rep := Evaluate(sec, ks, 1, true)
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

	rep := Evaluate(models.SecurityInfo{}, models.KernelSecurityInfo{}, 1, true)
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
	rep := Evaluate(models.SecurityInfo{AuditRules: -1}, models.KernelSecurityInfo{}, 2, false)
	if len(rep.Results) == 0 {
		t.Fatal("real registry produced no results")
	}
	assertTally(t, rep)
}
