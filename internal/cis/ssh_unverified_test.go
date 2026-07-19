package cis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestEvaluateSSHUnverifiedSkipped guards the false-OK fix: when sshd_config could
// not be read (non-root — sshd -T needs root, the file is 0600), SSH config rules
// must report Skipped (unverified) rather than Pass off the secure OpenSSH
// defaults. When the config WAS read, the same rule evaluates normally.
func TestEvaluateSSHUnverifiedSkipped(t *testing.T) {
	t.Parallel()
	ks := models.KernelSecurityInfo{}
	find := func(rep models.CISReport, id string) (models.CISResult, bool) {
		for _, r := range rep.Results {
			if r.ID == id {
				return r, true
			}
		}
		return models.CISResult{}, false
	}

	// Unverified: config-derived SSH rules must be Skipped in BOTH directions —
	// 5.2.6 (X11) would default to PASS, 5.2.7 (MaxAuthTries) would default to FAIL.
	// 5.2.17 (AllowTcpForwarding) is also guarded after the false-OK fix.
	unver := models.SecurityInfo{SSHConfigUnreadable: true, SSHAuditSource: ""}
	repUnver := Evaluate(unver, ks, 1, false, "apt")
	for _, id := range []string{"5.2.6", "5.2.7", "5.2.17"} {
		if r, ok := find(repUnver, id); !ok || r.Status != models.CISSkipped {
			t.Errorf("%s with unverified SSH config: status=%v ok=%v, want Skipped", id, r.Status, ok)
		}
	}
	// Verified via sshd -T: the same rules evaluate normally, not skipped.
	ver := models.SecurityInfo{SSHAuditSource: "sshd -T"}
	if r, ok := find(Evaluate(ver, ks, 1, false, "apt"), "5.2.6"); !ok || r.Status == models.CISSkipped {
		t.Errorf("5.2.6 with verified SSH config must evaluate, got status=%v ok=%v", r.Status, ok)
	}
}

// TestCISSSHDangerousCompiledDefaults guards the false-OK class where sshd -T
// fails (non-root on Debian/Ubuntu — exits 1 "no hostkeys available") and the
// file-parse fallback runs: PasswordAuthentication / AllowTcpForwarding /
// AllowAgentForwarding are commonly COMMENTED-OUT in the stock Ubuntu sshd_config,
// so the file parser never sets them. The collector pre-sets these to their
// dangerous OpenSSH compiled defaults (true) so the zero-value cannot masquerade
// as a secure "disabled" state. Rules 5.2.17 / 5.2.20 / 5.2.22 must FAIL, not PASS.
func TestCISSSHDangerousCompiledDefaults(t *testing.T) {
	t.Parallel()
	ks := models.KernelSecurityInfo{}
	find := func(rep models.CISReport, id string) (models.CISResult, bool) {
		for _, r := range rep.Results {
			if r.ID == id {
				return r, true
			}
		}
		return models.CISResult{}, false
	}

	// Simulate the file-parse fallback: sshd_config is readable (not unreadable),
	// but the directives are commented out so the parser never overrides the
	// pre-initialised dangerous compiled defaults.
	dangerousDefaults := models.SecurityInfo{
		SSHAuditSource:     "file",
		SSHPasswordAuth:    true, // compiled default: yes
		SSHTCPForwarding:   true, // compiled default: yes
		SSHAgentForwarding: true, // compiled default: yes
	}
	rep := Evaluate(dangerousDefaults, ks, 1, false, "apt")
	for _, id := range []string{"5.2.17", "5.2.20", "5.2.22"} {
		r, ok := find(rep, id)
		if !ok {
			t.Errorf("%s not found in report", id)
			continue
		}
		if r.Status != models.CISFail {
			t.Errorf("%s with dangerous compiled defaults active: status=%v, want Fail", id, r.Status)
		}
	}
}
