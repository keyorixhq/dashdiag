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
	unver := models.SecurityInfo{SSHConfigUnreadable: true, SSHAuditSource: ""}
	repUnver := Evaluate(unver, ks, 1, false)
	for _, id := range []string{"5.2.6", "5.2.7"} {
		if r, ok := find(repUnver, id); !ok || r.Status != models.CISSkipped {
			t.Errorf("%s with unverified SSH config: status=%v ok=%v, want Skipped", id, r.Status, ok)
		}
	}
	// Verified via sshd -T: the same rules evaluate normally, not skipped.
	ver := models.SecurityInfo{SSHAuditSource: "sshd -T"}
	if r, ok := find(Evaluate(ver, ks, 1, false), "5.2.6"); !ok || r.Status == models.CISSkipped {
		t.Errorf("5.2.6 with verified SSH config must evaluate, got status=%v ok=%v", r.Status, ok)
	}
}
