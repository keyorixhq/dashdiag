package cmd

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestSecurityChecksLimited guards the false-OK fix: a non-root run (or an
// unreadable sshd_config) must be reported as "checks limited", not "healthy.
// Checks passed", since the root-only probes silently degraded. A fully-audited
// host with no issues must NOT be flagged as limited.
func TestSecurityChecksLimited(t *testing.T) {
	tests := []struct {
		name string
		info models.SecurityInfo
		want bool
	}{
		{"non-root run is limited", models.SecurityInfo{NeedsRoot: true}, true},
		{"unreadable sshd_config (no audit source) is limited",
			models.SecurityInfo{SSHConfigUnreadable: true, SSHAuditSource: ""}, true},
		{"unreadable config but audited via sshd -T is not limited",
			models.SecurityInfo{SSHConfigUnreadable: true, SSHAuditSource: "sshd -T"}, false},
		{"fully audited root run is not limited",
			models.SecurityInfo{SSHAuditSource: "sshd -T"}, false},
		{"clean zero-value (root, readable) is not limited", models.SecurityInfo{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := securityChecksLimited(&tt.info); got != tt.want {
				t.Errorf("securityChecksLimited(%+v) = %v, want %v", tt.info, got, tt.want)
			}
		})
	}
}
