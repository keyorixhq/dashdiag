package cmd

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

// TestCisProfileName guards that the right profile label is emitted per distro
// and that STIG mode always wins over the distro-based label.
func TestCisProfileName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		distro  string
		level   int
		stig    bool
		wantSub string // expected substring in the profile name
	}{
		{"ubuntu", 1, false, "CIS Ubuntu"},
		{"", 1, false, "CIS Ubuntu"},  // unknown distro → Ubuntu default
		{"rhel", 1, false, "RHEL"},
		{"rocky", 1, false, "RHEL"},
		{"almalinux", 1, false, "RHEL"},
		{"centos", 1, false, "RHEL"},
		{"fedora", 1, false, "RHEL"},
		{"debian", 1, false, "Debian"},
		{"sles", 1, false, "SLES"},
		{"opensuse", 1, false, "SLES"},
		{"rhel", 1, true, "STIG"},    // STIG mode always overrides
		{"ubuntu", 2, false, "Level 2"},
	}
	for _, tc := range cases {
		t.Run(tc.distro+"/stig="+func() string {
			if tc.stig {
				return "true"
			}
			return "false"
		}(), func(t *testing.T) {
			t.Parallel()
			got := cisProfileName(tc.distro, tc.level, tc.stig)
			if !strings.Contains(got, tc.wantSub) {
				t.Errorf("cisProfileName(%q, %d, %v) = %q, want substring %q",
					tc.distro, tc.level, tc.stig, got, tc.wantSub)
			}
		})
	}
}

func TestCisIcon(t *testing.T) {
	// --plain must emit an ASCII token per status, not leak the human emoji.
	cases := []struct {
		status models.CISStatus
		want   string
	}{
		{models.CISPass, "OK"},
		{models.CISFail, "CRIT"},
		{models.CISManual, "INFO"},
		{models.CISSkipped, "SKIP"},
		{models.CISStatus("weird"), "-"},
	}
	for _, c := range cases {
		if got := strings.TrimSpace(cisIcon(c.status, output.ModePlain)); got != c.want {
			t.Errorf("cisIcon(%v) = %q, want %q", c.status, got, c.want)
		}
	}
}
