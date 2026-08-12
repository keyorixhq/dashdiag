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
		{"", 1, false, "CIS Ubuntu"}, // unknown distro → Ubuntu default
		{"rhel", 1, false, "RHEL"},
		{"rocky", 1, false, "RHEL"},
		{"almalinux", 1, false, "RHEL"},
		{"centos", 1, false, "RHEL"},
		{"fedora", 1, false, "RHEL"},
		{"debian", 1, false, "Debian"},
		{"sles", 1, false, "SLES"},
		{"opensuse", 1, false, "SLES"},
		{"rhel", 1, true, "STIG"}, // STIG mode always overrides
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
		name   string
		result models.CISResult
		want   string
	}{
		{"pass", models.CISResult{Status: models.CISPass}, "OK"},
		{"fail", models.CISResult{Status: models.CISFail}, "CRIT"},
		{"manual", models.CISResult{Status: models.CISManual}, "INFO"},
		{"skipped, genuinely not applicable", models.CISResult{Status: models.CISSkipped}, "SKIP"},
		// A genuine skip and an unverified skip share Status==CISSkipped but
		// must render distinctly — the whole point of the Unverified field.
		{"skipped, unverified", models.CISResult{Status: models.CISSkipped, Unverified: true}, "UNVERIFIED"},
		{"unknown status", models.CISResult{Status: models.CISStatus("weird")}, "-"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := strings.TrimSpace(cisIcon(c.result, output.ModePlain)); got != c.want {
				t.Errorf("cisIcon(%+v) = %q, want %q", c.result, got, c.want)
			}
		})
	}
}

// TestPrintCISReport_StripsControlChars guards terminal escape injection:
// Description/Finding/Remediation are built from raw host data (usernames,
// service names, config values) that a local attacker can influence.
func TestPrintCISReport_StripsControlChars(t *testing.T) {
	report := models.CISReport{
		Profile: "Test Profile", Hostname: "host1", Fail: 1,
		Results: []models.CISResult{
			{
				ID: "1.1", Section: "sec", Status: models.CISFail,
				Description: "desc\x1b]0;pwned\x07",
				Finding:     "finding\x1b[31mevil\x1b[0m",
				Remediation: "fix\x1bcmd",
			},
		},
	}
	out := captureStdout(t, func() {
		printCISReport(report, false, false, output.ModePlain)
	})
	if strings.Contains(out, "\x1b") {
		t.Errorf("printCISReport output still contains ESC byte:\n%s", out)
	}
	if !strings.Contains(out, "desc]0;pwned") || !strings.Contains(out, "finding[31mevil[0m") || !strings.Contains(out, "fixcmd") {
		t.Errorf("printCISReport output missing sanitized fields:\n%s", out)
	}
}
