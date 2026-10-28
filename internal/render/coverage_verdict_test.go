package render

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

// TestCoverageVerdictRules pins DD-COVERAGE-1 item 3 (Andrei's 2026-10-28 "keep"
// decision): coverage is reporting, it changes no verdict or exit code.
//
//   - not_applicable never raises the exit code;
//   - not_checked because of needs_root on a non-root run does not by itself;
//   - any other not_checked keeps the existing WARN floor;
//   - a root run where a needs-root-tagged check could not be read is a plain
//     Unverified (no NeedsRoot), so it floors (analysis.TestRootRun_*).
//
// and a real CRIT is never outranked by any of it.
func TestCoverageVerdictRules(t *testing.T) {
	ok := runner.Result{Name: "CPU Load", Data: &models.CPUInfo{}}
	shadow := needsRootInsight("Hardening", "/etc/shadow not readable")
	rootRunShadow := models.Insight{Level: "INFO", Check: "Hardening", Unverified: true, Message: "/etc/shadow not readable"}

	for _, tc := range []struct {
		name         string
		results      []runner.Result
		insights     []models.Insight
		wantLevel    string
		wantExit     int
		wantCoverage string // coverage of the check under test ("" = no such check)
		wantReason   string
		check        string
	}{
		{"not applicable only", []runner.Result{ok, {Name: "GPU"}, {Name: "Docker", Data: models.DockerInfo{}}},
			nil, "OK", 0, models.CoverageNotApplicable, models.ReasonNotSupportedPlatform, "GPU"},
		{"not applicable, not present", []runner.Result{ok, {Name: "Docker", Data: models.DockerInfo{}}},
			nil, "OK", 0, models.CoverageNotApplicable, models.ReasonNotPresent, "Docker"},
		{"needs root, non-root run", []runner.Result{ok, {Name: "Hardening", Data: &models.CPUInfo{}}},
			[]models.Insight{shadow}, "OK", 0, models.CoverageChecked, "", "Hardening"},
		{"needs root, ROOT run: same read unreadable still floors", []runner.Result{ok, {Name: "Hardening", Data: &models.CPUInfo{}}},
			[]models.Insight{rootRunShadow}, "WARN", 1, models.CoverageChecked, "", "Hardening"},
		{"timeout floors", []runner.Result{ok, {Name: "Disk", Err: fmt.Errorf("collector Disk timed out after 5s: %w", context.DeadlineExceeded)}},
			nil, "WARN", 1, models.CoverageNotChecked, models.ReasonTimeout, "Disk"},
		{"collector error floors", []runner.Result{ok, {Name: "Disk", Err: errors.New("parse failed")}},
			nil, "WARN", 1, models.CoverageNotChecked, models.ReasonCollectorError, "Disk"},
		{"permission error floors", []runner.Result{ok, {Name: "Disk", Err: &fs.PathError{Op: "open", Path: "/proc/x", Err: fs.ErrPermission}}},
			nil, "WARN", 1, models.CoverageNotChecked, models.ReasonUnreadable, "Disk"},
		{"absent but unverified floors", []runner.Result{ok, {Name: "K8s", Data: models.CephInfo{}}},
			[]models.Insight{{Level: "INFO", Check: "K8s", Unverified: true, Message: "API unreachable"}},
			"WARN", 1, models.CoverageNotChecked, models.ReasonUnverified, "K8s"},
		{"a real CRIT outranks everything", []runner.Result{ok, {Name: "Disk", Err: errors.New("boom")}, {Name: "GPU"}},
			[]models.Insight{{Level: "CRIT", Check: "CPU Load", Message: "load"}, shadow},
			"CRIT", 2, models.CoverageNotChecked, models.ReasonCollectorError, "Disk"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := Verdict(tc.results, tc.insights)
			if v.Level != tc.wantLevel || v.ExitCode() != tc.wantExit {
				t.Errorf("verdict %s exit %d, want %s exit %d", v.Level, v.ExitCode(), tc.wantLevel, tc.wantExit)
			}
			cov := Coverage(tc.results, tc.insights)
			got := covOf(t, cov, tc.check)
			if got.Coverage != tc.wantCoverage || got.Reason != tc.wantReason {
				t.Errorf("%s coverage %q/%q, want %q/%q", tc.check, got.Coverage, got.Reason, tc.wantCoverage, tc.wantReason)
			}
			// The invariant behind all of it: an OK verdict can only carry
			// not-checked items whose reason is needs_root.
			if v.Level == "OK" {
				for reason, n := range cov.Reasons {
					if n > 0 && reason != models.ReasonNeedsRoot {
						t.Errorf("verdict OK but %d item(s) not checked for %q", n, reason)
					}
				}
			}
		})
	}
}
