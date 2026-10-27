package render

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

func TestVerdict(t *testing.T) {
	boom := errors.New("permission denied")
	cases := []struct {
		name         string
		results      []runner.Result
		insights     []models.Insight
		level        string
		floored      bool
		notRun       int
		exit         int
		errored, unv int
	}{
		{"nothing", nil, nil, "OK", false, 0, 0, 0, 0},
		{"INFO only stays OK", nil, []models.Insight{{Level: "INFO", Check: "x"}}, "OK", false, 0, 0, 0, 0},
		{"warn", nil, []models.Insight{{Level: "WARN", Check: "IO"}}, "WARN", false, 0, 1, 0, 0},
		{"crit outranks warn", nil, []models.Insight{{Level: "WARN"}, {Level: "CRIT"}}, "CRIT", false, 0, 2, 0, 0},
		{"unverified INFO floors OK to WARN", nil,
			[]models.Insight{{Level: "INFO", Check: "Logs", Unverified: true}}, "WARN", true, 1, 1, 0, 1},
		{"errored collector floors OK to WARN",
			[]runner.Result{{Name: "Disk", Err: boom}}, nil, "WARN", true, 1, 1, 1, 0},
		{"errored collector + its unverified INFO is one check, not two",
			[]runner.Result{{Name: "Disk", Err: boom}},
			[]models.Insight{{Level: "INFO", Check: "Disk", Unverified: true}}, "WARN", true, 1, 1, 1, 1},
		{"floor never outranks a real CRIT",
			[]runner.Result{{Name: "Disk", Err: boom}},
			[]models.Insight{{Level: "CRIT", Check: "Net"}}, "CRIT", false, 1, 2, 1, 0},
		{"unverified WARN is a real WARN, not floored", nil,
			[]models.Insight{{Level: "WARN", Check: "FW", Unverified: true}}, "WARN", false, 1, 1, 0, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := Verdict(tc.results, tc.insights)
			if v.Level != tc.level || v.Floored() != tc.floored || v.NotRun != tc.notRun ||
				v.ExitCode() != tc.exit || v.Errored != tc.errored || v.Unverified != tc.unv {
				t.Errorf("Verdict = %+v floored=%v exit=%d; want level=%s floored=%v notRun=%d exit=%d errored=%d unverified=%d",
					v, v.Floored(), v.ExitCode(), tc.level, tc.floored, tc.notRun, tc.exit, tc.errored, tc.unv)
			}
			// The exit code is derived from the same verdict (no contract change).
			if got := exitCodeFromInsights(tc.insights); tc.results == nil && got != tc.exit {
				t.Errorf("exitCodeFromInsights = %d, want %d", got, tc.exit)
			}
		})
	}
}

func TestVerdict_NotFullyVerifiedWording(t *testing.T) {
	v := Verdict(nil, []models.Insight{
		{Level: "INFO", Check: "Logs", Unverified: true},
		{Level: "INFO", Check: "Disk", Unverified: true},
	})
	for _, plain := range []bool{false, true} {
		got := v.TerminalBanner(plain, "")
		if !strings.Contains(got, "Not fully verified: 2 checks could not run — see INFO below") {
			t.Errorf("banner (plain=%v) = %q: must name the count and where to look", plain, got)
		}
	}
	one := Verdict(nil, []models.Insight{{Level: "INFO", Check: "Logs", Unverified: true}})
	if got := one.TerminalBanner(true, ""); !strings.Contains(got, "1 check could not run") {
		t.Errorf("singular banner = %q", got)
	}
	if !strings.HasPrefix(v.TerminalBanner(true, ""), "WARN:") {
		t.Errorf("plain floored banner must lead with WARN: so grep/CI treat it as a warning, got %q", v.TerminalBanner(true, ""))
	}
}

func TestVerdict_CleanBannersUnchanged(t *testing.T) {
	v := Verdict(nil, nil)
	if got := v.TerminalBanner(true, " in 1.0s"); got != "OK: All checks passed in 1.0s" {
		t.Errorf("plain clean banner = %q (COMPATIBILITY.md text)", got)
	}
	if got := v.TerminalBanner(false, ""); !strings.Contains(got, "System healthy. Checks passed") {
		t.Errorf("human clean banner = %q", got)
	}
	if got := Verdict(nil, []models.Insight{{Level: "WARN"}}).TerminalBanner(false, ""); got != "" {
		t.Errorf("a WARN run prints its findings, not a banner; got %q", got)
	}
}

func TestSnapshotVerdict(t *testing.T) {
	clean := &baseline.Snapshot{Checks: []baseline.CheckResult{{Name: "A", Status: "OK"}}}
	if v := SnapshotVerdict(clean); v.Level != "OK" {
		t.Errorf("clean snapshot = %+v", v)
	}
	unv := &baseline.Snapshot{Checks: []baseline.CheckResult{{Name: "A", Status: "INFO", Unverified: true}}}
	if v := SnapshotVerdict(unv); !v.Floored() || v.NotRun != 1 {
		t.Errorf("unverified snapshot = %+v", v)
	}
	if v := SnapshotVerdict(nil); v.Level != "OK" {
		t.Errorf("nil snapshot = %+v", v)
	}
}

func TestHistoryEntry_VerdictVocabulary(t *testing.T) {
	snap := &baseline.Snapshot{Hostname: "h", Version: "v", Timestamp: time.Unix(0, 0).UTC(),
		Checks: []baseline.CheckResult{{Name: "Logs", Status: "INFO", Unverified: true}}}
	e := HistoryEntry(snap, nil, []models.Insight{{Level: "INFO", Check: "Logs", Unverified: true}})
	if e.Verdict != "WARN" {
		t.Errorf("a run that could not verify itself must be recorded WARN (the closed store vocabulary has no new value), got %q", e.Verdict)
	}
	if e.Checks["Logs"] != "INFO" || e.Hostname != "h" {
		t.Errorf("entry fields lost: %+v", e)
	}
}
