package render

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/analysis"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

func covOf(t *testing.T, s models.CoverageSummary, name string) models.CheckCoverage {
	t.Helper()
	for _, c := range s.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no coverage entry for %q in %+v", name, s.Checks)
	return models.CheckCoverage{}
}

func TestCoverage_Classification(t *testing.T) {
	results := []runner.Result{
		{Name: "CPU Load", Data: &models.CPUInfo{}},
		{Name: "Memory", Err: fmt.Errorf("collector Memory timed out after 2s: %w", context.DeadlineExceeded)},
		{Name: "Disk", Err: fmt.Errorf("statfs: %w", context.DeadlineExceeded)},
		{Name: "Network", Err: fmt.Errorf("netlink: %w", fs.ErrPermission)},
		{Name: "Swap", Err: errors.New("parse /proc/swaps: bad line")},
		{Name: "Launchd"}, // gated off: nil data
		{Name: "Ceph", Data: models.CephInfo{Available: false}}, // present-but-absent
		{Name: "Hardening", Data: &models.CPUInfo{}},
		{Name: "K8s", Data: models.CephInfo{Available: false}},
		{Name: "Docker", Data: models.DockerInfo{Available: false}},
	}
	insights := []models.Insight{
		{Level: "INFO", Check: "Hardening", Unverified: true, NeedsRoot: true, Message: "/etc/shadow not readable"},
		{Level: "INFO", Check: "Hardening/sudoers", Unverified: true, Message: "sudoers unreadable"},
		{Level: "INFO", Check: "K8s", Unverified: true, Message: "kubectl present, API unreachable"},
		{Level: "WARN", Check: "Docker/ps", Message: "a real finding about an absent collector"},
	}
	cov := Coverage(results, insights)

	want := map[string][2]string{
		"CPU Load":  {models.CoverageChecked, ""},
		"Memory":    {models.CoverageNotChecked, models.ReasonTimeout},
		"Disk":      {models.CoverageNotChecked, models.ReasonTimeout},
		"Network":   {models.CoverageNotChecked, models.ReasonUnreadable},
		"Swap":      {models.CoverageNotChecked, models.ReasonCollectorError},
		"Launchd":   {models.CoverageNotApplicable, models.ReasonNotSupportedPlatform},
		"Ceph":      {models.CoverageNotApplicable, models.ReasonNotPresent},
		"Hardening": {models.CoverageChecked, ""},
		"K8s":       {models.CoverageNotChecked, models.ReasonUnverified},
		"Docker":    {models.CoverageChecked, ""}, // an insight keeps an absent collector visible
	}
	for name, w := range want {
		got := covOf(t, cov, name)
		if got.Coverage != w[0] || got.Reason != w[1] {
			t.Errorf("%s: coverage %q reason %q, want %q %q", name, got.Coverage, got.Reason, w[0], w[1])
		}
	}

	h := covOf(t, cov, "Hardening")
	if len(h.NotCheckedSubchecks) != 2 {
		t.Fatalf("Hardening is checked but must list its 2 unread sub-checks, got %+v", h.NotCheckedSubchecks)
	}
	if cov.Checked != 3 || cov.NotApplicable != 2 || cov.Partial != 1 {
		t.Errorf("counts checked/na/partial = %d/%d/%d, want 3/2/1 (%+v)", cov.Checked, cov.NotApplicable, cov.Partial, cov)
	}
	// Memory, Disk, Network, Swap, K8s, Hardening (shadow), Hardening/sudoers.
	if cov.NotChecked != 7 {
		t.Errorf("NotChecked = %d, want 7 (4 errored + K8s + 2 Hardening sub-checks); reasons %v", cov.NotChecked, cov.Reasons)
	}
	if cov.Reasons[models.ReasonNeedsRoot] != 1 || cov.Reasons[models.ReasonTimeout] != 2 {
		t.Errorf("reasons = %v, want needs_root 1 and timeout 2", cov.Reasons)
	}
}

// An unverified insight no collector result owns is still something that was not
// looked at, and the verdict floors on it: it must stay visible and counted.
func TestCoverage_OrphanUnverifiedInsightIsCounted(t *testing.T) {
	cov := Coverage(nil, []models.Insight{{Level: "INFO", Check: "Logs", Unverified: true, NeedsRoot: true, Message: "kmsg"}})
	if cov.NotChecked != 1 || cov.Reasons[models.ReasonNeedsRoot] != 1 {
		t.Fatalf("orphan not counted: %+v", cov)
	}
	if c := covOf(t, cov, "Logs"); c.Coverage != models.CoverageNotChecked {
		t.Errorf("orphan = %+v, want not_checked", c)
	}
}

// The same check root-only AND otherwise unverified reads as the worse reason.
func TestCoverage_SameCheckBothReasonsKeepsTheWorse(t *testing.T) {
	cov := Coverage([]runner.Result{{Name: "Logs", Data: &models.CPUInfo{}}}, []models.Insight{
		{Level: "INFO", Check: "Logs", Unverified: true, NeedsRoot: true},
		{Level: "INFO", Check: "Logs", Unverified: true},
	})
	if cov.NotChecked != 1 || cov.Reasons[models.ReasonUnverified] != 1 || cov.Reasons[models.ReasonNeedsRoot] != 0 {
		t.Fatalf("want one unverified item, got %+v", cov)
	}
}

// TestCoverageMatchesVerdict pins coverage to the verdict: what Verdict reports
// as could-not-run plus skipped is exactly the not_checked count, for runs whose
// insights come from analysis.ApplyThresholds like a real one.
func TestCoverageMatchesVerdict(t *testing.T) {
	errored := []runner.Result{
		{Name: "CPU Load", Err: &fs.PathError{Op: "open", Path: "/proc/stat", Err: fs.ErrPermission}},
		{Name: "Memory", Err: context.DeadlineExceeded},
	}
	thresh := analysis.DefaultThresholds(platform.CloudEnvironment(0))
	erroredRun := analysis.ApplyThresholds(errored, thresh, platform.CloudEnvironment(0), platform.ContainerContext{})

	root := needsRootOnly()
	mixed := needsRootPlusOther()

	for _, tc := range []struct {
		name     string
		results  []runner.Result
		insights []models.Insight
	}{
		{"all errored", errored, erroredRun},
		{"needs root only", root.results, root.insights},
		{"needs root plus other", mixed.results, mixed.insights},
		{"clean", []runner.Result{{Name: "CPU Load", Data: &models.CPUInfo{}}}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := Verdict(tc.results, tc.insights)
			cov := Coverage(tc.results, tc.insights)
			if cov.NotChecked != v.NotRun+v.Skipped {
				t.Errorf("coverage not_checked = %d, verdict NotRun+Skipped = %d+%d (cov %+v)", cov.NotChecked, v.NotRun, v.Skipped, cov)
			}
			if cov.Reasons[models.ReasonNeedsRoot] != v.Skipped {
				t.Errorf("coverage needs_root = %d, verdict Skipped = %d", cov.Reasons[models.ReasonNeedsRoot], v.Skipped)
			}
		})
	}
}

func TestCoverage_JSONEntriesAndRunSummary(t *testing.T) {
	results := []runner.Result{
		{Name: "CPU Load", Data: &models.CPUInfo{}},
		{Name: "Memory", Err: context.DeadlineExceeded},
		{Name: "Hardening", Data: &models.CPUInfo{}},
		{Name: "GPU"}, // nothing to check: nil data
		{Name: "Ceph", Data: models.CephInfo{Available: false}},
	}
	insights := []models.Insight{
		{Level: "INFO", Check: "Hardening", Unverified: true, NeedsRoot: true, Message: "/etc/shadow not readable"},
		{Level: "INFO", Check: "Memory", Unverified: true, Message: "check could not run — timed out"},
	}
	data, err := RenderJSON(results, insights)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Verdict string
		Checks  []struct {
			Name, Status, Coverage string
			CoverageReason         string                           `json:"coverage_reason"`
			Sub                    []struct{ Check, Reason string } `json:"not_checked_subchecks"`
		}
		Coverage struct {
			Checked       int
			NotChecked    int            `json:"not_checked"`
			NotApplicable int            `json:"not_applicable"`
			Reasons       map[string]int `json:"not_checked_reasons"`
			NA            []struct {
				Name   string
				Reason string `json:"coverage_reason"`
			} `json:"not_applicable_checks"`
		}
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, c := range out.Checks {
		got[c.Name] = c.Coverage + "/" + c.CoverageReason
		if c.Coverage == "" {
			t.Errorf("checks[%s] has no coverage", c.Name)
		}
		if c.Name == "Memory" && c.Status != "ERROR" {
			t.Errorf("status of an errored check changed: %q", c.Status)
		}
	}
	if got["CPU Load"] != "checked/" || got["Memory"] != "not_checked/timeout" || got["Hardening"] != "checked/" {
		t.Errorf("checks[] coverage = %v", got)
	}
	if _, ok := got["GPU"]; ok {
		t.Error("a not-applicable collector must stay out of checks[] (no phantom OK)")
	}
	if out.Coverage.Checked != 2 || out.Coverage.NotChecked != 2 || out.Coverage.NotApplicable != 2 {
		t.Errorf("coverage summary = %+v, want 2 checked / 2 not checked / 2 not applicable", out.Coverage)
	}
	if len(out.Coverage.NA) != 2 {
		t.Errorf("not_applicable_checks = %+v, want GPU and Ceph", out.Coverage.NA)
	}
	if out.Verdict != "WARN" {
		t.Errorf("verdict = %q: coverage must not change it (errored Memory still floors)", out.Verdict)
	}
}

func TestCoverageLine(t *testing.T) {
	s := models.CoverageSummary{Checked: 12, NotChecked: 3, NotApplicable: 31,
		Reasons: map[string]int{models.ReasonNeedsRoot: 2, models.ReasonTimeout: 1}}
	want := "12 checked · 3 not checked (needs root: 2, timeout: 1) · 31 not applicable"
	if got := CoverageLine(&s); got != want {
		t.Errorf("CoverageLine = %q, want %q", got, want)
	}
	if got := CoverageLine(&models.CoverageSummary{Checked: 5}); got != "5 checked" {
		t.Errorf("zero parts must be left out, got %q", got)
	}
	if CoverageLine(nil) != "" {
		t.Error("nil summary must print nothing")
	}
}

func TestCoverageReasonsAreDocumented(t *testing.T) {
	want := map[string]bool{}
	for _, r := range models.CoverageReasons {
		want[r] = true
	}
	for _, r := range []string{"needs_root", "timeout", "unreadable", "collector_error", "parse", "not_recorded", "unverified", "not_present", "not_supported_platform"} {
		if !want[r] {
			t.Errorf("reason %q missing from models.CoverageReasons", r)
		}
	}
	if len(models.CoverageReasons) != 9 {
		t.Errorf("CoverageReasons = %v: a new reason needs schema enum + COMPATIBILITY.md + CoverageAction", models.CoverageReasons)
	}
	for _, r := range models.CoverageReasons[:7] {
		if CoverageAction(r) == "" {
			t.Errorf("not-checked reason %q has no action", r)
		}
	}
}

// TestCoverage_UnverifiedReasonSplits: an Unverified insight carries its own
// cause into coverage_reason; "unverified" stays only for one that has none, and
// needs_root still wins when NeedsRoot is set.
func TestCoverage_UnverifiedReasonSplits(t *testing.T) {
	results := []runner.Result{
		{Name: "Hardening", Data: &models.CPUInfo{}},
		{Name: "InfiniBand", Data: &models.CPUInfo{}},
	}
	insights := []models.Insight{
		{Level: "INFO", Check: "Hardening/a", Unverified: true, UnverifiedReason: models.ReasonNotRecorded},
		{Level: "INFO", Check: "Hardening/b", Unverified: true, UnverifiedReason: models.ReasonParse},
		{Level: "INFO", Check: "Hardening/c", Unverified: true, UnverifiedReason: models.ReasonNeedsRoot, NeedsRoot: true},
		{Level: "INFO", Check: "InfiniBand", Unverified: true},
	}
	cov := Coverage(results, insights)
	want := map[string]int{models.ReasonNotRecorded: 1, models.ReasonParse: 1, models.ReasonNeedsRoot: 1, models.ReasonUnverified: 1}
	for r, n := range want {
		if cov.Reasons[r] != n {
			t.Errorf("reasons[%s] = %d, want %d (%v)", r, cov.Reasons[r], n, cov.Reasons)
		}
	}
}
