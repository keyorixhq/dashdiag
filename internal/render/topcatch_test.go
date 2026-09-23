package render

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/analysis"
	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

func TestComputeTopCatch_NoCritWarn_ReturnsNil(t *testing.T) {
	t.Parallel()
	insights := []models.Insight{{Level: "INFO", Check: "Network", Message: "not measured"}}
	if tc := ComputeTopCatch(insights, nil); tc != nil {
		t.Errorf("expected nil for INFO-only insights, got %+v", tc)
	}
	if tc := ComputeTopCatch(nil, nil); tc != nil {
		t.Errorf("expected nil for empty insights/corrs, got %+v", tc)
	}
}

func TestComputeTopCatch_CritBeatsWarn(t *testing.T) {
	t.Parallel()
	insights := []models.Insight{
		{Level: "WARN", Check: "Memory", Message: "memory high"},
		{Level: "CRIT", Check: "Disk", Message: "disk full"},
	}
	tc := ComputeTopCatch(insights, nil)
	if tc == nil || tc.Severity != "CRIT" || tc.Topic != "disk" {
		t.Fatalf("expected the CRIT Disk finding to win, got %+v", tc)
	}
}

func TestComputeTopCatch_CorrelationBeatsSymptomAtSameSeverity(t *testing.T) {
	t.Parallel()
	insights := []models.Insight{
		{Level: "CRIT", Check: "Memory", Message: "memory exhausted"},
		{Level: "CRIT", Check: "Swap", Message: "swap thrashing"},
	}
	corrs := []analysis.Correlation{
		{Name: "Memory Pressure Cascade", Level: "CRIT", Summary: "RAM exhaustion forced swap thrashing", Action: "ps aux --sort=-%mem", Checks: []string{"Memory", "Swap"}},
	}
	tc := ComputeTopCatch(insights, corrs)
	if tc == nil {
		t.Fatal("expected a Top catch")
	}
	if tc.Summary != corrs[0].Summary || tc.Fix != corrs[0].Action {
		t.Errorf("expected the correlation to win over its own symptom insights, got %+v", tc)
	}
	if tc.Topic != "memory" {
		t.Errorf("expected topic derived from the correlation's first Check, got %q", tc.Topic)
	}
}

func TestComputeTopCatch_HighestSeverityWinsOverLowerCorrelation(t *testing.T) {
	t.Parallel()
	// A CRIT insight with no correlation must still beat a WARN-level
	// correlation — severity is the primary criterion, correlation-over-
	// symptom only breaks ties AT the top severity.
	insights := []models.Insight{
		{Level: "CRIT", Check: "Disk", Message: "disk full"},
		{Level: "WARN", Check: "CPULoad", Message: "load elevated"},
	}
	corrs := []analysis.Correlation{
		{Name: "Some WARN correlation", Level: "WARN", Summary: "warn cause", Action: "inspect", Checks: []string{"CPULoad"}},
	}
	tc := ComputeTopCatch(insights, corrs)
	if tc == nil || tc.Severity != "CRIT" || tc.Topic != "disk" {
		t.Fatalf("expected the CRIT Disk insight to win over a WARN correlation, got %+v", tc)
	}
}

func TestComputeTopCatch_FixBeatsNoFixAmongTiedInsights(t *testing.T) {
	t.Parallel()
	insights := []models.Insight{
		{Level: "CRIT", Check: "Zeta", Message: "z finding"}, // alphabetically first, but no hints
		{Level: "CRIT", Check: "Alpha", Message: "a finding", Hints: []string{"to fix: do the thing"}},
	}
	tc := ComputeTopCatch(insights, nil)
	if tc == nil || tc.Topic != "alpha" || tc.Fix != "to fix: do the thing" {
		t.Fatalf("expected the insight WITH a fix to win despite losing alphabetically, got %+v", tc)
	}
}

func TestComputeTopCatch_AlphabeticalTiebreakWhenNeitherHasFix(t *testing.T) {
	t.Parallel()
	insights := []models.Insight{
		{Level: "CRIT", Check: "Zeta", Message: "z finding"},
		{Level: "CRIT", Check: "Alpha", Message: "a finding"},
	}
	tc := ComputeTopCatch(insights, nil)
	if tc == nil || tc.Topic != "alpha" {
		t.Fatalf("expected deterministic alphabetical tiebreak (alpha), got %+v", tc)
	}
	if tc.Fix != topCatchFallbackFix {
		t.Errorf("expected the fallback fix when no hints exist, got %q", tc.Fix)
	}
}

func TestComputeTopCatch_TopicIsSlugified(t *testing.T) {
	t.Parallel()
	insights := []models.Insight{{Level: "CRIT", Check: "Network/DNS", Message: "resolver down"}}
	tc := ComputeTopCatch(insights, nil)
	if tc == nil || tc.Topic != "network" {
		t.Fatalf("expected a subsystem-qualified check to slug to its base name, got %+v", tc)
	}
}

func TestTopCatchLine_SanitizesControlChars(t *testing.T) {
	t.Parallel()
	insights := []models.Insight{{Level: "CRIT", Check: "Proc", Message: "evil\x1b[31m process"}}
	tc, ok := TopCatchLine(insights)
	if !ok || tc == nil {
		t.Fatal("expected a Top catch")
	}
	if strings.ContainsRune(tc.Summary, 0x1b) {
		t.Errorf("expected control characters stripped from Summary, got %q", tc.Summary)
	}
}

func TestPrintTopCatch_AllClearLine(t *testing.T) {
	r := NewRenderer(output.ModePlain)
	out := captureStdout(t, func() {
		r.PrintTopCatch(nil, nil, 22)
	})
	want := "Top catch: none — 22 checks passed.\n"
	if out != want {
		t.Errorf("PrintTopCatch(all-clear) = %q, want %q", out, want)
	}
}

func TestPrintTopCatch_FindingLine(t *testing.T) {
	r := NewRenderer(output.ModePlain)
	insights := []models.Insight{{Level: "CRIT", Check: "Docker", Message: "container crash looping", Hints: []string{"to inspect: docker logs"}}}
	out := captureStdout(t, func() {
		r.PrintTopCatch(insights, nil, 10)
	})
	want := "Top catch: container crash looping (docker) → to inspect: docker logs\n"
	if out != want {
		t.Errorf("PrintTopCatch(finding) = %q, want %q", out, want)
	}
}

func TestPrintTopCatch_JSONYAMLModesNoOp(t *testing.T) {
	insights := []models.Insight{{Level: "CRIT", Check: "Docker", Message: "x"}}
	for _, mode := range []output.OutputMode{output.ModeJSON, output.ModeYAML} {
		r := NewRenderer(mode)
		out := captureStdout(t, func() {
			r.PrintTopCatch(insights, nil, 1)
		})
		if out != "" {
			t.Errorf("PrintTopCatch in %v mode should no-op, got %q", mode, out)
		}
	}
}

func TestRenderJSON_TopCatchField_NullWhenHealthy(t *testing.T) {
	t.Parallel()
	results := []runner.Result{{Name: "CPU Load", Data: &models.CPUInfo{}}}
	insights := []models.Insight{{Level: "OK", Check: "CPU Load"}}
	data, err := RenderJSON(results, insights)
	if err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	rawVal, present := out["top_catch"]
	if !present {
		t.Fatal("expected the \"top_catch\" key to always be present in the JSON document")
	}
	if rawVal != nil {
		t.Errorf("expected top_catch to be null when healthy, got %v", rawVal)
	}
}

func TestRenderJSON_TopCatchField_PopulatedOnCrit(t *testing.T) {
	t.Parallel()
	results := []runner.Result{{Name: "Docker", Data: &models.DockerInfo{}}}
	insights := []models.Insight{{
		Level: "CRIT", Check: "Docker", Message: "container crash looping",
		Hints: []string{"to inspect: docker logs payments-api"},
	}}
	data, err := RenderJSON(results, insights)
	if err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	var out JSONOutput
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.TopCatch == nil {
		t.Fatal("expected a populated top_catch for a CRIT insight")
	}
	if out.TopCatch.Topic != "docker" || out.TopCatch.Severity != "CRIT" {
		t.Errorf("unexpected top_catch: %+v", out.TopCatch)
	}
	if out.TopCatch.Fix != "to inspect: docker logs payments-api" {
		t.Errorf("expected the insight's hint as fix, got %q", out.TopCatch.Fix)
	}
}
