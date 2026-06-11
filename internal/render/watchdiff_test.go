package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/output"
)

func ins(level, check, msg string) models.Insight {
	return models.Insight{Level: level, Check: check, Message: msg}
}

func TestInsightChanges(t *testing.T) {
	t.Run("new issue is added", func(t *testing.T) {
		prev := []models.Insight{ins("WARN", "CPU", "load at 70%")}
		cur := []models.Insight{ins("WARN", "CPU", "load at 70%"), ins("CRIT", "Disk", "/ at 95% — full")}
		added, resolved, changed := InsightChanges(prev, cur)
		if len(added) != 1 || added[0].Check != "Disk" {
			t.Fatalf("expected Disk added, got %+v", added)
		}
		if len(resolved) != 0 || len(changed) != 0 {
			t.Errorf("expected no resolved/changed, got resolved=%+v changed=%+v", resolved, changed)
		}
	})

	t.Run("disappeared issue is resolved", func(t *testing.T) {
		prev := []models.Insight{ins("CRIT", "Network", "gateway unreachable")}
		cur := []models.Insight{}
		added, resolved, _ := InsightChanges(prev, cur)
		if len(added) != 0 || len(resolved) != 1 || resolved[0].Check != "Network" {
			t.Fatalf("expected Network resolved, got added=%+v resolved=%+v", added, resolved)
		}
	})

	t.Run("fluctuating value is NOT a change", func(t *testing.T) {
		// Same issue, different percentage each tick — must not churn as resolved+new.
		prev := []models.Insight{ins("WARN", "CPU", "load at 71.5%")}
		cur := []models.Insight{ins("WARN", "CPU", "load at 83.2%")}
		added, resolved, changed := InsightChanges(prev, cur)
		if len(added) != 0 || len(resolved) != 0 || len(changed) != 0 {
			t.Errorf("fluctuating value should be stable, got added=%+v resolved=%+v changed=%+v", added, resolved, changed)
		}
	})

	t.Run("severity escalation is a change, not resolve+new", func(t *testing.T) {
		prev := []models.Insight{ins("WARN", "CPU", "load at 75%")}
		cur := []models.Insight{ins("CRIT", "CPU", "load at 96%")}
		added, resolved, changed := InsightChanges(prev, cur)
		if len(added) != 0 || len(resolved) != 0 {
			t.Fatalf("escalation must not add/resolve, got added=%+v resolved=%+v", added, resolved)
		}
		if len(changed) != 1 || changed[0].FromLevel != "WARN" || changed[0].ToLevel != "CRIT" {
			t.Fatalf("expected WARN→CRIT change, got %+v", changed)
		}
	})

	t.Run("no change yields nothing", func(t *testing.T) {
		same := []models.Insight{ins("WARN", "CPU", "load at 75%"), ins("INFO", "Drives", "5 power-on years")}
		added, resolved, changed := InsightChanges(same, same)
		if len(added) != 0 || len(resolved) != 0 || len(changed) != 0 {
			t.Errorf("identical ticks should show no change, got added=%+v resolved=%+v changed=%+v", added, resolved, changed)
		}
	})

	t.Run("added sorted CRIT-first", func(t *testing.T) {
		prev := []models.Insight{}
		cur := []models.Insight{ins("WARN", "CPU", "x"), ins("CRIT", "Disk", "y")}
		added, _, _ := InsightChanges(prev, cur)
		if len(added) != 2 || added[0].Level != "CRIT" {
			t.Errorf("expected CRIT first, got %+v", added)
		}
	})
}

func TestPrintInsightChanges(t *testing.T) {
	t.Run("no change prints a steady-state line", func(t *testing.T) {
		var buf bytes.Buffer
		PrintInsightChanges(&buf, nil, nil, nil, output.ModeHuman)
		if !strings.Contains(buf.String(), "no change") {
			t.Errorf("expected 'no change' line, got %q", buf.String())
		}
	})

	t.Run("renders new, changed, resolved", func(t *testing.T) {
		var buf bytes.Buffer
		added := []models.Insight{ins("CRIT", "Disk", "/ full")}
		resolved := []models.Insight{ins("WARN", "Network", "gw slow")}
		changed := []InsightChange{{Insight: ins("CRIT", "CPU", "load high"), FromLevel: "WARN", ToLevel: "CRIT"}}
		PrintInsightChanges(&buf, added, resolved, changed, output.ModeHuman)
		out := buf.String()
		for _, want := range []string{"Disk", "/ full", "Network", "resolved", "WARN→CRIT", "CPU"} {
			if !strings.Contains(out, want) {
				t.Errorf("output missing %q; got:\n%s", want, out)
			}
		}
	})

	t.Run("non-human mode is a no-op", func(t *testing.T) {
		var buf bytes.Buffer
		PrintInsightChanges(&buf, []models.Insight{ins("CRIT", "Disk", "x")}, nil, nil, output.ModeJSON)
		if buf.Len() != 0 {
			t.Errorf("expected no output in JSON mode, got %q", buf.String())
		}
	})
}
