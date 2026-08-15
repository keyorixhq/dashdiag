package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestCheckAWS_EBSReadFailed covers the case a.EBSReadFailed branch in
// awsEBSInsights — the read succeeded (root) but returned untrusted data.
func TestCheckAWS_EBSReadFailed(t *testing.T) {
	t.Parallel()
	got := checkAWS(models.AWSInfo{IsEC2: true, EBSReadAttempted: true, EBSReadFailed: true})
	if !hasInsightMsg(got, "INFO", "could not read EBS performance stats") {
		t.Errorf("EBSReadFailed must produce an explicit INFO, got %+v", got)
	}
}

// TestCheckAWS_EBSDeltaReadFailed is the regression test for
// internal-collectors-02-01: a successful first EBS read followed by a
// failed second (delta) read must disclose that the "currently throttled"
// verdict is unverified, not silently read as a clean zero delta.
func TestCheckAWS_EBSDeltaReadFailed(t *testing.T) {
	t.Parallel()
	got := checkAWS(models.AWSInfo{IsEC2: true, EBSReadAttempted: true, EBSDeltaReadFailed: true})
	if !hasInsightMsg(got, "INFO", "follow-up sample failed") {
		t.Errorf("EBSDeltaReadFailed must produce an explicit INFO, got %+v", got)
	}
}

// TestCheckRabbitMQ_BothAlarms covers the `r.MemoryAlarm && r.DiskAlarm`
// switch case inside checkRabbitMQ — both watermarks breached simultaneously.
func TestCheckRabbitMQ_BothAlarms(t *testing.T) {
	t.Parallel()
	got := checkRabbitMQ(models.RabbitMQInfo{
		Detected:        true,
		DiagnosticsRead: true,
		AlarmsRead:      true,
		MemoryAlarm:     true,
		DiskAlarm:       true,
	})
	if len(got) == 0 {
		t.Fatal("expected a CRIT insight for both alarms, got none")
	}
	if got[0].Level != "CRIT" {
		t.Errorf("both alarms must be CRIT, got %q", got[0].Level)
	}
	if !strings.Contains(got[0].Message, "memory and disk") {
		t.Errorf("both-alarms CRIT must say 'memory and disk', got %q", got[0].Message)
	}
}

// TestCheckPVE_NeedsRoot covers the p.NeedsRoot branch in checkPVE — PVE
// detected but running non-root.
func TestCheckPVE_NeedsRoot(t *testing.T) {
	t.Parallel()
	got := checkPVE(models.PVEInfo{IsPVE: true, NeedsRoot: true})
	if !hasInsightMsg(got, "INFO", "run as root for full cluster") {
		t.Errorf("NeedsRoot must produce an explicit INFO, got %+v", got)
	}
}

// TestAdaptHintsToPlatform_EmptyHints covers the `len(hints) == 0 → continue`
// branch in adaptHintsToPlatform — when an insight exists but carries no hints,
// it must be skipped cleanly on darwin/openrc paths.
func TestAdaptHintsToPlatform_EmptyHints(t *testing.T) {
	t.Parallel()
	ins := []models.Insight{
		{Level: "WARN", Check: "Hardening", Hints: nil},                          // no hints
		{Level: "WARN", Check: "Clock", Hints: []string{"to inspect: ss -tlnp"}}, // has hints
	}
	out := adaptHintsToPlatform(cloneInsights(ins), "darwin", "unknown")
	if len(out) != 2 {
		t.Fatalf("expected 2 insights, got %d", len(out))
	}
	if out[0].Hints != nil {
		t.Errorf("empty-hints insight must stay empty, got %v", out[0].Hints)
	}
}

// TestNixosifyHints_EmptyHints covers the `len(hints) == 0 → continue`
// branch in nixosifyHints — insight with no hints must pass through unchanged.
func TestNixosifyHints_EmptyHints(t *testing.T) {
	t.Parallel()
	ins := []models.Insight{
		{Level: "WARN", Check: "NixOS", Hints: nil},
		{Level: "WARN", Check: "NixOS", Hints: []string{"to fix: sysctl -w vm.swappiness=10"}},
	}
	out := nixosifyHints(cloneInsights(ins))
	if len(out) != 2 {
		t.Fatalf("expected 2 insights, got %d", len(out))
	}
	if out[0].Hints != nil {
		t.Errorf("empty-hints insight must stay nil, got %v", out[0].Hints)
	}
}
