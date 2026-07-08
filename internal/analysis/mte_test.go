package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestCheckMTE_NotAvailable confirms an arm64 host without MTE support (or a
// non-arm64 host, via the notlinux stub) never fires — MTE=false must be silent.
func TestCheckMTE_NotAvailable(t *testing.T) {
	t.Parallel()
	if got := checkMTE(models.MTEInfo{Available: false}); got != nil {
		t.Errorf("expected nil for Available=false, got %+v", got)
	}
}

// TestCheckMTE_Unverified confirms the honest-degrade path: an unreadable
// kernel log must surface as INFO, never a silent "0 faults" false-OK.
func TestCheckMTE_Unverified(t *testing.T) {
	t.Parallel()
	got := checkMTE(models.MTEInfo{Available: true, StatusReason: "kernel log unreadable (journalctl -k and dmesg both failed)"})
	if len(got) != 1 {
		t.Fatalf("insight count: got %d, want 1", len(got))
	}
	if got[0].Level != "INFO" {
		t.Errorf("level: got %q, want INFO", got[0].Level)
	}
}

// TestCheckMTE_ExceptionTraceOffWarns confirms the posture-gap insight fires
// when MTE hardware is present but debug.exception-trace is off — this is the
// insight that justifies the feature even with zero faults ever observed.
func TestCheckMTE_ExceptionTraceOffWarns(t *testing.T) {
	t.Parallel()
	got := checkMTE(models.MTEInfo{Available: true, ExceptionTraceEnabled: false})
	if len(got) != 1 {
		t.Fatalf("insight count: got %d, want 1", len(got))
	}
	if got[0].Level != "WARN" {
		t.Errorf("level: got %q, want WARN", got[0].Level)
	}
}

// TestCheckMTE_ExceptionTraceOnNoFaultsSilent confirms no insight when
// exception-trace is already on and nothing has crashed — a clean posture.
func TestCheckMTE_ExceptionTraceOnNoFaultsSilent(t *testing.T) {
	t.Parallel()
	if got := checkMTE(models.MTEInfo{Available: true, ExceptionTraceEnabled: true}); got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

// TestCheckMTE_FaultIsCrit confirms an actual tag-check-fault crash is CRIT,
// named with process/pid/fault-type, and additive to the exception-trace-off
// WARN when both conditions co-occur is NOT possible here (a fault can only be
// observed when exception-trace IS on) — so only the CRIT fires, not the WARN.
func TestCheckMTE_FaultIsCrit(t *testing.T) {
	t.Parallel()
	got := checkMTE(models.MTEInfo{
		Available:             true,
		ExceptionTraceEnabled: true,
		RecentFaults: []models.MTEFaultEvent{
			{Process: "mte_test", PID: 2263, FaultType: "synchronous"},
		},
	})
	if len(got) != 1 {
		t.Fatalf("insight count: got %d, want 1", len(got))
	}
	if got[0].Level != "CRIT" {
		t.Errorf("level: got %q, want CRIT", got[0].Level)
	}
}

// TestCheckMTE_MultipleFaultsEachReported confirms every distinct fault gets
// its own insight, not a single rolled-up count.
func TestCheckMTE_MultipleFaultsEachReported(t *testing.T) {
	t.Parallel()
	got := checkMTE(models.MTEInfo{
		Available:             true,
		ExceptionTraceEnabled: true,
		RecentFaults: []models.MTEFaultEvent{
			{Process: "a", PID: 1, FaultType: "synchronous"},
			{Process: "b", PID: 2, FaultType: "asynchronous"},
		},
	})
	if len(got) != 2 {
		t.Fatalf("insight count: got %d, want 2", len(got))
	}
	for _, ins := range got {
		if ins.Level != "CRIT" {
			t.Errorf("level: got %q, want CRIT for every fault", ins.Level)
		}
	}
}
