package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func withRoot(t *testing.T, root bool) {
	t.Helper()
	old := isRoot
	isRoot = func() bool { return root }
	t.Cleanup(func() { isRoot = old })
}

// A needs-root skip is only exempt from the verdict floor on a non-root run;
// the same unreadable source as root is a plain Unverified that still floors.
func TestNeedsRootInsight_OnlyNonRootIsExempt(t *testing.T) {
	withRoot(t, false)
	ins := needsRootInsight("INFO", "Hardening", "/etc/shadow not readable", nil)
	if !ins.Unverified || !ins.NeedsRoot {
		t.Fatalf("non-root: %+v, want Unverified and NeedsRoot", ins)
	}
	withRoot(t, true)
	ins = needsRootInsight("INFO", "Hardening", "/etc/shadow not readable", nil)
	if !ins.Unverified || ins.NeedsRoot {
		t.Fatalf("root: %+v, want Unverified and NOT NeedsRoot (another cause, must still floor)", ins)
	}
}

func TestCheckLogs_NeedsRootSplit(t *testing.T) {
	withRoot(t, false)
	th := DefaultThresholds(0)
	var needs, plain int
	for _, ins := range checkLogs(models.LogsInfo{NeedsRoot: true, KmsgUnreadable: true, CrashFilesUnreadable: true}, th) {
		if !ins.Unverified {
			continue
		}
		if !ins.NeedsRoot {
			t.Errorf("non-root privilege gap %q must be NeedsRoot", ins.Message)
		}
		needs++
	}
	if needs != 3 {
		t.Errorf("needs-root insights = %d, want 3 (limited, kmsg, crash files)", needs)
	}

	// A failed systemctl crash-loop query is not a privilege gap: it stays a
	// plain Unverified even on a non-root run, so it keeps flooring.
	for _, ins := range checkLogs(models.LogsInfo{CrashLoopsUnverified: true, CrashFilesUnreadable: true}, th) {
		if ins.Unverified && ins.NeedsRoot {
			t.Errorf("crash-loop query failure %q must not be NeedsRoot", ins.Message)
		}
		if ins.Unverified {
			plain++
		}
	}
	if plain != 1 {
		t.Errorf("plain unverified insights = %d, want 1", plain)
	}
}
