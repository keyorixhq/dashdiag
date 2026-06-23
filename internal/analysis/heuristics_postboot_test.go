package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestCheckPostBoot_NotAvailableSilent(t *testing.T) {
	if got := checkPostBoot(models.PostBootInfo{}); got != nil {
		t.Errorf("unavailable post-boot should yield nothing, got %v", got)
	}
}

func TestCheckPostBoot_UnmeasurableIsShownNotOmitted(t *testing.T) {
	// Volatile journald: must surface (never omitted, never OK) but as INFO, not an
	// alarmist WARN on every cloud/minimal host.
	got := checkPostBoot(models.PostBootInfo{Available: true, State: "unmeasurable", Reason: "no_persistent_journal"})
	if len(got) != 1 || got[0].Level != "INFO" {
		t.Fatalf("unmeasurable = %+v, want one INFO line", got)
	}
	if !hasInsightMsg(got, "INFO", "did not survive") {
		t.Errorf("should explain volatile journald: %q", got[0].Message)
	}

	// EACCES variant tells the operator to run as root.
	got = checkPostBoot(models.PostBootInfo{Available: true, State: "unmeasurable", Reason: "journal_unreadable"})
	if !hasInsightMsg(got, "INFO", "not readable as this user") {
		t.Errorf("EACCES should hint root, got %+v", got)
	}
}

func TestCheckPostBoot_Absent(t *testing.T) {
	got := checkPostBoot(models.PostBootInfo{Available: true, State: "absent"})
	if !hasInsightMsg(got, "INFO", "no prior boot on record") {
		t.Errorf("absent should state first-boot, got %+v", got)
	}
}

func TestCheckPostBoot_PanicWarns(t *testing.T) {
	got := checkPostBoot(models.PostBootInfo{
		Available: true, State: "found", Source: "persistent_journal",
		ShutdownChecked: true, KernelPanic: true, PanicHint: "Kernel panic - not syncing: VFS",
	})
	if !hasInsightMsg(got, "WARN", "kernel panic") {
		t.Errorf("prior-boot panic should WARN, got %+v", got)
	}
}

func TestCheckPostBoot_OOMAndUncleanWarn(t *testing.T) {
	got := checkPostBoot(models.PostBootInfo{
		Available: true, State: "found", Source: "persistent_journal",
		OOMKills: 2, OOMVictims: []string{"mysqld", "java"},
		ShutdownChecked: true, UncleanShutdown: true,
	})
	if !hasInsightMsg(got, "WARN", "OOM kill") || !hasInsightMsg(got, "WARN", "mysqld") {
		t.Errorf("prior-boot OOM should WARN with victims, got %+v", got)
	}
	if !hasInsightMsg(got, "WARN", "unclean") {
		t.Errorf("unclean shutdown should WARN, got %+v", got)
	}
}

func TestCheckPostBoot_CleanRecognition(t *testing.T) {
	// Readable prior boot, nothing notable → one INFO recognition line (a real healthy
	// result), no WARN.
	got := checkPostBoot(models.PostBootInfo{
		Available: true, State: "found", Source: "persistent_journal",
		ShutdownChecked: true, UncleanShutdown: false,
	})
	if len(got) != 1 || got[0].Level != "INFO" {
		t.Fatalf("clean prior boot = %+v, want one INFO line", got)
	}
	if !hasInsightMsg(got, "INFO", "no OOM kill or kernel panic") {
		t.Errorf("clean recognition wording: %q", got[0].Message)
	}
}

func TestCheckPostBoot_WtmpDoesNotClaimOOMPanicClean(t *testing.T) {
	// The coarse wtmp path can't see OOM/panic (journal-only) — the recognition line
	// must NOT assert those were clean, only the shutdown state it could observe.
	got := checkPostBoot(models.PostBootInfo{
		Available: true, State: "found", Source: "wtmp",
		ShutdownChecked: true, UncleanShutdown: false,
	})
	if len(got) != 1 || got[0].Level != "INFO" {
		t.Fatalf("wtmp clean = %+v, want one INFO line", got)
	}
	if strings.Contains(got[0].Message, "no OOM kill or kernel panic") {
		t.Errorf("wtmp path must not claim OOM/panic clean (not checkable via wtmp): %q", got[0].Message)
	}
	if !strings.Contains(got[0].Message, "unavailable") {
		t.Errorf("wtmp path should disclose OOM/panic detail unavailable: %q", got[0].Message)
	}
}

func TestCheckPostBoot_UncleanNotClaimedWhenUnchecked(t *testing.T) {
	// ShutdownChecked false (coarse wtmp couldn't confirm) → must NOT emit an unclean
	// WARN, and the recognition line must not assert "shutdown was clean".
	got := checkPostBoot(models.PostBootInfo{
		Available: true, State: "found", Source: "wtmp",
		ShutdownChecked: false, UncleanShutdown: false,
	})
	if hasInsightMsg(got, "WARN", "unclean") {
		t.Errorf("must not WARN unclean when shutdown wasn't checked: %+v", got)
	}
	for _, i := range got {
		if i.Level == "INFO" && strings.Contains(i.Message, "shutdown was clean") {
			t.Errorf("must not claim clean shutdown when unchecked: %q", i.Message)
		}
	}
}
