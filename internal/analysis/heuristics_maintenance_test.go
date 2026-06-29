package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestCheckKdump(t *testing.T) {
	// armed = enabled + crash kernel loaded + memory reserved → no insight
	armed := models.KdumpInfo{Available: true, Enabled: true, CrashLoaded: true, ReservedBytes: 448 << 20, Crashkernel: "448M"}
	if got := checkKdump(armed); len(got) != 0 {
		t.Errorf("armed kdump should be silent, got %+v", got)
	}
	// not installed / disabled → never a fault
	if got := checkKdump(models.KdumpInfo{Available: false}); got != nil {
		t.Errorf("absent kdump must be nil")
	}
	if got := checkKdump(models.KdumpInfo{Available: true, Enabled: false}); got != nil {
		t.Errorf("disabled-by-admin kdump must be nil (not a fault)")
	}
	// enabled but no reservation → the silent-failure WARN
	noResv := models.KdumpInfo{Available: true, Enabled: true, CrashLoaded: false, ReservedBytes: 0, Crashkernel: ""}
	if !hasInsightMsg(checkKdump(noResv), "WARN", "NO crash dump") {
		t.Errorf("enabled-but-unreserved kdump must WARN: %+v", checkKdump(noResv))
	}
	if !hasInsightMsg(checkKdump(noResv), "WARN", "crashkernel= memory reservation") {
		t.Errorf("missing crashkernel= must be named: %+v", checkKdump(noResv))
	}
	// enabled + reserved but service failed → WARN
	failed := models.KdumpInfo{Available: true, Enabled: true, ServiceState: "failed"}
	if !hasInsightMsg(checkKdump(failed), "WARN", "FAILED") {
		t.Errorf("failed kdump.service must WARN: %+v", checkKdump(failed))
	}
}

func TestCheckTuned(t *testing.T) {
	if got := checkTuned(models.TunedInfo{Available: false}); got != nil {
		t.Errorf("absent tuned must be nil")
	}
	// inactive → INFO
	if !hasInsightMsg(checkTuned(models.TunedInfo{Available: true, Active: false}), "INFO", "not active") {
		t.Errorf("inactive tuned must INFO")
	}
	// active, profile == recommended → silent
	ok := models.TunedInfo{Available: true, Active: true, Profile: "virtual-guest", Recommended: "virtual-guest"}
	if got := checkTuned(ok); len(got) != 0 {
		t.Errorf("matching tuned profile should be silent, got %+v", got)
	}
	// active, profile != recommended → INFO (the OL9-on-balanced live catch)
	mism := models.TunedInfo{Available: true, Active: true, Profile: "balanced", Recommended: "virtual-guest"}
	got := checkTuned(mism)
	if !hasInsightMsg(got, "INFO", "differs from the recommended") {
		t.Errorf("mismatched tuned profile must INFO: %+v", got)
	}
	if !hasInsightMsg(got, "INFO", "virtual-guest") {
		t.Errorf("recommended profile must be named: %+v", got)
	}
}

func TestCheckKernelPatch(t *testing.T) {
	if got := checkKernelPatch(models.KernelPatchInfo{Available: false}); got != nil {
		t.Errorf("absent must be nil")
	}
	// running == latest → silent
	same := models.KernelPatchInfo{Available: true, Running: "6.12.0-203.el10uek.x86_64", LatestInstalled: "6.12.0-203.el10uek.x86_64", RebootNeeded: false}
	if got := checkKernelPatch(same); len(got) != 0 {
		t.Errorf("up-to-date kernel should be silent, got %+v", got)
	}
	// newer installed than running → WARN reboot
	stale := models.KernelPatchInfo{Available: true, Running: "6.12.0-203.el10uek.x86_64", LatestInstalled: "6.12.0-300.el10uek.x86_64", RebootNeeded: true}
	got := checkKernelPatch(stale)
	if !hasInsightMsg(got, "WARN", "reboot to apply") {
		t.Errorf("reboot-pending kernel must WARN: %+v", got)
	}
	if !hasInsightMsg(got, "WARN", "still running") {
		t.Errorf("must name the running kernel: %+v", got)
	}
	// SUSE (zypper) path: reboot needed but no specific newer version known → WARN
	// with the generic message, NOT an empty "(%s)".
	suse := models.KernelPatchInfo{Available: true, Running: "6.4.0-150600-default", LatestInstalled: "", RebootNeeded: true}
	gs := checkKernelPatch(suse)
	if !hasInsightMsg(gs, "WARN", "reboot to apply") {
		t.Errorf("SUSE reboot-needed must WARN: %+v", gs)
	}
	if hasInsightMsg(gs, "WARN", "newer kernel ()") {
		t.Errorf("must not emit an empty '(%%s)' when LatestInstalled is unknown: %+v", gs)
	}
}

func TestCheckKsplice(t *testing.T) {
	if got := checkKsplice(models.KspliceInfo{Available: false}); got != nil {
		t.Errorf("absent ksplice must be nil")
	}
	// clean → silent
	if got := checkKsplice(models.KspliceInfo{Available: true, PendingUpdates: 0}); len(got) != 0 {
		t.Errorf("up-to-date ksplice should be silent, got %+v", got)
	}
	// pending → WARN
	if !hasInsightMsg(checkKsplice(models.KspliceInfo{Available: true, PendingUpdates: 3}), "WARN", "not applied") {
		t.Errorf("pending ksplice patches must WARN")
	}
	// unverified → INFO (honest, not a false OK)
	if !hasInsightMsg(checkKsplice(models.KspliceInfo{Available: true, CheckUnverified: true}), "INFO", "could not be read") {
		t.Errorf("unverified ksplice must INFO")
	}
}

func TestCheckServiceRestart(t *testing.T) {
	if got := checkServiceRestart(models.ServiceRestartInfo{Available: false}); got != nil {
		t.Errorf("absent must be nil")
	}
	// clean → silent
	if got := checkServiceRestart(models.ServiceRestartInfo{Available: true, StaleCount: 0}); len(got) != 0 {
		t.Errorf("no stale libs should be silent, got %+v", got)
	}
	// stale → WARN
	stale := models.ServiceRestartInfo{Available: true, StaleCount: 2, StaleNames: []string{"sshd", "dbus-broker"}}
	got := checkServiceRestart(stale)
	if !hasInsightMsg(got, "WARN", "OLD code") {
		t.Errorf("stale-lib processes must WARN: %+v", got)
	}
	// non-root partial scan with no finds → INFO, NOT a clean OK (honesty)
	if !hasInsightMsg(checkServiceRestart(models.ServiceRestartInfo{Available: true, StaleCount: 0, NeedsRoot: true}), "INFO", "partial") {
		t.Errorf("partial non-root scan must INFO, not silently pass")
	}
}
