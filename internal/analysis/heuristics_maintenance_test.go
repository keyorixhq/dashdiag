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
	// BUG-088: SUSE zypp lock held the whole budget → reboot status genuinely unknown.
	// Must surface INFO "could not be determined", never a silent OK (nil) or a WARN.
	unv := checkKernelPatch(models.KernelPatchInfo{Available: true, CheckUnverified: true, RebootNeeded: false})
	if !hasInsightMsg(unv, "INFO", "could not be determined") {
		t.Errorf("zypp-locked kernel must surface INFO 'could not be determined', not a clean OK: %+v", unv)
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
	// stale AND non-root: the WARN fired first and returned before the NeedsRoot
	// check ever ran, so a partial count was asserted as exact — false precision,
	// not false-clean, but the same root cause. The WARN must still fire (real
	// staleness found) but must also disclose the count may be a floor.
	staleNonRoot := models.ServiceRestartInfo{
		Available: true, StaleCount: 2, StaleNames: []string{"sshd", "dbus-broker"}, NeedsRoot: true,
	}
	if !hasInsightMsg(checkServiceRestart(staleNonRoot), "WARN", "OLD code") {
		t.Errorf("stale-lib processes must still WARN even when the scan was partial")
	}
	if !hasInsightMsg(checkServiceRestart(staleNonRoot), "WARN", "non-root and partial") {
		t.Errorf("WARN must disclose the scan was non-root/partial, not assert an exact count")
	}
}

func TestCheckKernelRetention(t *testing.T) {
	if got := checkKernelRetention(models.KernelRetentionInfo{Available: false}); got != nil {
		t.Errorf("absent must be nil")
	}
	// A /boot on a roomy root fs is never a concern, even with many kernels.
	roomy := models.KernelRetentionInfo{Available: true, PackageManager: "zypper", InstalledKernels: 6, BootTotalGB: 30, BootUsedPct: 8}
	if got := checkKernelRetention(roomy); len(got) != 0 {
		t.Errorf("roomy /boot must be silent, got %+v", got)
	}
	// Small separate /boot, near full, several kernels → WARN.
	full := models.KernelRetentionInfo{Available: true, PackageManager: "dnf", InstalledKernels: 4, BootTotalGB: 0.5, BootUsedPct: 85}
	if !hasInsightMsg(checkKernelRetention(full), "WARN", "next kernel update can fail") {
		t.Errorf("small near-full /boot with kernels must WARN: %+v", checkKernelRetention(full))
	}
	// ≥90% → CRIT.
	crit := models.KernelRetentionInfo{Available: true, PackageManager: "dnf", InstalledKernels: 5, BootTotalGB: 0.5, BootUsedPct: 93}
	if !hasInsightMsg(checkKernelRetention(crit), "CRIT", "next kernel update") {
		t.Errorf("near-full /boot must CRIT at ≥90%%: %+v", checkKernelRetention(crit))
	}
	// Unbounded retention + a growing pile → WARN even on a roomy /boot.
	unb := models.KernelRetentionInfo{Available: true, PackageManager: "zypper", Unbounded: true, RetentionPolicy: "all", InstalledKernels: 6, BootTotalGB: 30, BootUsedPct: 20}
	if !hasInsightMsg(checkKernelRetention(unb), "WARN", "unbounded") {
		t.Errorf("unbounded retention with a pile must WARN: %+v", checkKernelRetention(unb))
	}
	// Unbounded but only a couple kernels → not yet a concern.
	few := models.KernelRetentionInfo{Available: true, PackageManager: "zypper", Unbounded: true, InstalledKernels: 2, BootTotalGB: 30, BootUsedPct: 20}
	if got := checkKernelRetention(few); len(got) != 0 {
		t.Errorf("unbounded but few kernels should be silent, got %+v", got)
	}
}

func TestCheckLivePatch(t *testing.T) {
	if got := checkLivePatch(models.LivePatchInfo{Available: false}); got != nil {
		t.Error("no livepatch loaded must be nil (silent)")
	}
	// loaded + all enabled → silent (healthy: kernel is live-patched)
	healthy := models.LivePatchInfo{Available: true, PatchesLoaded: 2, PatchesEnabled: 2}
	if got := checkLivePatch(healthy); len(got) != 0 {
		t.Errorf("all-enabled livepatches must be silent, got %+v", got)
	}
	// loaded but disabled → WARN (kernel running un-patched code)
	disabled := models.LivePatchInfo{Available: true, PatchesLoaded: 1, PatchesEnabled: 0, DisabledPatches: []string{"klp_fix"}}
	if !hasInsightMsg(checkLivePatch(disabled), "WARN", "NOT enabled") {
		t.Error("disabled livepatch must WARN")
	}
	// stuck in transition → WARN
	stuck := models.LivePatchInfo{Available: true, PatchesLoaded: 1, PatchesEnabled: 1, TransitioningPatches: []string{"klp_fix"}}
	if !hasInsightMsg(checkLivePatch(stuck), "WARN", "transition") {
		t.Error("transitioning livepatch must WARN")
	}
	// Non-root false-alarm guard: a loaded patch whose enabled-state couldn't be read must
	// degrade to INFO ("re-run as root"), NOT a WARN. The patch may well be active — we
	// never measured it — so asserting it's disabled would be a false-alarm under non-root.
	unverified := models.LivePatchInfo{Available: true, PatchesLoaded: 1, UnverifiedPatches: []string{"klp_fix"}}
	got := checkLivePatch(unverified)
	if !hasInsightMsg(got, "INFO", "could not be read") {
		t.Error("unverified livepatch must INFO (re-run as root)")
	}
	for _, in := range got {
		if in.Level == "WARN" || in.Level == "CRIT" {
			t.Errorf("unverified livepatch must NOT WARN/CRIT — that is a non-root false-alarm; got %s %q", in.Level, in.Message)
		}
	}
}

func TestCheckTransactional(t *testing.T) {
	if got := checkTransactional(models.TransactionalInfo{Available: false}); got != nil {
		t.Error("non-transactional host must be nil")
	}
	// clean transactional host (booted == default) → silent
	if got := checkTransactional(models.TransactionalInfo{Available: true, BootedSnapshot: 3, DefaultSnapshot: 3}); len(got) != 0 {
		t.Errorf("booted==default must be silent, got %+v", got)
	}
	// staged update (default != booted) → WARN
	pending := models.TransactionalInfo{Available: true, RebootPending: true, BootedSnapshot: 3, DefaultSnapshot: 4}
	if !hasInsightMsg(checkTransactional(pending), "WARN", "staged but NOT active") {
		t.Error("a staged transactional update (default != booted) must WARN")
	}
}
