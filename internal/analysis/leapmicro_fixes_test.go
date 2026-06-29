package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Finding 1 (heuristic side): when SELinux is present but its mode is "unknown"
// (the enforce node was unreadable), the verdict must degrade to an honest
// "mode unreadable" INFO — never the false "kernel security module not enforced"
// that an unprivileged operator would read as "security is off".
func TestKernelSecSELinuxUnknownIsHonestNotFalseNotEnforced(t *testing.T) {
	mac := models.KernelSecurityInfo{SELinuxPresent: true, SELinuxMode: "unknown"}
	got := checkKernelSecurity(mac, defaultThresh)
	if !hasInsightMsg(got, "INFO", "enforce state could not be read") {
		t.Errorf("want 'enforce state could not be read' INFO, got %#v", got)
	}
	if hasInsightMsg(got, "INFO", "not enforced") {
		t.Errorf("present-but-unknown SELinux must NOT report 'not enforced': %#v", got)
	}
	// SELinux's enforce node is world-readable, so an unknown mode is NOT a
	// privilege gap — re-running as root would not help, so don't claim it would.
	if hasInsightMsg(got, "INFO", "re-run as root") {
		t.Errorf("SELinux-indeterminate must NOT advise 're-run as root' (enforce node is world-readable): %#v", got)
	}
}

// AppArmor's mode lives in a root-only node, so an "unknown" mode there IS a
// privilege gap — it must keep advising "re-run as root" (the asymmetry the
// SELinux fix above must not break).
func TestKernelSecAppArmorUnknownStillAdvisesRoot(t *testing.T) {
	mac := models.KernelSecurityInfo{AppArmorPresent: true, AppArmorMode: "unknown"}
	got := checkKernelSecurity(mac, defaultThresh)
	if !hasInsightMsg(got, "INFO", "re-run as root") {
		t.Errorf("AppArmor-indeterminate (root-only profiles node) should advise re-run as root: %#v", got)
	}
}

// Enforcing SELinux must never render the "not enforced" verdict (the non-root
// false-OK this change fixes — root saw "enforcing", non-root saw "not enforced").
func TestKernelSecSELinuxEnforcingNotFalseNotEnforced(t *testing.T) {
	mac := models.KernelSecurityInfo{SELinuxPresent: true, SELinuxMode: "enforcing"}
	if hasInsightMsg(checkKernelSecurity(mac, defaultThresh), "INFO", "not enforced") {
		t.Errorf("enforcing SELinux wrongly reported as not enforced")
	}
}

// Finding 2: a read-only btrfs root on an immutable OS (transactional-update /
// MicroOS / Leap Micro / SteamOS) is read-only BY DESIGN — it must not WARN; the
// same ro root on a normal host is an error remount and must WARN.
func TestCheckDiskImmutableRootSuppressesReadOnlyWarn(t *testing.T) {
	roRoot := models.FilesystemInfo{
		Mount: "/", Device: "/dev/sda3", FSType: "btrfs", ReadOnly: true,
		TotalGB: 20, UsedGB: 5, UsedPct: 25,
	}
	immutable := models.DiskInfo{Filesystems: []models.FilesystemInfo{roRoot}, ImmutableRootFS: true}
	if hasInsightMsg(checkDisk(immutable, defaultThresh), "WARN", "mounted READ-ONLY") {
		t.Errorf("immutable-OS read-only root must NOT WARN")
	}
	normal := models.DiskInfo{Filesystems: []models.FilesystemInfo{roRoot}, ImmutableRootFS: false}
	if !hasInsightMsg(checkDisk(normal, defaultThresh), "WARN", "mounted READ-ONLY") {
		t.Errorf("read-only root on a normal (non-immutable) host must WARN")
	}
}
