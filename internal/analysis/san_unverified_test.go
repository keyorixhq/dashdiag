package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// SAN/volume "couldn't read → silent OK" closures (FALSE_OK_SWEEP #19/#20).

func TestMultipathPathsUnreadableIsWarn(t *testing.T) {
	// multipathd running but both path queries failed → Status="error", Devices empty.
	got := checkMultipath(models.MultipathInfo{
		Available: true, Status: "error", StatusReason: "multipathd running but paths unreadable",
	})
	if !hasInsightMsg(got, "WARN", "could NOT be verified") {
		t.Errorf("unreadable multipath paths must WARN, got %+v", got)
	}
	// genuinely no maps configured (no error) → clean.
	if got := checkMultipath(models.MultipathInfo{Available: true}); len(got) != 0 {
		t.Errorf("no maps + no error must be clean, got %+v", got)
	}
	// absent → clean.
	if got := checkMultipath(models.MultipathInfo{}); len(got) != 0 {
		t.Errorf("absent multipath must be clean, got %+v", got)
	}
}

// A DRBD 9 host whose resource state can't be read (netlink needs root) must say
// "needs root", not silently omit DRBD (which would hide a split-brain/diskless res).
func TestDRBDUnverifiedIsInfoNotSilent(t *testing.T) {
	got := checkDRBD(models.DRBDInfo{Version: "9.1.0", Unverified: true})
	if !hasInsightMsg(got, "INFO", "needs root") {
		t.Errorf("unverified DRBD 9 must emit a needs-root INFO, got %+v", got)
	}
	// Verified, no resources → clean (genuinely no configured resources).
	if got := checkDRBD(models.DRBDInfo{Version: "9.1.0"}); len(got) != 0 {
		t.Errorf("verified DRBD with no resources must be clean, got %+v", got)
	}
}

func TestLVMQueryFailuresAreInfo(t *testing.T) {
	cases := []struct {
		name string
		info models.LVMInfo
		want string
	}{
		{"pvs failed", models.LVMInfo{PVReadFailed: true}, "physical-volume state could NOT be verified"},
		{"vgs failed", models.LVMInfo{VGReadFailed: true}, "volume-group state could NOT be verified"},
		{"lvs failed", models.LVMInfo{LVReadFailed: true}, "logical-volume state could NOT be verified"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := checkLVM(tc.info); !hasInsightMsg(got, "INFO", tc.want) {
				t.Errorf("%s must INFO %q, got %+v", tc.name, tc.want, got)
			}
		})
	}
	// A clean LVM host (no failures, no VGs) emits nothing.
	if got := checkLVM(models.LVMInfo{}); len(got) != 0 {
		t.Errorf("clean LVM must be silent, got %+v", got)
	}
}

// Active iSCSI sessions whose state can't be read unprivileged (iscsiadm's per-session
// sysfs fields are root-only) must surface "needs root", never be silently omitted —
// else a failed/reconnecting session is invisible to a non-root health run.
func TestISCSINeedsRootIsInfoNotSilent(t *testing.T) {
	got := checkISCSI(models.ISCSIInfo{Available: true, NeedsRoot: true})
	if !hasInsightMsg(got, "INFO", "needs root") {
		t.Errorf("iSCSI NeedsRoot must emit a needs-root INFO, got %+v", got)
	}
	// Genuinely no sessions (not NeedsRoot) → silent.
	if got := checkISCSI(models.ISCSIInfo{Available: true}); len(got) != 0 {
		t.Errorf("no sessions must be silent, got %+v", got)
	}
	// A real failed session still CRITs (unchanged).
	fail := models.ISCSIInfo{Available: true, Sessions: []models.ISCSISession{{State: "FAILED"}}, FailedCount: 1}
	if !hasInsightMsg(checkISCSI(fail), "CRIT", "not logged in") {
		t.Errorf("a failed session must still CRIT, got %+v", checkISCSI(fail))
	}
}
