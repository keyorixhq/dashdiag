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

// A partial /proc/drbd read (8.x: scanner.Err() after at least one resource
// line was already parsed, collectors/drbd_linux.go:185-192) must NOT discard
// the resources that WERE parsed — a resource read as SplitBrain before the
// read failed is a real CRIT and must still surface, alongside a disclosure
// that the list may be incomplete. Regression: checkDRBD used to check
// Unverified before scoring any resource, silently dropping this CRIT
// (exit code 2->0) on exactly the host where the DRBD check matters most.
func TestDRBDPartialReadKeepsParsedResources(t *testing.T) {
	got := checkDRBD(models.DRBDInfo{
		Version:    "8.4.10",
		Unverified: true,
		Resources:  []models.DRBDResource{{Minor: 0, ConnState: "SplitBrain"}},
	})
	if !hasInsightMsg(got, "CRIT", "SPLIT-BRAIN") {
		t.Errorf("a resource parsed before a partial read failed must still CRIT, got %+v", got)
	}
	if !hasInsightMsg(got, "INFO", "incomplete") {
		t.Errorf("a partial read with resources present must disclose the list may be incomplete, got %+v", got)
	}
	// The needs-root message is specific to the v9/netlink producer, which
	// never has Resources set — must not fire here.
	if hasInsightMsg(got, "INFO", "needs root") {
		t.Errorf("8.x partial-read disclosure must not claim \"DRBD 9\"/needs-root, got %+v", got)
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

// TestLVMPresenceCheckFailedNotSilentlyAbsent: the outer `lvs --version`
// presence gate itself couldn't confirm lvm2 is absent (found the binary but
// it errored) — this must surface as an unverified INFO, not fold into the
// same silence as a genuinely-no-LVM host, and must not fall through to the
// VG/PV/LV disclosures below (nothing was queried).
func TestLVMPresenceCheckFailedNotSilentlyAbsent(t *testing.T) {
	got := checkLVM(models.LVMInfo{PresenceReadFailed: true})
	if !hasInsightMsg(got, "INFO", "could not confirm whether LVM is installed") {
		t.Errorf("presence-check failure must INFO, got %+v", got)
	}
	if len(got) != 1 {
		t.Errorf("expected a single disclosure insight, got %+v", got)
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

// TestISCSISessionsParseFailedIsInfoNotSilent is the regression test for
// internal-collectors-17-02: sysfs confirms session(s) exist but iscsiadm's
// output didn't match the expected format, so session state (logged-in vs
// failed/reconnecting) couldn't be determined — this must surface as an
// unverified disclosure, never silently fall through to "no sessions."
func TestISCSISessionsParseFailedIsInfoNotSilent(t *testing.T) {
	got := checkISCSI(models.ISCSIInfo{Available: true, SessionsParseFailed: true})
	if !hasInsightMsg(got, "INFO", "could not be parsed") {
		t.Errorf("SessionsParseFailed must emit an unverified INFO, got %+v", got)
	}
}
