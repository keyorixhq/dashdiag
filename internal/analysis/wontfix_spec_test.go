package analysis

// wontfix_spec_test.go — specification test for a finding closed WONT_FIX in
// the adversarial review (VERIFICATION-2026-08.md §8). Pins a DECIDED
// behaviour, not a bug hunt. If it fails, either the behaviour drifted or the
// decision changed — revisit the decision before "fixing" the code.
//
// The INTENDED-case behaviour (a genuine ro-bind of the same real device is
// suppressed; an unrelated ro mount with no rw sibling still WARNs) is
// already covered by TestCheckDiskNixStoreROBindSuppressed in
// nixos_nix_store_ro_test.go. Not duplicated here.

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestSpec_InternalAnalysis1003_ROBindSuppressionTrustsDeviceStringAlone:
// internal-analysis-10-03 was closed WONT_FIX because a correct fix needs a
// collector-layer /proc/self/mountinfo major:minor field that doesn't
// currently exist — adding it isn't small without extending the
// capture/replay plumbing, crossing into new-subsystem territory (see
// VERIFICATION-2026-08.md §8). Pending that, roBindOfRWDevice's suppression
// (heuristics_storage.go) trusts fs.Device STRING equality alone, with no
// independent corroboration — not even a same-filesystem-type sanity check
// between the rw and ro entries sharing that string. A real bind mount always
// preserves fstype (it's the same block device mounted twice), so two entries
// with the same Device string but DIFFERENT FSType could never be a genuine
// bind — yet the check has no way to notice, because it only ever looks at
// the string. This test documents that accepted gap: it must NOT start
// cross-checking FSType (or anything else) without the decision being
// revisited, since that would silently change WARN suppression behaviour
// this decision left alone on purpose.
func TestSpec_InternalAnalysis1003_ROBindSuppressionTrustsDeviceStringAlone(t *testing.T) {
	t.Parallel()
	const sharedDeviceString = "/dev/mapper/coincidental-alias"

	disk := models.DiskInfo{
		Filesystems: []models.FilesystemInfo{
			// Real bind mounts always share FSType with their rw sibling — an
			// ext4-rw/xfs-ro pair sharing one Device string is physically
			// implausible as an actual bind of the same device, but the check
			// has no cross-check to notice: it suppresses purely on the string.
			{Mount: "/", Device: sharedDeviceString, FSType: "ext4", ReadOnly: false, TotalGB: 16, UsedGB: 2, UsedPct: 17},
			{Mount: "/data", Device: sharedDeviceString, FSType: "xfs", ReadOnly: true, TotalGB: 16, UsedGB: 2, UsedPct: 17},
		},
	}
	if hasInsightMsg(checkDisk(disk, defaultThresh), "WARN", "mounted READ-ONLY") {
		t.Errorf("expected the ro-bind suppression to fire on device-string equality alone (even across " +
			"mismatched FSType) — if this now WARNs, roBindOfRWDevice gained real corroboration beyond the " +
			"device string and internal-analysis-10-03 may actually be fixed; revisit the decision doc " +
			"rather than just accepting this result")
	}
}
