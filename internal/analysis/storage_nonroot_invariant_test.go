package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Storage-HA collectors read root-gated sources (ceph admin keyring, drbdsetup
// netlink, iscsiadm's 0400 sysfs fields, multipathd's socket / devmapper ioctl). The
// binary-level non-root CI invariant (scripts/check-nonroot-invariant.sh) can't
// exercise them — the GitHub runner has no Ceph/DRBD/iSCSI/SAN — so this is the
// off-CI guard for that class: given the collector's "couldn't read as non-root"
// state, the verdict must SURFACE it (a non-empty INFO/WARN "needs root / could not
// verify") and NEVER escalate to a false CRIT (the Ceph false-"unreachable" bug, #598)
// nor stay silently OK (the DRBD-9 / iSCSI silent-omission bugs, #600/#612).
//
// When you add a storage/SAN collector with a root-gated read, add its unverified
// state here so a future regression to silence-or-false-CRIT is caught deterministically.
func TestStorageHANonRootDegradesHonestly(t *testing.T) {
	cases := []struct {
		name string
		run  func() []models.Insight
	}{
		{"ceph non-root (keyring root-only)", func() []models.Insight {
			return checkCeph(models.CephInfo{Configured: true, NeedsRoot: true})
		}},
		{"drbd9 non-root (netlink needs CAP_NET_ADMIN)", func() []models.Insight {
			return checkDRBD(models.DRBDInfo{Version: "9.1.0", Unverified: true})
		}},
		{"iscsi non-root (session sysfs 0400)", func() []models.Insight {
			return checkISCSI(models.ISCSIInfo{Available: true, NeedsRoot: true})
		}},
		{"multipath unreadable (root-only socket/ioctl)", func() []models.Insight {
			return checkMultipath(models.MultipathInfo{
				Available: true, Status: "error",
				StatusReason: "multipathd running but paths unreadable",
			})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ins := tc.run()
			if len(ins) == 0 {
				t.Fatalf("%s: unverified state produced NO insight — a silent false-OK; it must surface 'needs root / could not verify'", tc.name)
			}
			for _, in := range ins {
				if in.Level == "CRIT" {
					t.Errorf("%s: unverified state escalated to CRIT %q — must be INFO/WARN 'could not verify', not a false fault", tc.name, in.Message)
				}
			}
		})
	}
}
