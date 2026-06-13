package analysis

import "testing"

// These classifiers are the single source of truth shared by `dsd health`
// (checkLVM / PVE heuristics) and the dedicated renderers (`dsd disk`, `dsd pve`).
// Before they existed the two sides used different inline thresholds, so the same
// volume read WARN in one command and OK/CRIT in the other (BUG-050 class). Pinning
// the boundaries here keeps both consumers in agreement and prevents re-drift.
func TestLVMPVELevelBoundaries(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		// Thin pool: WARN 80, CRIT 90.
		{"thin 79 ok", LVMThinPoolLevel(79), ""},
		{"thin 80 warn", LVMThinPoolLevel(80), "WARN"},
		{"thin 89 warn", LVMThinPoolLevel(89), "WARN"},
		{"thin 90 crit", LVMThinPoolLevel(90), "CRIT"},
		// Snapshot: WARN 80, CRIT 95 (tolerates higher fill than a pool).
		{"snap 79 ok", LVMSnapshotLevel(79), ""},
		{"snap 80 warn", LVMSnapshotLevel(80), "WARN"},
		{"snap 94 warn", LVMSnapshotLevel(94), "WARN"},
		{"snap 95 crit", LVMSnapshotLevel(95), "CRIT"},
		// VG: takes FREE %, classifies used (100-free). WARN at <=10 free, CRIT at <=2 free.
		{"vg 11 free ok", LVMVGFullLevel(11), ""},
		{"vg 10 free warn", LVMVGFullLevel(10), "WARN"},
		{"vg 3 free warn", LVMVGFullLevel(3), "WARN"},
		{"vg 2 free crit", LVMVGFullLevel(2), "CRIT"},
		// PVE storage: WARN 80, CRIT 90.
		{"pve 79 ok", PVEStorageLevel(79), ""},
		{"pve 80 warn", PVEStorageLevel(80), "WARN"},
		{"pve 89 warn", PVEStorageLevel(89), "WARN"},
		{"pve 90 crit", PVEStorageLevel(90), "CRIT"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.got != c.want {
				t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
			}
		})
	}
}
