package render

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/baseline"
	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestVerdict_NeedsRootFloorTable(t *testing.T) {
	skip := models.Insight{Level: "INFO", Check: "Hardening", Unverified: true, NeedsRoot: true, Message: "/etc/shadow not readable"}
	other := models.Insight{Level: "INFO", Check: "K8s", Unverified: true, Message: "API unreachable"}
	warn := models.Insight{Level: "WARN", Check: "Disk", Message: "disk 85%"}
	rootRun := models.Insight{Level: "INFO", Check: "Hardening", Unverified: true, Message: "/etc/shadow not readable"} // as root: NeedsRoot unset

	cases := []struct {
		name         string
		ins          []models.Insight
		level        string
		exit         int
		unverified   int
		needsRoot    int
		skippedCheck int
	}{
		{"needs-root only (non-root)", []models.Insight{skip}, "OK", 0, 1, 1, 1},
		{"same read failing as root", []models.Insight{rootRun}, "WARN", 1, 1, 0, 0},
		{"needs-root plus another unverified", []models.Insight{skip, other}, "WARN", 1, 2, 1, 1},
		{"needs-root plus a real WARN", []models.Insight{skip, warn}, "WARN", 1, 1, 1, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := Verdict(nil, c.ins)
			if v.Level != c.level || v.ExitCode() != c.exit || v.Unverified != c.unverified || v.NeedsRoot != c.needsRoot || v.Skipped != c.skippedCheck {
				t.Errorf("Verdict = %+v, want level %s exit %d unverified %d needs_root %d skipped %d",
					v, c.level, c.exit, c.unverified, c.needsRoot, c.skippedCheck)
			}
		})
	}
}

// A stored snapshot derives the same verdict as the run that wrote it.
func TestSnapshotVerdict_NeedsRootMatchesRun(t *testing.T) {
	ins := []models.Insight{{Level: "INFO", Check: "Hardening", Unverified: true, NeedsRoot: true, Message: "m"}}
	snap := &baseline.Snapshot{Checks: []baseline.CheckResult{{Name: "Hardening", Status: "INFO", Unverified: true, NeedsRoot: true}}}
	if got, want := SnapshotVerdict(snap), Verdict(nil, ins); got.Level != want.Level || got.NeedsRoot != want.NeedsRoot {
		t.Errorf("SnapshotVerdict = %+v, Verdict = %+v: must agree", got, want)
	}
}
