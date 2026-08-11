package analysis

import (
	"errors"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/platform"
	"github.com/keyorixhq/dashdiag/internal/runner"
)

// TestUnverifiedInsightHelper guards the primitive itself: it must behave
// exactly like insight() (same Level/Check/Message/Hints) plus Unverified set.
func TestUnverifiedInsightHelper(t *testing.T) {
	t.Parallel()
	got := unverifiedInsight("INFO", "Widget", "could not read widget state", []string{"hint"})
	if got.Level != "INFO" || got.Check != "Widget" || got.Message != "could not read widget state" || !got.Unverified {
		t.Errorf("unverifiedInsight() = %+v, want Level=INFO Check=Widget Message=%q Unverified=true",
			got, "could not read widget state")
	}
	if len(got.Hints) != 1 || got.Hints[0] != "hint" {
		t.Errorf("Hints = %+v, want [hint]", got.Hints)
	}
}

// TestApplyThresholds_CollectorErrorIsUnverified guards the single most
// mechanical case: when a collector itself errors, ApplyThresholds must mark
// the resulting INFO insight Unverified — this is the case baseline can also
// see directly via runner.Result.Err, but the Insight-level flag is what
// actually reaches CheckResult.Unverified through BuildSnapshot.
func TestApplyThresholds_CollectorErrorIsUnverified(t *testing.T) {
	t.Parallel()
	results := []runner.Result{{Name: "Network", Err: errors.New("timeout")}}
	insights := ApplyThresholds(results, Thresholds{}, platform.CloudEnvironment(0), platform.ContainerContext{})
	if len(insights) != 1 {
		t.Fatalf("want 1 insight, got %d: %+v", len(insights), insights)
	}
	if !insights[0].Unverified {
		t.Errorf("Unverified = false, want true — a collector error is never a confirmed finding")
	}
	if insights[0].Level != "INFO" {
		t.Errorf("Level = %q, want INFO", insights[0].Level)
	}
}

// TestHeuristics_UnverifiedSpotCheck spot-checks representative unverifiedInsight
// call sites across several independent subsystems converted alongside the
// internal/baseline false-clean fix (a WARN/CRIT that becomes unverifiable on a
// re-run must never diff as "Improved" — see baseline.ComputeDiff). Each case
// below exercises a real heuristic function with the specific input that
// triggers its "could not measure" path.
func TestHeuristics_UnverifiedSpotCheck(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		insight models.Insight
	}{
		{"Vault API unreadable", checkVault(models.VaultInfo{Available: true, Reachable: true, StatusRead: false, HTTPStatus: 0})[0]},
		{"PVE needs root", checkPVE(models.PVEInfo{IsPVE: true, NeedsRoot: true})[0]},
		{"HWRaid needs root", checkHWRaid(models.HWRaidInfo{Available: true, NeedsRoot: true})[0]},
		{"HA status unreadable", checkHA(models.HAInfo{Available: true, Running: true, StatusReadable: false})[0]},
		{"IPMI needs root", checkIPMI(models.IPMIInfo{NeedsRoot: true})[0]},
		{"Ceph needs root", checkCeph(models.CephInfo{Available: false, NeedsRoot: true})[0]},
		{"iSCSI needs root", checkISCSI(models.ISCSIInfo{NeedsRoot: true})[0]},
		{"ZFS list read failed", checkZFS(models.ZFSInfo{ListReadFailed: true})[0]},
		{"DRBD unreadable, no resources", checkDRBD(models.DRBDInfo{Unverified: true})[0]},
		{"Sessions unchecked", checkSessions(models.SessionsInfo{Checked: false})[0]},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !c.insight.Unverified {
				t.Errorf("%s: Unverified = false, want true", c.name)
			}
			if c.insight.Message == "" {
				t.Errorf("%s: Message is empty", c.name)
			}
		})
	}
}

// TestHeuristics_ConfirmedFindingsStayNotUnverified is the contrast case: a
// confirmed problem (data WAS read, and it's bad) must never be marked
// Unverified, even when the message happens to reference privilege or the
// word "unreadable" in an unrelated clause — only a genuine measurement gap
// should carry the flag.
func TestHeuristics_ConfirmedFindingsStayNotUnverified(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		insight models.Insight
	}{
		{"Vault confirmed down", checkVault(models.VaultInfo{Available: true, Reachable: false})[0]},
		{"HWRaid confirmed degraded", func() models.Insight {
			out := checkHWRaid(models.HWRaidInfo{Available: true, Controllers: []models.HWRaidController{{
				VirtualDrives: []models.HWRaidVD{{Name: "vd0", Degraded: true, RaidLevel: "RAID5"}},
			}}})
			return out[0]
		}()},
		{"iSCSI confirmed session failure", checkISCSI(models.ISCSIInfo{
			Available: true, Sessions: []models.ISCSISession{{}}, FailedCount: 1,
		})[0]},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.insight.Unverified {
				t.Errorf("%s: Unverified = true, want false — this is a confirmed finding, not a measurement gap", c.name)
			}
		})
	}
}
