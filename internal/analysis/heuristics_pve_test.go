package analysis

import (
	"strings"
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// TestCheckPVEClusterOfflineNode_UnsafeNodeNameWithheld is the regression
// test for internal-analysis-06-05: PVENode.Name is parsed verbatim from the
// cluster status response with no charset restriction. The "to inspect: ssh
// root@<node> '...'" hint for an OFFLINE node is a copy-pasteable shell
// command, so a node name containing shell metacharacters must never be
// spliced into it — mirrors the RAUCInactiveSlot fix in heuristics_steamos.go
// (TestCheckSteamOSBadInactiveSlot_UnsafeSlotNameWithheld).
func TestCheckPVEClusterOfflineNode_UnsafeNodeNameWithheld(t *testing.T) {
	t.Parallel()
	// checkPVECluster only walks p.Nodes for the OFFLINE hint when the
	// cluster has more than one node — include a second, healthy node so the
	// offline branch actually fires.
	p := models.PVEInfo{
		IsPVE: true, QuorumOK: true,
		Nodes: []models.PVENode{
			{Name: "pve01; rm -rf ~", Online: false, Version: "8.1"},
			{Name: "pve02", Online: true, Version: "8.1"},
		},
	}
	got := checkPVECluster(p)
	if !hasInsight(got, "CRIT", "is OFFLINE") {
		t.Fatalf("expected a CRIT offline-node insight, got %+v", got)
	}
	for _, ins := range got {
		for _, h := range ins.Hints {
			if strings.Contains(h, "rm -rf") {
				t.Errorf("unsafe node name was spliced into a copy-pasteable hint: %q", h)
			}
			if strings.Contains(h, "ssh root@pve01; rm -rf ~") {
				t.Errorf("unsafe node name was spliced verbatim into the ssh hint: %q", h)
			}
		}
	}
}

// TestCheckPVEClusterOfflineNode_SafeNodeNameStillGetsSSHHint is the
// complementary happy-path check: a node name made only of characters
// looksLikeSafeToken allows must still produce the actionable, copy-pasteable
// ssh hint (the fix must not regress the common case).
func TestCheckPVEClusterOfflineNode_SafeNodeNameStillGetsSSHHint(t *testing.T) {
	t.Parallel()
	p := models.PVEInfo{
		IsPVE: true, QuorumOK: true,
		Nodes: []models.PVENode{
			{Name: "pve01", Online: false, Version: "8.1"},
			{Name: "pve02", Online: true, Version: "8.1"},
		},
	}
	got := checkPVECluster(p)
	if !hasInsight(got, "CRIT", "is OFFLINE") {
		t.Fatalf("expected a CRIT offline-node insight, got %+v", got)
	}
	want := "to inspect: ssh root@pve01 'systemctl status pve-cluster corosync'"
	found := false
	for _, ins := range got {
		for _, h := range ins.Hints {
			if h == want {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("expected safe node name to produce hint %q, got %+v", want, got)
	}
}
