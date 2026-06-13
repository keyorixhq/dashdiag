package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// When pvedaemon exists and we are root but the pvesh API probe failed, every
// PVE collection is empty. Without the APIReachable guard the node read as a clean
// "healthy" with quorum implicitly OK (false-OK). checkPVE must instead surface a
// WARN that health could not be verified — and must NOT emit a spurious "quorum
// LOST" CRIT (QuorumOK is false on the failure path, but we don't actually know).
func TestPVEAPIUnreachableIsNotHealthy(t *testing.T) {
	unreachable := models.PVEInfo{IsPVE: true, NeedsRoot: false, APIReachable: false, QuorumOK: false}
	got := checkPVE(unreachable)
	if !hasInsight(got, "WARN", "not responding") {
		t.Errorf("API-unreachable PVE node must WARN 'not verified', got %+v", got)
	}
	if hasInsight(got, "CRIT", "quorum LOST") {
		t.Errorf("must not claim quorum LOST when the API was never reached, got %+v", got)
	}

	// A reachable standalone node (no cluster, quorum implicitly OK) stays clean.
	standalone := models.PVEInfo{IsPVE: true, NeedsRoot: false, APIReachable: true, QuorumOK: true}
	if got := checkPVE(standalone); hasInsight(got, "WARN", "not responding") {
		t.Errorf("a reachable node must not report API-unreachable, got %+v", got)
	}

	// A reachable node with genuine quorum loss still CRITs (the guard didn't mask it).
	quorumLost := models.PVEInfo{IsPVE: true, NeedsRoot: false, APIReachable: true, QuorumOK: false, ClusterName: "cl"}
	if got := checkPVE(quorumLost); !hasInsight(got, "CRIT", "quorum LOST") {
		t.Errorf("a reachable node with quorum loss must still CRIT, got %+v", got)
	}
}
