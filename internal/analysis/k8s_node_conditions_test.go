package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// RKE2/k3s managed-etcd nodes carry an "EtcdIsVoter"=True condition meaning the node
// is a HEALTHY voting member of the etcd cluster. checkK8sNodes used to blanket-CRIT
// any node condition that was True (except Ready), so it false-CRIT'd every RKE2 etcd
// node with "EtcdIsVoter condition True — workloads may be evicted" (found live on a
// real RKE2 node, 2026-07-01). Only the standard pressure/unavailable conditions are
// faults when True; an unknown condition's polarity must not be assumed.
func TestCheckK8sNodesEtcdIsVoterNotAFault(t *testing.T) {
	// Verbatim conditions from the live RKE2 node (rke2-test, v1.35.6+rke2r1).
	healthyRKE2 := models.K8sInfo{
		Nodes: []models.K8sNodeInfo{{
			Name: "rke2-test",
			Conditions: map[string]string{
				"NetworkUnavailable": "False",
				"EtcdIsVoter":        "True",
				"MemoryPressure":     "False",
				"DiskPressure":       "False",
				"PIDPressure":        "False",
				"Ready":              "True",
			},
		}},
	}
	if got := checkK8sNodes(healthyRKE2); len(got) != 0 {
		t.Errorf("a healthy RKE2 etcd node must produce no node-condition insights, got %d: %+v", len(got), got)
	}

	// Regression guard: a genuine pressure condition (True) must still CRIT.
	underPressure := models.K8sInfo{
		Nodes: []models.K8sNodeInfo{{
			Name:       "worker-1",
			Conditions: map[string]string{"MemoryPressure": "True", "Ready": "True", "EtcdIsVoter": "True"},
		}},
	}
	got := checkK8sNodes(underPressure)
	if !hasInsightMsg(got, "CRIT", "MemoryPressure condition True") {
		t.Errorf("MemoryPressure=True must still CRIT; got %+v", got)
	}
	if hasInsightMsg(got, "CRIT", "EtcdIsVoter") {
		t.Errorf("EtcdIsVoter must never be flagged, even alongside a real pressure fault")
	}
}
