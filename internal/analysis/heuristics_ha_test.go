package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestCheckHA(t *testing.T) {
	base := models.HAInfo{ // a healthy, fully-fenced single-node cluster
		Available: true, Running: true, StatusReadable: true,
		QuorumKnown: true, Quorate: true, NodesOnline: 2, NodesTotal: 2,
		ResourcesStarted: 1, ResourcesTotal: 1, StonithEnabled: true, StonithDevices: 1,
	}
	if got := checkHA(models.HAInfo{Available: false}); got != nil {
		t.Error("absent cluster stack must be nil (silent on non-cluster hosts)")
	}
	if got := checkHA(base); len(got) != 0 {
		t.Errorf("healthy fenced cluster must be silent, got %+v", got)
	}
	if !hasInsightMsg(checkHA(models.HAInfo{Available: true, Running: false}), "WARN", "not running") {
		t.Error("installed-but-stopped stack must WARN")
	}
	if !hasInsightMsg(checkHA(models.HAInfo{Available: true, Running: true, StatusReadable: false}), "INFO", "could not be read") {
		t.Error("running-but-unreadable (non-root) must INFO, not imply healthy")
	}
	noQuorum := base
	noQuorum.Quorate = false
	if !hasInsightMsg(checkHA(noQuorum), "CRIT", "LOST QUORUM") {
		t.Error("lost quorum must CRIT")
	}
	offline := base
	offline.NodesOnline, offline.OfflineNodes = 1, []string{"node2"}
	if !hasInsightMsg(checkHA(offline), "CRIT", "OFFLINE") {
		t.Error("offline node must CRIT")
	}
	failed := base
	failed.FailedResources = []string{"vip"}
	if !hasInsightMsg(checkHA(failed), "CRIT", "FAILED") {
		t.Error("failed resource must CRIT")
	}
	noFence := base
	noFence.StonithEnabled = false
	if !hasInsightMsg(checkHA(noFence), "WARN", "STONITH") {
		t.Error("disabled fencing must WARN (split-brain risk)")
	}
	noDevice := base
	noDevice.StonithDevices = 0
	if !hasInsightMsg(checkHA(noDevice), "WARN", "NO fence device") {
		t.Error("fencing enabled but no device must WARN")
	}
}
