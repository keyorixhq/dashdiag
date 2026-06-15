package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestCheckMongoDB(t *testing.T) {
	if got := checkMongoDB(models.MongoDBInfo{Detected: false}); got != nil {
		t.Errorf("undetected mongo should be silent, got %+v", got)
	}
	if got := checkMongoDB(models.MongoDBInfo{Detected: true, MetricsRead: false}); !insightWithMsg(got, "INFO", "could not be read") {
		t.Errorf("no metrics should be INFO, got %+v", got)
	}
	// standalone healthy → silent
	if got := checkMongoDB(models.MongoDBInfo{Detected: true, MetricsRead: true, ConnCurrent: 5, ConnAvailable: 1000}); len(got) != 0 {
		t.Errorf("healthy standalone should be silent, got %+v", got)
	}
	// replica set healthy (has primary) → silent
	if got := checkMongoDB(models.MongoDBInfo{Detected: true, MetricsRead: true, IsReplicaSet: true, ReplicaSetName: "rs0", HasPrimary: true, Members: 3, ConnCurrent: 5, ConnAvailable: 1000}); len(got) != 0 {
		t.Errorf("healthy replica set should be silent, got %+v", got)
	}
	// no primary → CRIT
	noPrimary := checkMongoDB(models.MongoDBInfo{Detected: true, MetricsRead: true, IsReplicaSet: true, ReplicaSetName: "rs0", HasPrimary: false, Members: 3})
	if !insightWithMsg(noPrimary, "CRIT", "NO PRIMARY") {
		t.Errorf("no primary should CRIT, got %+v", noPrimary)
	}
	// down member (has primary) → WARN
	down := checkMongoDB(models.MongoDBInfo{Detected: true, MetricsRead: true, IsReplicaSet: true, HasPrimary: true, Members: 3, DownMembers: 1})
	if !insightWithMsg(down, "WARN", "unreachable") {
		t.Errorf("down member should WARN, got %+v", down)
	}
	// conn saturation → WARN
	sat := checkMongoDB(models.MongoDBInfo{Detected: true, MetricsRead: true, ConnCurrent: 95, ConnAvailable: 5})
	if !insightWithMsg(sat, "WARN", "approaching the limit") {
		t.Errorf("conn saturation should WARN, got %+v", sat)
	}
}
