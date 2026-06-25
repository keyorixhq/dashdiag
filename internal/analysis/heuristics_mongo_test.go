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
	// replica set healthy (rs.status() read, has primary) → silent
	if got := checkMongoDB(models.MongoDBInfo{Detected: true, MetricsRead: true, IsReplicaSet: true, ReplStatusRead: true, ReplicaSetName: "rs0", HasPrimary: true, Members: 3, ConnCurrent: 5, ConnAvailable: 1000}); len(got) != 0 {
		t.Errorf("healthy replica set should be silent, got %+v", got)
	}
	// no primary (rs.status() read confirmed it) → CRIT
	noPrimary := checkMongoDB(models.MongoDBInfo{Detected: true, MetricsRead: true, IsReplicaSet: true, ReplStatusRead: true, ReplicaSetName: "rs0", HasPrimary: false, Members: 3})
	if !insightWithMsg(noPrimary, "CRIT", "NO PRIMARY") {
		t.Errorf("no primary should CRIT, got %+v", noPrimary)
	}
	// rs.status() could NOT be read (auth-gated) — must NOT cry wolf with a
	// no-primary CRIT; honest INFO instead. This is the false-CRIT fix.
	unread := checkMongoDB(models.MongoDBInfo{Detected: true, MetricsRead: true, IsReplicaSet: true, ReplStatusRead: false, ReplicaSetName: "rs0"})
	if insightWithMsg(unread, "CRIT", "NO PRIMARY") {
		t.Errorf("unread rs.status() must NOT fire the no-primary CRIT, got %+v", unread)
	}
	if !insightWithMsg(unread, "INFO", "could not be read") {
		t.Errorf("unread rs.status() should INFO, got %+v", unread)
	}
	// down member (has primary) → WARN
	down := checkMongoDB(models.MongoDBInfo{Detected: true, MetricsRead: true, IsReplicaSet: true, ReplStatusRead: true, HasPrimary: true, Members: 3, DownMembers: 1})
	if !insightWithMsg(down, "WARN", "unreachable") {
		t.Errorf("down member should WARN, got %+v", down)
	}
	// conn saturation → WARN
	sat := checkMongoDB(models.MongoDBInfo{Detected: true, MetricsRead: true, ConnCurrent: 95, ConnAvailable: 5})
	if !insightWithMsg(sat, "WARN", "approaching the limit") {
		t.Errorf("conn saturation should WARN, got %+v", sat)
	}
}
