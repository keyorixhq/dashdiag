package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestCheckKafka(t *testing.T) {
	if got := checkKafka(models.KafkaInfo{Detected: false}); got != nil {
		t.Errorf("undetected kafka should be silent, got %+v", got)
	}

	// Broker port up but topic metadata unreadable → INFO, never a silent OK.
	noMeta := checkKafka(models.KafkaInfo{Detected: true, Accepting: true, MetricsRead: false})
	if !insightWithMsg(noMeta, "INFO", "topic metadata could not be read") {
		t.Errorf("unreadable metadata should be INFO, got %+v", noMeta)
	}

	// Healthy (offline + URP both read, none found) → silent.
	healthy := checkKafka(models.KafkaInfo{Detected: true, Accepting: true, MetricsRead: true, UnderReplicatedRead: true})
	if len(healthy) != 0 {
		t.Errorf("healthy kafka should be silent, got %+v", healthy)
	}

	// Offline read succeeded but the under-replicated query failed → INFO, never a
	// silent OK: redundancy is unverified when the URP query wasn't read.
	noURP := checkKafka(models.KafkaInfo{Detected: true, Accepting: true, MetricsRead: true, UnderReplicatedRead: false})
	if !insightWithMsg(noURP, "INFO", "redundancy is unverified") {
		t.Errorf("unread under-replication should INFO, got %+v", noURP)
	}

	// Offline partitions → CRIT (data unavailable).
	off := checkKafka(models.KafkaInfo{Detected: true, MetricsRead: true, UnderReplicatedRead: true, OfflinePartitions: 2,
		OfflineDetail: "Topic: orders Partition: 3 Leader: none Replicas: 1 Isr:"})
	if !insightWithMsg(off, "CRIT", "OFFLINE") {
		t.Fatalf("offline partitions should CRIT, got %+v", off)
	}
	if !insightWithMsg(off, "CRIT", "orders") {
		t.Errorf("CRIT should carry the sample partition detail, got %+v", off)
	}

	// Under-replicated only → WARN (no redundancy), not CRIT.
	urp := checkKafka(models.KafkaInfo{Detected: true, MetricsRead: true, UnderReplicatedRead: true, UnderReplicatedPartitions: 1})
	if !insightWithMsg(urp, "WARN", "under-replicated") {
		t.Errorf("under-replicated partitions should WARN, got %+v", urp)
	}
	if insightWithMsg(urp, "CRIT", "OFFLINE") {
		t.Errorf("under-replicated alone must not CRIT, got %+v", urp)
	}

	// Both conditions → both insights present (CRIT offline + WARN URP).
	both := checkKafka(models.KafkaInfo{Detected: true, MetricsRead: true, UnderReplicatedRead: true, OfflinePartitions: 1, UnderReplicatedPartitions: 4})
	if !insightWithMsg(both, "CRIT", "OFFLINE") || !insightWithMsg(both, "WARN", "under-replicated") {
		t.Errorf("offline+URP should yield both CRIT and WARN, got %+v", both)
	}
}
