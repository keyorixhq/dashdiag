package analysis

import (
	"fmt"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// checkKafka surfaces health issues for a local Kafka broker. Gated on Detected.
// The headline is OFFLINE partitions: a partition with no leader can be neither
// produced to nor consumed from — its data is unavailable, a live outage.
// Under-replicated partitions are the softer signal (no redundancy). Never a
// silent OK when topic metadata couldn't be read.
func checkKafka(k models.KafkaInfo) []models.Insight {
	if !k.Detected {
		return nil
	}

	if !k.MetricsRead {
		return []models.Insight{insight("INFO", "Kafka",
			"Kafka's broker port is up, but topic metadata could not be read",
			[]string{
				"note: the kafka CLI must reach the bootstrap server (SSL/SASL auth may be required)",
				"to inspect: kafka-topics.sh --bootstrap-server localhost:9092 --describe --unavailable-partitions",
			},
		)}
	}

	var out []models.Insight

	// Offline partitions have no leader — produces and consumes for them fail.
	if k.OfflinePartitions > 0 {
		msg := fmt.Sprintf("%d partition(s) are OFFLINE (no leader) — produces and consumes for them are FAILING; data is unavailable", k.OfflinePartitions)
		if k.OfflineDetail != "" {
			msg += " (e.g. " + k.OfflineDetail + ")"
		}
		out = append(out, insight("CRIT", "Kafka", msg,
			[]string{
				"to inspect: kafka-topics.sh --bootstrap-server localhost:9092 --describe --unavailable-partitions",
				"note: a partition goes offline when every replica's broker is down — check that the leader's broker is up and rejoined",
			}))
	}

	// Under-replicated partitions: replicas not in the ISR — no redundancy.
	if k.UnderReplicatedPartitions > 0 {
		msg := fmt.Sprintf("%d partition(s) under-replicated — replicas are not in sync, so there is no redundancy", k.UnderReplicatedPartitions)
		if k.URPDetail != "" {
			msg += " (e.g. " + k.URPDetail + ")"
		}
		out = append(out, insight("WARN", "Kafka", msg,
			[]string{
				"to inspect: kafka-topics.sh --bootstrap-server localhost:9092 --describe --under-replicated-partitions",
				"note: a follower fell behind or its broker is down; a further broker loss could take these partitions offline",
			}))
	}

	return out
}
