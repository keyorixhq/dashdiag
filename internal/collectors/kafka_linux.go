//go:build linux

package collectors

import (
	"context"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

const kafkaBootstrapLocal = "127.0.0.1:9092"

// kafkaCLI returns the kafka topics admin tool to use, or "" if none is installed
// (so a non-Kafka service on 9092 isn't mislabelled). Apache distributions ship
// `kafka-topics.sh`; some packages (Confluent, certain images) ship `kafka-topics`.
func kafkaCLI() string {
	for _, bin := range []string{"kafka-topics.sh", "kafka-topics"} {
		if _, err := lookPath(bin); err == nil {
			return bin
		}
	}
	return ""
}

// kafkaBootstrap returns the first reachable loopback broker address (and
// whether one was actually found reachable — internal-collectors-17-01: the
// KafkaAvailable() dial at collector-registration time and this Collect()
// call are separated by a real window in which concurrently-running
// collectors execute, so a broker that died in between must not have its
// prior liveness silently assumed here). Kafka often binds the IPv6
// wildcard, so try both families; default to the IPv4 form when neither
// answers, so callers still have a bootstrap address to pass to the CLI (the
// CLI's own connection failure is what actually surfaces as a real error).
func kafkaBootstrap() (addr string, reachable bool) {
	for _, a := range []string{kafkaBootstrapLocal, "[::1]:9092"} {
		if dialReachable("tcp", a, 300*time.Millisecond) {
			return a, true
		}
	}
	return kafkaBootstrapLocal, false
}

// KafkaAvailable reports whether a local Kafka broker is installed (a kafka CLI is
// present) and its broker port (9092) is reachable.
func KafkaAvailable() bool {
	if kafkaCLI() == "" {
		return false
	}
	for _, addr := range []string{kafkaBootstrapLocal, "[::1]:9092"} {
		if dialReachable("tcp", addr, 300*time.Millisecond) {
			return true
		}
	}
	return false
}

type KafkaCollector struct{}

func NewKafkaCollector() *KafkaCollector { return &KafkaCollector{} }

func (c *KafkaCollector) Name() string { return "Kafka" }

// Timeout is generous: the kafka CLI spins up a JVM per invocation (several
// seconds), and this collector runs two describe queries.
func (c *KafkaCollector) Timeout() time.Duration { return 20 * time.Second }

func (c *KafkaCollector) Collect(ctx context.Context) (interface{}, error) {
	cli := kafkaCLI()
	if cli == "" {
		return &models.KafkaInfo{Detected: false}, nil
	}
	server, reachable := kafkaBootstrap()
	info := &models.KafkaInfo{Detected: true, Accepting: reachable}

	// Offline (unavailable) partitions — no leader, so the data is unavailable.
	// A failure here means "couldn't look" (the CLI couldn't reach the broker, or
	// auth is required), not "healthy" — the port already answered.
	out, err := runCmd(ctx, cli, "--bootstrap-server", server, "--describe", "--unavailable-partitions")
	if err != nil {
		info.StatusReason = "kafka topic metadata unavailable (the CLI could not reach the bootstrap server; SSL/SASL auth may be required)"
		return info, nil
	}
	info.MetricsRead = true
	info.OfflinePartitions, info.OfflineDetail = countKafkaPartitionLines(out)

	// Under-replicated partitions — replicas not in the ISR, so no redundancy.
	if out2, err := runCmd(ctx, cli, "--bootstrap-server", server, "--describe", "--under-replicated-partitions"); err == nil {
		info.UnderReplicatedRead = true
		info.UnderReplicatedPartitions, info.URPDetail = countKafkaPartitionLines(out2)
	}
	return info, nil
}

// countKafkaPartitionLines counts the partition rows in a `kafka-topics --describe`
// filtered listing (each affected partition prints one line containing "Partition:";
// empty output means none) and returns the first such line as a sample.
func countKafkaPartitionLines(out string) (int, string) {
	n := 0
	detail := ""
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "Partition:") {
			n++
			if detail == "" {
				detail = strings.Join(strings.Fields(line), " ")
			}
		}
	}
	return n, detail
}
