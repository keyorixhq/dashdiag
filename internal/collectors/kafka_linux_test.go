//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestKafkaCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewKafkaCollector()
	if c.Name() != "Kafka" {
		t.Errorf("Name() = %q, want Kafka", c.Name())
	}
	if c.Timeout() != 20*time.Second {
		t.Errorf("Timeout() = %v, want 20s", c.Timeout())
	}
}

func TestKafkaCLI(t *testing.T) {
	t.Run("found via first bin name", func(t *testing.T) {
		withCombinedFixture(t, map[string][]byte{
			"lookpath/kafka-topics.sh": []byte("/opt/kafka/bin/kafka-topics.sh"),
		}, nil, nil)
		if got := kafkaCLI(); got != "kafka-topics.sh" {
			t.Errorf("kafkaCLI() = %q, want kafka-topics.sh", got)
		}
	})

	t.Run("found via second bin name", func(t *testing.T) {
		withCombinedFixture(t, map[string][]byte{
			"lookpath/kafka-topics": []byte("/usr/bin/kafka-topics"),
		}, nil, nil)
		if got := kafkaCLI(); got != "kafka-topics" {
			t.Errorf("kafkaCLI() = %q, want kafka-topics", got)
		}
	})

	t.Run("neither present", func(t *testing.T) {
		withCombinedFixture(t, nil, nil, nil)
		if got := kafkaCLI(); got != "" {
			t.Errorf("kafkaCLI() = %q, want empty", got)
		}
	})
}

func TestKafkaBootstrap(t *testing.T) {
	t.Run("ipv4 reachable", func(t *testing.T) {
		withCombinedFixture(t, map[string][]byte{
			"dial/tcp/127.0.0.1:9092": {'1'},
		}, nil, nil)
		if got := kafkaBootstrap(); got != "127.0.0.1:9092" {
			t.Errorf("kafkaBootstrap() = %q, want 127.0.0.1:9092", got)
		}
	})

	t.Run("ipv6 reachable", func(t *testing.T) {
		withCombinedFixture(t, map[string][]byte{
			"dial/tcp/[::1]:9092": {'1'},
		}, nil, nil)
		if got := kafkaBootstrap(); got != "[::1]:9092" {
			t.Errorf("kafkaBootstrap() = %q, want [::1]:9092", got)
		}
	})

	t.Run("neither reachable falls back to ipv4 default", func(t *testing.T) {
		withCombinedFixture(t, nil, nil, nil)
		if got := kafkaBootstrap(); got != "127.0.0.1:9092" {
			t.Errorf("kafkaBootstrap() = %q, want 127.0.0.1:9092 default", got)
		}
	})
}

func TestKafkaAvailable(t *testing.T) {
	t.Run("CLI missing means false without checking dial", func(t *testing.T) {
		withCombinedFixture(t, map[string][]byte{
			"dial/tcp/127.0.0.1:9092": {'1'},
			"dial/tcp/[::1]:9092":     {'1'},
		}, nil, nil)
		if KafkaAvailable() {
			t.Error("KafkaAvailable() = true, want false when no CLI is installed")
		}
	})

	t.Run("CLI present and port reachable", func(t *testing.T) {
		withCombinedFixture(t, map[string][]byte{
			"lookpath/kafka-topics.sh": []byte("/opt/kafka/bin/kafka-topics.sh"),
			"dial/tcp/127.0.0.1:9092":  {'1'},
		}, nil, nil)
		if !KafkaAvailable() {
			t.Error("KafkaAvailable() = false, want true")
		}
	})

	t.Run("CLI present but port unreachable", func(t *testing.T) {
		withCombinedFixture(t, map[string][]byte{
			"lookpath/kafka-topics.sh": []byte("/opt/kafka/bin/kafka-topics.sh"),
		}, nil, nil)
		if KafkaAvailable() {
			t.Error("KafkaAvailable() = true, want false when port unreachable")
		}
	})
}

func TestKafkaCollector_Collect_NotDetected(t *testing.T) {
	withCombinedFixture(t, nil, nil, nil)
	c := NewKafkaCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.KafkaInfo)
	if info.Detected {
		t.Errorf("info = %+v, want Detected=false", info)
	}
}

func TestKafkaCollector_Collect_FullHappyPath(t *testing.T) {
	offlineOut := "\tTopic: orders\tPartition: 3\tLeader: -1\tReplicas: 1,2\tIsr: 1\n" +
		"\tTopic: orders\tPartition: 7\tLeader: -1\tReplicas: 1,2\tIsr: 1\n"
	urpOut := "\tTopic: orders\tPartition: 1\tLeader: 1\tReplicas: 1,2\tIsr: 1\n"
	withCombinedFixture(t, map[string][]byte{
		"lookpath/kafka-topics.sh": []byte("/opt/kafka/bin/kafka-topics.sh"),
		"dial/tcp/127.0.0.1:9092":  {'1'},
	}, nil, func(b *source.Bundle) {
		b.PutCmd("kafka-topics.sh", []string{"--bootstrap-server", "127.0.0.1:9092", "--describe", "--unavailable-partitions"}, offlineOut, 0)
		b.PutCmd("kafka-topics.sh", []string{"--bootstrap-server", "127.0.0.1:9092", "--describe", "--under-replicated-partitions"}, urpOut, 0)
	})

	c := NewKafkaCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.KafkaInfo)
	if !info.Detected || !info.Accepting {
		t.Errorf("info = %+v, want Detected=true Accepting=true", info)
	}
	if !info.MetricsRead {
		t.Fatal("MetricsRead = false, want true")
	}
	if info.OfflinePartitions != 2 {
		t.Errorf("OfflinePartitions = %d, want 2", info.OfflinePartitions)
	}
	if info.OfflineDetail != "Topic: orders Partition: 3 Leader: -1 Replicas: 1,2 Isr: 1" {
		t.Errorf("OfflineDetail = %q, want first offline line", info.OfflineDetail)
	}
	if !info.UnderReplicatedRead {
		t.Fatal("UnderReplicatedRead = false, want true")
	}
	if info.UnderReplicatedPartitions != 1 {
		t.Errorf("UnderReplicatedPartitions = %d, want 1", info.UnderReplicatedPartitions)
	}
	if info.URPDetail != "Topic: orders Partition: 1 Leader: 1 Replicas: 1,2 Isr: 1" {
		t.Errorf("URPDetail = %q, want the urp line", info.URPDetail)
	}
}

func TestKafkaCollector_Collect_DescribeFails(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"lookpath/kafka-topics.sh": []byte("/opt/kafka/bin/kafka-topics.sh"),
		"dial/tcp/127.0.0.1:9092":  {'1'},
	}, nil, func(b *source.Bundle) {
		b.PutCmd("kafka-topics.sh", []string{"--bootstrap-server", "127.0.0.1:9092", "--describe", "--unavailable-partitions"}, "", 1)
	})

	c := NewKafkaCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.KafkaInfo)
	if info.MetricsRead {
		t.Error("MetricsRead = true, want false when describe fails")
	}
	if info.StatusReason == "" {
		t.Error("expected a StatusReason when the describe query fails")
	}
}

func TestKafkaCollector_Collect_UnderReplicatedFailsGracefully(t *testing.T) {
	offlineOut := "\tTopic: orders\tPartition: 3\tLeader: -1\n"
	withCombinedFixture(t, map[string][]byte{
		"lookpath/kafka-topics.sh": []byte("/opt/kafka/bin/kafka-topics.sh"),
		"dial/tcp/127.0.0.1:9092":  {'1'},
	}, nil, func(b *source.Bundle) {
		b.PutCmd("kafka-topics.sh", []string{"--bootstrap-server", "127.0.0.1:9092", "--describe", "--unavailable-partitions"}, offlineOut, 0)
		b.PutCmd("kafka-topics.sh", []string{"--bootstrap-server", "127.0.0.1:9092", "--describe", "--under-replicated-partitions"}, "", 1)
	})

	c := NewKafkaCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.KafkaInfo)
	if !info.MetricsRead {
		t.Error("MetricsRead = false, want true (offline query still succeeded)")
	}
	if info.UnderReplicatedRead {
		t.Error("UnderReplicatedRead = true, want false when the urp query fails")
	}
	if info.OfflinePartitions != 1 {
		t.Errorf("OfflinePartitions = %d, want 1", info.OfflinePartitions)
	}
}

func TestCountKafkaPartitionLines(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		out        string
		wantCount  int
		wantDetail string
	}{
		{"zero matches", "no partitions here\nnothing else\n", 0, ""},
		{"one match", "\tTopic: t\tPartition: 0\tLeader: 1\n", 1, "Topic: t Partition: 0 Leader: 1"},
		{
			"multiple matches keep first as detail",
			"\tTopic: t\tPartition: 0\tLeader: 1\n\tTopic: t\tPartition: 1\tLeader: 2\n",
			2,
			"Topic: t Partition: 0 Leader: 1",
		},
		{"lines without Partition ignored", "some header\nTopic: t\nmore noise\n", 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			n, detail := countKafkaPartitionLines(tt.out)
			if n != tt.wantCount {
				t.Errorf("count = %d, want %d", n, tt.wantCount)
			}
			if detail != tt.wantDetail {
				t.Errorf("detail = %q, want %q", detail, tt.wantDetail)
			}
		})
	}
}
