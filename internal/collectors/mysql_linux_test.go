//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestMySQLCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewMySQLCollector()
	if c.Name() != "MySQL" {
		t.Errorf("Name() = %q, want MySQL", c.Name())
	}
	if c.Timeout() != 6*time.Second {
		t.Errorf("Timeout() = %v, want 6s", c.Timeout())
	}
}

func TestDetectMySQLSocket_NotReachable(t *testing.T) {
	withCombinedFixture(t, nil, nil, nil)
	if got := detectMySQLSocket(); got != "" {
		t.Errorf("detectMySQLSocket() = %q, want empty", got)
	}
	if MySQLAvailable() {
		t.Error("MySQLAvailable() = true, want false")
	}
}

func TestDetectMySQLSocket_EachCandidatePath(t *testing.T) {
	for _, path := range mysqlSocketPaths {
		t.Run(path, func(t *testing.T) {
			withCombinedFixture(t, map[string][]byte{
				"dial/unix/" + path: {'1'},
			}, nil, nil)
			if got := detectMySQLSocket(); got != path {
				t.Errorf("detectMySQLSocket() = %q, want %q", got, path)
			}
			if !MySQLAvailable() {
				t.Error("MySQLAvailable() = false, want true")
			}
		})
	}
}

func TestMySQLCollector_Collect_NotDetected(t *testing.T) {
	withCombinedFixture(t, nil, nil, nil)
	c := NewMySQLCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.MySQLInfo)
	if info.Detected {
		t.Errorf("info = %+v, want Detected=false", info)
	}
}

const mysqlSock = "/var/run/mysqld/mysqld.sock"

func mysqlArgs(sql string) []string {
	return []string{"--socket=" + mysqlSock, "-N", "-B", "-e", sql}
}

func TestMySQLCollector_Collect_FullHappyPath_NotReplica(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"dial/unix/" + mysqlSock:      {'1'},
		"socketpeercred/" + mysqlSock: []byte(`{"uid":0,"present":true}`),
	}, nil, func(b *source.Bundle) {
		b.PutCmd("mysql", mysqlArgs("SELECT VERSION()"), "8.0.36\n", 0)
		b.PutCmd("mysql", mysqlArgs("SELECT @@max_connections"), "151\n", 0)
		b.PutCmd("mysql", mysqlArgs("SHOW GLOBAL STATUS LIKE 'Threads_connected'"), "Threads_connected\t5\n", 0)
		b.PutCmd("mysql", mysqlArgs(`SHOW SLAVE STATUS\G`), "", 0)
		b.PutCmd("mysql", mysqlArgs(`SHOW REPLICA STATUS\G`), "", 0)
	})

	c := NewMySQLCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.MySQLInfo)
	if !info.Detected || info.SocketPath != mysqlSock || !info.Accepting {
		t.Errorf("info = %+v, want Detected=true SocketPath=%q Accepting=true", info, mysqlSock)
	}
	if !info.MetricsRead || info.Version != "8.0.36" || info.Flavor != "MySQL" {
		t.Errorf("info = %+v, want MetricsRead=true Version=8.0.36 Flavor=MySQL", info)
	}
	if !info.ConnStatsRead || info.MaxConnections != 151 || info.ThreadsConnected != 5 {
		t.Errorf("info = %+v, want ConnStatsRead=true MaxConnections=151 ThreadsConnected=5", info)
	}
	if info.IsReplica {
		t.Error("IsReplica = true, want false")
	}
}

func TestMySQLCollector_Collect_ReplicaViaOldSlaveStatus(t *testing.T) {
	slaveStatus := "Slave_IO_Running: Yes\nSlave_SQL_Running: Yes\nSeconds_Behind_Master: 3\n"
	withCombinedFixture(t, map[string][]byte{
		"dial/unix/" + mysqlSock:      {'1'},
		"socketpeercred/" + mysqlSock: []byte(`{"uid":0,"present":true}`),
	}, nil, func(b *source.Bundle) {
		b.PutCmd("mysql", mysqlArgs("SELECT VERSION()"), "10.11.6-MariaDB\n", 0)
		b.PutCmd("mysql", mysqlArgs("SELECT @@max_connections"), "151\n", 0)
		b.PutCmd("mysql", mysqlArgs("SHOW GLOBAL STATUS LIKE 'Threads_connected'"), "Threads_connected\t2\n", 0)
		b.PutCmd("mysql", mysqlArgs(`SHOW SLAVE STATUS\G`), slaveStatus, 0)
	})

	c := NewMySQLCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.MySQLInfo)
	if info.Flavor != "MariaDB" {
		t.Errorf("Flavor = %q, want MariaDB", info.Flavor)
	}
	if !info.IsReplica {
		t.Fatal("IsReplica = false, want true")
	}
	if info.ReplStopped {
		t.Error("ReplStopped = true, want false (both threads running)")
	}
	if info.SecondsBehind != 3 {
		t.Errorf("SecondsBehind = %d, want 3", info.SecondsBehind)
	}
}

func TestMySQLCollector_Collect_ReplicaViaNewReplicaStatusFallback(t *testing.T) {
	replicaStatus := "Replica_IO_Running: Yes\nReplica_SQL_Running: Yes\nSeconds_Behind_Source: 9\n"
	withCombinedFixture(t, map[string][]byte{
		"dial/unix/" + mysqlSock:      {'1'},
		"socketpeercred/" + mysqlSock: []byte(`{"uid":0,"present":true}`),
	}, nil, func(b *source.Bundle) {
		b.PutCmd("mysql", mysqlArgs("SELECT VERSION()"), "8.4.0\n", 0)
		b.PutCmd("mysql", mysqlArgs("SELECT @@max_connections"), "151\n", 0)
		b.PutCmd("mysql", mysqlArgs("SHOW GLOBAL STATUS LIKE 'Threads_connected'"), "Threads_connected\t2\n", 0)
		// Old statement returns empty output on 8.4+ (removed) -- triggers the fallback.
		b.PutCmd("mysql", mysqlArgs(`SHOW SLAVE STATUS\G`), "", 0)
		b.PutCmd("mysql", mysqlArgs(`SHOW REPLICA STATUS\G`), replicaStatus, 0)
	})

	c := NewMySQLCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.MySQLInfo)
	if !info.IsReplica {
		t.Fatal("IsReplica = false, want true (via fallback)")
	}
	if info.SecondsBehind != 9 {
		t.Errorf("SecondsBehind = %d, want 9", info.SecondsBehind)
	}
	if info.ReplStopped {
		t.Error("ReplStopped = true, want false")
	}
}

func TestMySQLCollector_Collect_VersionQueryFails(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"dial/unix/" + mysqlSock:      {'1'},
		"socketpeercred/" + mysqlSock: []byte(`{"uid":0,"present":true}`),
	}, nil, func(b *source.Bundle) {
		b.PutCmd("mysql", mysqlArgs("SELECT VERSION()"), "", 1)
	})

	c := NewMySQLCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.MySQLInfo)
	if info.MetricsRead {
		t.Error("MetricsRead = true, want false when VERSION() fails")
	}
	if info.StatusReason == "" {
		t.Error("expected a StatusReason when VERSION() fails")
	}
	if info.ConnStatsRead {
		t.Error("ConnStatsRead = true, want false — nothing else should have been attempted")
	}
}

func TestMySQLCollector_Collect_ConnStatsRequiresBothQueries(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"dial/unix/" + mysqlSock:      {'1'},
		"socketpeercred/" + mysqlSock: []byte(`{"uid":0,"present":true}`),
	}, nil, func(b *source.Bundle) {
		b.PutCmd("mysql", mysqlArgs("SELECT VERSION()"), "8.0.36\n", 0)
		b.PutCmd("mysql", mysqlArgs("SELECT @@max_connections"), "151\n", 0)
		// Threads_connected query fails.
		b.PutCmd("mysql", mysqlArgs("SHOW GLOBAL STATUS LIKE 'Threads_connected'"), "", 1)
		b.PutCmd("mysql", mysqlArgs(`SHOW SLAVE STATUS\G`), "", 0)
		b.PutCmd("mysql", mysqlArgs(`SHOW REPLICA STATUS\G`), "", 0)
	})

	c := NewMySQLCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.MySQLInfo)
	if info.ConnStatsRead {
		t.Error("ConnStatsRead = true, want false when only max_connections succeeded")
	}
	if info.MaxConnections != 151 {
		t.Errorf("MaxConnections = %d, want 151 (still recorded)", info.MaxConnections)
	}
}

// TestMySQLCollector_Collect_UntrustedPeer_SkipsMetrics is the regression test
// for the socket-trust fix: a listener on the socket path whose kernel-verified
// SO_PEERCRED UID is neither root nor the mysql service account must NOT have
// the mysql client run against it. Before the fix, ANY listener accepting the
// dial was treated as the real server and queried — an unprivileged local
// attacker who pre-created e.g. /tmp/mysql.sock could feed
// collectMySQLMetrics fabricated output that dsd would report as genuine.
func TestMySQLCollector_Collect_UntrustedPeer_SkipsMetrics(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"dial/unix/" + mysqlSock:      {'1'},
		"socketpeercred/" + mysqlSock: []byte(`{"uid":1000,"present":true}`),
		"userlookup/mysql":            []byte("27"), // distinct from the attacker's uid 1000
	}, nil, func(b *source.Bundle) {
		// If the trust gate is broken, Collect would run this and MetricsRead
		// would come back true — the query is seeded to SUCCEED so a failure to
		// gate (not a query error) is what would make this test pass wrongly.
		b.PutCmd("mysql", mysqlArgs("SELECT VERSION()"), "8.0.36\n", 0)
	})

	c := NewMySQLCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.MySQLInfo)
	if !info.PeerVerified {
		t.Error("PeerVerified = false, want true — the SO_PEERCRED probe itself succeeded")
	}
	if info.PeerTrusted {
		t.Error("PeerTrusted = true, want false — peer uid 1000 is neither root nor the mysql account")
	}
	if info.MetricsRead {
		t.Error("MetricsRead = true, want false — must never query an unverified/untrusted listener")
	}
	if info.StatusReason == "" {
		t.Error("expected a StatusReason disclosing the untrusted peer")
	}
}

// TestMySQLCollector_Collect_UnverifiedPeer_SkipsMetrics covers a recording gap
// / probe failure (e.g. a bundle captured before this check existed, or the
// SO_PEERCRED syscall itself failing) — PeerVerified must be false and metrics
// must still be skipped (not silently treated as trusted).
func TestMySQLCollector_Collect_UnverifiedPeer_SkipsMetrics(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"dial/unix/" + mysqlSock: {'1'},
		// No "socketpeercred/" entry at all — simulates a recording gap.
	}, nil, func(b *source.Bundle) {
		b.PutCmd("mysql", mysqlArgs("SELECT VERSION()"), "8.0.36\n", 0)
	})

	c := NewMySQLCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.MySQLInfo)
	if info.PeerVerified {
		t.Error("PeerVerified = true, want false — no recorded probe result")
	}
	if info.PeerTrusted {
		t.Error("PeerTrusted = true, want false when unverified")
	}
	if info.MetricsRead {
		t.Error("MetricsRead = true, want false when peer identity couldn't be verified")
	}
	if info.StatusReason == "" {
		t.Error("expected a StatusReason disclosing the unverified peer")
	}
}

func TestLastField(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want string
	}{
		{"Threads_connected\t5", "5"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := lastField(tt.in); got != tt.want {
			t.Errorf("lastField(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestParseMySQLReplica(t *testing.T) {
	// q returns the SHOW SLAVE STATUS\G output for that query, empty otherwise.
	mkQ := func(slaveStatus string) func(string) (string, bool) {
		return func(query string) (string, bool) {
			if query == "SHOW SLAVE STATUS\\G" {
				return slaveStatus, slaveStatus != ""
			}
			return "", false
		}
	}

	t.Run("stopped replication (NULL lag) → ReplStopped", func(t *testing.T) {
		// IO thread stopped: Seconds_Behind_Master is NULL — the false-OK trap.
		out := "*************************** 1. row ***************************\n" +
			"  Slave_IO_Running: No\n" +
			" Slave_SQL_Running: Yes\n" +
			" Seconds_Behind_Master: NULL\n"
		var info models.MySQLInfo
		parseMySQLReplica(mkQ(out), &info)
		if !info.IsReplica {
			t.Fatal("IsReplica should be true")
		}
		if !info.ReplStopped {
			t.Error("ReplStopped should be true when Slave_IO_Running != Yes")
		}
		if info.SecondsBehind != 0 {
			t.Errorf("SecondsBehind = %d, want 0 (NULL not parsed)", info.SecondsBehind)
		}
	})

	t.Run("healthy replica → not stopped, real lag", func(t *testing.T) {
		out := "  Slave_IO_Running: Yes\n Slave_SQL_Running: Yes\n Seconds_Behind_Master: 12\n"
		var info models.MySQLInfo
		parseMySQLReplica(mkQ(out), &info)
		if info.ReplStopped {
			t.Error("ReplStopped should be false when both threads are Yes")
		}
		if info.SecondsBehind != 12 {
			t.Errorf("SecondsBehind = %d, want 12", info.SecondsBehind)
		}
	})

	// Regression guard: MySQL 8.4 REMOVED "SHOW SLAVE STATUS" entirely — it
	// returns ok=false (unknown statement), not the Replica_* fixture under the
	// old query name. The real 8.4 wire behavior only answers "SHOW REPLICA
	// STATUS". Before the fix, parseMySQLReplica returned on the first query's
	// failure and never tried the new statement, so a stopped/lagging 8.4+
	// replica silently read as "not a replica".
	mkQ84 := func(replicaStatus string) func(string) (string, bool) {
		return func(query string) (string, bool) {
			switch query {
			case "SHOW SLAVE STATUS\\G":
				return "", false // removed in 8.4 — the statement itself errors
			case "SHOW REPLICA STATUS\\G":
				return replicaStatus, replicaStatus != ""
			default:
				return "", false
			}
		}
	}

	t.Run("MySQL 8.4: SHOW SLAVE STATUS removed, falls back to SHOW REPLICA STATUS", func(t *testing.T) {
		out := "  Replica_IO_Running: Yes\n Replica_SQL_Running: No\n Seconds_Behind_Source: NULL\n"
		var info models.MySQLInfo
		parseMySQLReplica(mkQ84(out), &info)
		if !info.IsReplica {
			t.Fatal("IsReplica should be true — the fallback query must still be tried")
		}
		if !info.ReplStopped {
			t.Error("ReplStopped should be true (Replica_SQL_Running != Yes)")
		}
	})

	t.Run("MySQL 8.4: healthy replica via fallback, real lag via Seconds_Behind_Source", func(t *testing.T) {
		out := "  Replica_IO_Running: Yes\n Replica_SQL_Running: Yes\n Seconds_Behind_Source: 7\n"
		var info models.MySQLInfo
		parseMySQLReplica(mkQ84(out), &info)
		if info.ReplStopped {
			t.Error("ReplStopped should be false when both threads are Yes")
		}
		if info.SecondsBehind != 7 {
			t.Errorf("SecondsBehind = %d, want 7", info.SecondsBehind)
		}
	})

	t.Run("MySQL 8.4: not a replica on either statement → silent", func(t *testing.T) {
		var info models.MySQLInfo
		parseMySQLReplica(mkQ84(""), &info)
		if info.IsReplica || info.ReplStopped {
			t.Errorf("non-replica should set nothing, got IsReplica=%v ReplStopped=%v", info.IsReplica, info.ReplStopped)
		}
	})

	t.Run("not a replica → silent", func(t *testing.T) {
		var info models.MySQLInfo
		parseMySQLReplica(mkQ(""), &info)
		if info.IsReplica || info.ReplStopped {
			t.Errorf("non-replica should set nothing, got IsReplica=%v ReplStopped=%v", info.IsReplica, info.ReplStopped)
		}
	})
}
