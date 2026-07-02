//go:build linux

package collectors

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

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
