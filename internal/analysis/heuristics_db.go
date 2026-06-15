package analysis

import (
	"fmt"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// checkPostgres surfaces health issues for a local PostgreSQL server. Gated on
// Detected (a reachable local socket), silent on hosts without one. Returns nil
// when healthy — except when the server is up but its metrics couldn't be read,
// which is reported as INFO so an inaccessible server is never a silent OK.
func checkPostgres(pg models.PostgresInfo) []models.Insight {
	if !pg.Detected {
		return nil
	}
	var out []models.Insight

	// A running server that refuses connections is a live outage.
	if !pg.Accepting {
		reason := pg.AcceptReason
		if reason == "" {
			reason = "not accepting connections"
		}
		return []models.Insight{insight("CRIT", "Postgres",
			fmt.Sprintf("PostgreSQL is up but not accepting connections — %s", reason),
			[]string{
				"to inspect: pg_isready -h " + pg.SocketDir,
				"to inspect: tail -n 50 the server log (often /var/log/postgresql/*.log)",
				"note: common causes — recovery in progress, max_connections reached, or a full data disk",
			},
		)}
	}

	if !pg.MetricsRead {
		return []models.Insight{insight("INFO", "Postgres",
			"PostgreSQL is up and accepting connections; connection/replication metrics were not read",
			[]string{
				"note: run dsd as root or the postgres user for connection-saturation and replica-lag checks",
				"to inspect: sudo -u postgres psql -c 'SELECT count(*), current_setting(''max_connections'') FROM pg_stat_activity'",
			},
		)}
	}

	// Connection saturation — the classic "FATAL: too many connections" outage.
	if pg.MaxConnections > 0 {
		ratio := float64(pg.ActiveConns) / float64(pg.MaxConnections)
		switch {
		case ratio >= 0.95:
			out = append(out, insight("CRIT", "Postgres",
				fmt.Sprintf("PostgreSQL connections at %d/%d (%.0f%%) — new connections will be refused",
					pg.ActiveConns, pg.MaxConnections, ratio*100),
				[]string{
					"to inspect: SELECT state, count(*) FROM pg_stat_activity GROUP BY state",
					"to fix: add a connection pooler (pgbouncer), or raise max_connections (costs RAM)",
				}))
		case ratio >= 0.80:
			out = append(out, insight("WARN", "Postgres",
				fmt.Sprintf("PostgreSQL connections at %d/%d (%.0f%%) — approaching the limit",
					pg.ActiveConns, pg.MaxConnections, ratio*100),
				[]string{"to inspect: SELECT state, count(*) FROM pg_stat_activity GROUP BY state",
					"note: a connection pooler (pgbouncer) is the usual fix before raising max_connections"}))
		}
	}

	// Idle-in-transaction connections hold locks and block VACUUM → bloat.
	if pg.IdleInTxn >= 5 {
		out = append(out, insight("WARN", "Postgres",
			fmt.Sprintf("%d connection(s) idle in transaction — they hold locks and block VACUUM (bloat risk)", pg.IdleInTxn),
			[]string{
				"to inspect: SELECT pid, state, query FROM pg_stat_activity WHERE state='idle in transaction'",
				"to fix: set idle_in_transaction_session_timeout, or fix the app to commit/rollback promptly",
			}))
	}

	// Replica falling behind.
	if pg.InRecovery && pg.ReplayLagSec > 300 {
		out = append(out, insight("WARN", "Postgres",
			fmt.Sprintf("replica is %.0fs behind the primary — replay lag growing", pg.ReplayLagSec),
			[]string{
				"to inspect: SELECT now()-pg_last_xact_replay_timestamp() AS lag",
				"note: check WAL receiver, network to primary, and replica I/O headroom",
			}))
	}

	return out
}
